//! X25519 recipient wrapper for HydraLock v1.
//!
//! Algorithm:
//!   1. Generate ephemeral X25519 keypair: (eph_sk, eph_pk)
//!   2. Compute DH shared secret: shared = X25519(eph_sk, recipient_pk)
//!   3. Derive KEK:
//!      salt   = eph_pk (32B) || recipient_pk (32B) = 64B
//!      HKDF-SHA-512(ikm=shared, salt=salt, info="hydralock:v1:x25519-kek")
//!      → 32 bytes
//!   4. Wrap key with AES-256-GCM-SIV: nonce=wrap_nonce, aad=wrapper_aad
//!
//! The HKDF salt binds the KEK to the specific (eph_pk, recipient_pk) pair,
//! preventing cross-recipient key splicing. The wrapper AAD binds the stanza
//! to the file context (suite_id, wrapper_index, file_uuid, header_hash).
//!
//! Wire format (94 bytes):
//!   Offset  Size  Field
//!   0       2     stanza_version (u16 = 1)
//!   2       32    ephemeral_public_key
//!   34      12    wrap_nonce
//!   46      48    wrapped_key (32B ciphertext + 16B AES-GCM-SIV tag)
//!   Total: 94 bytes

use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha512;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::crypto::password::Kek;
use crate::crypto::secret::SecretKey32;
use crate::crypto::wrap::{
    AES_GCM_SIV_NONCE_LEN, WRAPPED_KEY_LEN, WrapError, unwrap_key, wrap_key,
};

/// Stanza type identifier for the X25519 wrapper.
pub const WRAPPER_TYPE_X25519: u16 = 0x0002;

/// Wire-format stanza version.
const STANZA_VERSION: u16 = 1;

/// HKDF info label for X25519 KEK derivation.
const HKDF_INFO_X25519_KEK: &[u8] = b"hydralock:v1:x25519-kek";

/// Fixed byte length of an encoded X25519 stanza.
///
/// Layout:
///   Offset  Size  Field
///   0       2     stanza_version (u16)
///   2       32    ephemeral_public_key
///   34      12    wrap_nonce
///   46      48    wrapped_key (32B ciphertext + 16B tag)
///   Total: 94 bytes
pub const X25519_STANZA_LEN: usize = 94;

const EPH_PK_OFFSET: usize = 2;
const NONCE_OFFSET: usize = 34;
const WRAPPED_KEY_OFFSET: usize = 46;
const WRAPPED_KEY_BODY_LEN: usize = WRAPPED_KEY_LEN - AES_GCM_SIV_NONCE_LEN; // 48

/// Decoded X25519 stanza.
#[derive(Clone, PartialEq, Eq)]
pub struct X25519Stanza {
    /// 32-byte ephemeral X25519 public key.
    pub ephemeral_public_key: [u8; 32],
    /// 12-byte AES-GCM-SIV nonce for the key wrapping.
    pub wrap_nonce: [u8; AES_GCM_SIV_NONCE_LEN],
    /// 48-byte wrapped key body (ciphertext 32B + tag 16B, no nonce prefix).
    pub wrapped_key: [u8; WRAPPED_KEY_BODY_LEN],
}

impl core::fmt::Debug for X25519Stanza {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("X25519Stanza")
            .field(
                "ephemeral_public_key",
                &hex_short(&self.ephemeral_public_key),
            )
            .field("wrap_nonce", &hex_short(&self.wrap_nonce))
            .field("wrapped_key", &"[REDACTED]")
            .finish()
    }
}

fn hex_short(b: &[u8]) -> String {
    b.iter()
        .take(8)
        .map(|x| format!("{:02x}", x))
        .collect::<String>()
        + "..."
}

/// Errors during X25519 wrapping/unwrapping.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum X25519Error {
    /// Stanza byte length is wrong.
    InvalidLength { expected: usize, actual: usize },
    /// The `stanza_version` field is not 1.
    UnsupportedStanzaVersion { expected: u16, actual: u16 },
    /// Key wrapping (AES-GCM-SIV encryption) failed.
    WrapFailed,
    /// Key unwrapping failed — wrong key or corrupted stanza.
    UnwrapFailed,
}

impl core::fmt::Display for X25519Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidLength { expected, actual } => {
                write!(
                    f,
                    "invalid stanza length: expected {expected}, got {actual}"
                )
            }
            Self::UnsupportedStanzaVersion { expected, actual } => {
                write!(
                    f,
                    "unsupported stanza version: expected {expected}, got {actual}"
                )
            }
            Self::WrapFailed => write!(f, "X25519 key wrapping failed"),
            Self::UnwrapFailed => {
                write!(
                    f,
                    "X25519 key unwrapping failed: wrong recipient key or corrupted stanza"
                )
            }
        }
    }
}

impl std::error::Error for X25519Error {}

impl X25519Stanza {
    /// Parse an X25519 stanza from its 94-byte binary representation.
    pub fn parse(bytes: &[u8]) -> Result<Self, X25519Error> {
        if bytes.len() != X25519_STANZA_LEN {
            return Err(X25519Error::InvalidLength {
                expected: X25519_STANZA_LEN,
                actual: bytes.len(),
            });
        }

        let stanza_version = u16::from_be_bytes([bytes[0], bytes[1]]);
        if stanza_version != STANZA_VERSION {
            return Err(X25519Error::UnsupportedStanzaVersion {
                expected: STANZA_VERSION,
                actual: stanza_version,
            });
        }

        let mut ephemeral_public_key = [0u8; 32];
        ephemeral_public_key.copy_from_slice(&bytes[EPH_PK_OFFSET..EPH_PK_OFFSET + 32]);

        let mut wrap_nonce = [0u8; AES_GCM_SIV_NONCE_LEN];
        wrap_nonce.copy_from_slice(&bytes[NONCE_OFFSET..NONCE_OFFSET + AES_GCM_SIV_NONCE_LEN]);

        let mut wrapped_key = [0u8; WRAPPED_KEY_BODY_LEN];
        wrapped_key
            .copy_from_slice(&bytes[WRAPPED_KEY_OFFSET..WRAPPED_KEY_OFFSET + WRAPPED_KEY_BODY_LEN]);

        Ok(Self {
            ephemeral_public_key,
            wrap_nonce,
            wrapped_key,
        })
    }

    /// Encode this stanza into its canonical 94-byte binary representation.
    pub fn encode(&self) -> [u8; X25519_STANZA_LEN] {
        let mut out = [0u8; X25519_STANZA_LEN];
        out[0..2].copy_from_slice(&STANZA_VERSION.to_be_bytes());
        out[EPH_PK_OFFSET..EPH_PK_OFFSET + 32].copy_from_slice(&self.ephemeral_public_key);
        out[NONCE_OFFSET..NONCE_OFFSET + AES_GCM_SIV_NONCE_LEN].copy_from_slice(&self.wrap_nonce);
        out[WRAPPED_KEY_OFFSET..WRAPPED_KEY_OFFSET + WRAPPED_KEY_BODY_LEN]
            .copy_from_slice(&self.wrapped_key);
        out
    }

    /// Seal `key` for `recipient_pk` using deterministic `eph_sk_bytes` and `wrap_nonce`.
    ///
    /// Use `seal_with_rng` in production. This function is exposed for deterministic
    /// testing and cross-implementation vector generation.
    pub fn seal(
        key: &SecretKey32,
        recipient_pk: &[u8; 32],
        eph_sk_bytes: &[u8; 32],
        wrap_nonce: [u8; AES_GCM_SIV_NONCE_LEN],
        aad: &[u8],
    ) -> Result<Self, X25519Error> {
        let eph_sk = StaticSecret::from(*eph_sk_bytes);
        let eph_pk = PublicKey::from(&eph_sk);
        let recipient_pub = PublicKey::from(*recipient_pk);

        let shared = eph_sk.diffie_hellman(&recipient_pub);

        // Derive KEK via HKDF-SHA-512.
        // Salt = eph_pk (32B) || recipient_pk (32B)
        let mut hkdf_salt = [0u8; 64];
        hkdf_salt[..32].copy_from_slice(eph_pk.as_bytes());
        hkdf_salt[32..].copy_from_slice(recipient_pk);

        let kek_bytes = derive_x25519_kek(shared.as_bytes(), &hkdf_salt);
        let kek = Kek(SecretKey32::from_bytes(*kek_bytes));

        let wrapped_full =
            wrap_key(&kek, key, &wrap_nonce, aad).map_err(|_| X25519Error::WrapFailed)?;

        let mut wrapped_key = [0u8; WRAPPED_KEY_BODY_LEN];
        wrapped_key.copy_from_slice(&wrapped_full[AES_GCM_SIV_NONCE_LEN..]);

        Ok(Self {
            ephemeral_public_key: *eph_pk.as_bytes(),
            wrap_nonce,
            wrapped_key,
        })
    }

    /// Seal `key` for `recipient_pk` using fresh random ephemeral key and nonce from `rng`.
    pub fn seal_with_rng<R: RngCore>(
        key: &SecretKey32,
        recipient_pk: &[u8; 32],
        aad: &[u8],
        rng: &mut R,
    ) -> Result<Self, X25519Error> {
        let mut eph_sk_bytes = Zeroizing::new([0u8; 32]);
        rng.fill_bytes(eph_sk_bytes.as_mut());

        let mut wrap_nonce = [0u8; AES_GCM_SIV_NONCE_LEN];
        rng.fill_bytes(&mut wrap_nonce);

        Self::seal(key, recipient_pk, &eph_sk_bytes, wrap_nonce, aad)
    }

    /// Open (unwrap) the sealed key using the recipient's static secret key `recipient_sk`.
    ///
    /// `aad` must match the value used during `seal`.
    pub fn open(&self, recipient_sk: &[u8; 32], aad: &[u8]) -> Result<SecretKey32, X25519Error> {
        let sk = StaticSecret::from(*recipient_sk);
        let eph_pk = PublicKey::from(self.ephemeral_public_key);
        let recipient_pk = PublicKey::from(&sk);

        let shared = sk.diffie_hellman(&eph_pk);

        let mut hkdf_salt = [0u8; 64];
        hkdf_salt[..32].copy_from_slice(self.ephemeral_public_key.as_ref());
        hkdf_salt[32..].copy_from_slice(recipient_pk.as_bytes());

        let kek_bytes = derive_x25519_kek(shared.as_bytes(), &hkdf_salt);
        let kek = Kek(SecretKey32::from_bytes(*kek_bytes));

        let mut wrapped_full = [0u8; WRAPPED_KEY_LEN];
        wrapped_full[..AES_GCM_SIV_NONCE_LEN].copy_from_slice(&self.wrap_nonce);
        wrapped_full[AES_GCM_SIV_NONCE_LEN..].copy_from_slice(&self.wrapped_key);

        unwrap_key(&kek, &wrapped_full, aad).map_err(|e| match e {
            WrapError::DecryptFailed => X25519Error::UnwrapFailed,
            _ => X25519Error::WrapFailed,
        })
    }
}

/// Derive a 32-byte KEK from the X25519 shared secret via HKDF-SHA-512.
///
/// Returns a Zeroizing buffer so the raw bytes are wiped after use.
fn derive_x25519_kek(shared_secret: &[u8; 32], salt: &[u8; 64]) -> Zeroizing<[u8; 32]> {
    let hk = Hkdf::<Sha512>::new(Some(salt), shared_secret);
    let mut kek = Zeroizing::new([0u8; 32]);
    hk.expand(HKDF_INFO_X25519_KEK, kek.as_mut())
        .expect("32 bytes is a valid HKDF-SHA-512 output length");
    kek
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_recipient_sk() -> [u8; 32] {
        [0x10u8; 32]
    }

    fn test_recipient_pk() -> [u8; 32] {
        let sk = StaticSecret::from([0x10u8; 32]);
        *PublicKey::from(&sk).as_bytes()
    }

    fn test_eph_sk() -> [u8; 32] {
        [0x20u8; 32]
    }

    fn test_wrap_nonce() -> [u8; AES_GCM_SIV_NONCE_LEN] {
        [0x30u8; AES_GCM_SIV_NONCE_LEN]
    }

    fn test_key() -> SecretKey32 {
        SecretKey32::from_bytes([0xABu8; 32])
    }

    fn test_aad() -> Vec<u8> {
        b"hydralock-test-aad".to_vec()
    }

    #[test]
    fn seal_open_roundtrip() {
        let key = test_key();
        let recipient_sk = test_recipient_sk();
        let recipient_pk = test_recipient_pk();

        let stanza = X25519Stanza::seal(
            &key,
            &recipient_pk,
            &test_eph_sk(),
            test_wrap_nonce(),
            &test_aad(),
        )
        .expect("seal failed");

        let recovered = stanza
            .open(&recipient_sk, &test_aad())
            .expect("open failed");
        assert_eq!(recovered.expose(), key.expose());
    }

    #[test]
    fn stanza_encode_decode_roundtrip() {
        let key = test_key();
        let recipient_pk = test_recipient_pk();

        let stanza = X25519Stanza::seal(
            &key,
            &recipient_pk,
            &test_eph_sk(),
            test_wrap_nonce(),
            &test_aad(),
        )
        .expect("seal failed");

        let encoded = stanza.encode();
        assert_eq!(encoded.len(), X25519_STANZA_LEN);

        let decoded = X25519Stanza::parse(&encoded).expect("parse failed");
        assert_eq!(decoded.ephemeral_public_key, stanza.ephemeral_public_key);
        assert_eq!(decoded.wrap_nonce, stanza.wrap_nonce);
        assert_eq!(decoded.wrapped_key, stanza.wrapped_key);
    }

    #[test]
    fn stanza_is_deterministic() {
        let key = test_key();
        let recipient_pk = test_recipient_pk();
        let eph_sk = test_eph_sk();
        let nonce = test_wrap_nonce();
        let aad = test_aad();

        let s1 = X25519Stanza::seal(&key, &recipient_pk, &eph_sk, nonce, &aad).unwrap();
        let s2 = X25519Stanza::seal(&key, &recipient_pk, &eph_sk, nonce, &aad).unwrap();
        assert_eq!(s1.ephemeral_public_key, s2.ephemeral_public_key);
        assert_eq!(s1.wrapped_key, s2.wrapped_key);
    }

    #[test]
    fn wrong_recipient_key_fails_open() {
        let key = test_key();
        let recipient_pk = test_recipient_pk();
        let wrong_sk = [0xFFu8; 32];

        let stanza = X25519Stanza::seal(
            &key,
            &recipient_pk,
            &test_eph_sk(),
            test_wrap_nonce(),
            &test_aad(),
        )
        .expect("seal failed");

        let err = stanza.open(&wrong_sk, &test_aad());
        assert!(matches!(err, Err(X25519Error::UnwrapFailed)));
    }

    #[test]
    fn wrong_aad_fails_open() {
        let key = test_key();
        let recipient_pk = test_recipient_pk();
        let recipient_sk = test_recipient_sk();

        let stanza = X25519Stanza::seal(
            &key,
            &recipient_pk,
            &test_eph_sk(),
            test_wrap_nonce(),
            b"correct-aad",
        )
        .expect("seal failed");

        let err = stanza.open(&recipient_sk, b"wrong-aad");
        assert!(matches!(err, Err(X25519Error::UnwrapFailed)));
    }

    #[test]
    fn tampered_wrapped_key_fails_open() {
        let key = test_key();
        let recipient_pk = test_recipient_pk();
        let recipient_sk = test_recipient_sk();

        let mut stanza = X25519Stanza::seal(
            &key,
            &recipient_pk,
            &test_eph_sk(),
            test_wrap_nonce(),
            &test_aad(),
        )
        .expect("seal failed");

        stanza.wrapped_key[0] ^= 0x01;

        let err = stanza.open(&recipient_sk, &test_aad());
        assert!(matches!(err, Err(X25519Error::UnwrapFailed)));
    }

    #[test]
    fn seal_with_rng_produces_parseable_stanza() {
        let key = test_key();
        let recipient_pk = test_recipient_pk();
        let recipient_sk = test_recipient_sk();
        let mut rng = rand::thread_rng();

        let stanza = X25519Stanza::seal_with_rng(&key, &recipient_pk, &test_aad(), &mut rng)
            .expect("seal_with_rng failed");

        let encoded = stanza.encode();
        let decoded = X25519Stanza::parse(&encoded).expect("parse failed");

        let recovered = decoded
            .open(&recipient_sk, &test_aad())
            .expect("open failed");
        assert_eq!(recovered.expose(), key.expose());
    }

    #[test]
    fn parse_rejects_wrong_length() {
        let err = X25519Stanza::parse(&[0u8; 93]);
        assert!(matches!(
            err,
            Err(X25519Error::InvalidLength {
                expected: 94,
                actual: 93
            })
        ));
    }

    #[test]
    fn parse_rejects_wrong_stanza_version() {
        let mut bytes = [0u8; X25519_STANZA_LEN];
        bytes[0..2].copy_from_slice(&9u16.to_be_bytes());
        let err = X25519Stanza::parse(&bytes);
        assert!(matches!(
            err,
            Err(X25519Error::UnsupportedStanzaVersion {
                expected: 1,
                actual: 9
            })
        ));
    }

    #[test]
    fn different_recipients_get_different_wrapped_keys() {
        let key = test_key();
        let pk1 = test_recipient_pk();
        let pk2 = *PublicKey::from(&StaticSecret::from([0x50u8; 32])).as_bytes();

        let s1 =
            X25519Stanza::seal(&key, &pk1, &test_eph_sk(), test_wrap_nonce(), &test_aad()).unwrap();
        let s2 =
            X25519Stanza::seal(&key, &pk2, &test_eph_sk(), test_wrap_nonce(), &test_aad()).unwrap();

        assert_ne!(s1.wrapped_key, s2.wrapped_key);
        // eph_pk is the same because the same eph_sk is used; only the DH output differs.
    }
}
