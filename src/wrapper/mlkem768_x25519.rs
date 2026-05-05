//! ML-KEM-768 + X25519 hybrid recipient wrapper for HydraLock v1.
//!
//! Security rationale:
//!   If X25519 is broken by a quantum adversary, ML-KEM-768 still protects the key.
//!   If ML-KEM-768 has a classical flaw, X25519 still provides classical security.
//!   Both shared secrets must be compromised simultaneously to break the hybrid.
//!
//! Algorithm:
//!   Sender side (seal):
//!     1. Generate ephemeral X25519 keypair (eph_sk, eph_pk).
//!     2. Compute ss_x25519 = X25519(eph_sk, recipient_x25519_pk).
//!     3. Encapsulate using ML-KEM-768: (ct_mlkem, ss_mlkem) = MLKEM768.Encaps(recipient_ek).
//!     4. Derive KEK = HKDF-SHA-512(
//!            ikm  = ss_x25519 (32B) || ss_mlkem (32B),
//!            salt = eph_x25519_pk (32B) || recipient_x25519_pk (32B),
//!            info = "hydralock:v1:mlkem768-x25519-kek",
//!        ) → 32 bytes.
//!     5. Wrap key with AES-256-GCM-SIV: (wrap_nonce, wrapped_key).
//!
//!   Recipient side (open):
//!     1. Compute ss_x25519 = X25519(recipient_x25519_sk, eph_pk).
//!     2. Decapsulate: ss_mlkem = MLKEM768.Decaps(recipient_dk, ct_mlkem).
//!     3. Re-derive KEK (same HKDF).
//!     4. Unwrap key with AES-256-GCM-SIV.
//!
//! Wire format (1182 bytes):
//!   Offset   Size    Field
//!   0        2       stanza_version (u16 = 1, big-endian)
//!   2        32      eph_x25519_pk
//!   34       1088    mlkem768_ct
//!   1122     12      wrap_nonce
//!   1134     48      wrapped_key (32B ciphertext + 16B AES-GCM-SIV tag)
//!   Total: 1182 bytes

use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha512;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use ml_kem::{
    B32, Ciphertext, Decapsulate, DecapsulationKey768, EncapsulationKey768, KeyExport, KeyInit,
    MlKem768, TryKeyInit,
};

use crate::crypto::password::Kek;
use crate::crypto::secret::SecretKey32;
use crate::crypto::wrap::{
    AES_GCM_SIV_NONCE_LEN, WRAPPED_KEY_LEN, WrapError, unwrap_key, wrap_key,
};

/// Stanza type identifier for the ML-KEM-768 + X25519 hybrid wrapper.
pub const WRAPPER_TYPE_MLKEM768_X25519: u16 = 0x0003;

/// Wire-format stanza version.
const STANZA_VERSION: u16 = 1;

/// HKDF info label for KEK derivation.
const HKDF_INFO: &[u8] = b"hydralock:v1:mlkem768-x25519-kek";

/// Byte length of an ML-KEM-768 encapsulation key (public key).
pub const MLKEM768_EK_LEN: usize = 1184;

/// Byte length of an ML-KEM-768 ciphertext (encapsulated shared secret).
pub const MLKEM768_CT_LEN: usize = 1088;

/// Byte length of an ML-KEM-768 decapsulation key seed.
pub const MLKEM768_SEED_LEN: usize = 64;

/// Byte length of an ML-KEM-768 shared secret.
pub const MLKEM768_SS_LEN: usize = 32;

/// Byte length of the wrapped key body stored in the stanza (no nonce prefix).
const WRAPPED_KEY_BODY_LEN: usize = WRAPPED_KEY_LEN - AES_GCM_SIV_NONCE_LEN; // 48

/// Fixed byte length of an encoded ML-KEM-768 + X25519 stanza.
///
/// Layout:
///   Offset   Size    Field
///   0        2       stanza_version
///   2        32      eph_x25519_pk
///   34       1088    mlkem768_ct
///   1122     12      wrap_nonce
///   1134     48      wrapped_key
///   Total: 1182 bytes
pub const MLKEM768_X25519_STANZA_LEN: usize =
    2 + 32 + MLKEM768_CT_LEN + AES_GCM_SIV_NONCE_LEN + WRAPPED_KEY_BODY_LEN;

const EPH_X25519_PK_OFFSET: usize = 2;
const MLKEM768_CT_OFFSET: usize = 34;
const WRAP_NONCE_OFFSET: usize = MLKEM768_CT_OFFSET + MLKEM768_CT_LEN; // 1122
const WRAPPED_KEY_OFFSET: usize = WRAP_NONCE_OFFSET + AES_GCM_SIV_NONCE_LEN; // 1134

/// Errors during ML-KEM-768 + X25519 wrapping/unwrapping.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MlKem768X25519Error {
    /// Stanza byte length is wrong.
    InvalidLength { expected: usize, actual: usize },
    /// The `stanza_version` field is not 1.
    UnsupportedStanzaVersion { expected: u16, actual: u16 },
    /// Recipient encapsulation key bytes failed ML-KEM-768 validation.
    InvalidRecipientKey,
    /// Key wrapping failed.
    WrapFailed,
    /// Key unwrapping failed — wrong key, corrupted stanza, or mismatched AAD.
    UnwrapFailed,
}

impl core::fmt::Display for MlKem768X25519Error {
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
            Self::InvalidRecipientKey => write!(f, "invalid ML-KEM-768 encapsulation key"),
            Self::WrapFailed => write!(f, "key wrapping failed"),
            Self::UnwrapFailed => write!(
                f,
                "key unwrapping failed: wrong recipient key, corrupted stanza, or mismatched AAD"
            ),
        }
    }
}

impl std::error::Error for MlKem768X25519Error {}

/// Recipient public key for the ML-KEM-768 + X25519 hybrid wrapper.
///
/// The sealer must obtain this from the recipient out-of-band.
/// Total serialized size: 32 + 1184 = 1216 bytes.
#[derive(Clone)]
pub struct MlKem768X25519RecipientPublicKey {
    /// 32-byte X25519 public key.
    pub x25519_pk: [u8; 32],
    /// 1184-byte ML-KEM-768 encapsulation key.
    pub mlkem768_ek_bytes: [u8; MLKEM768_EK_LEN],
}

impl MlKem768X25519RecipientPublicKey {
    /// Encode as a flat byte array: x25519_pk (32B) || mlkem768_ek (1184B) = 1216B.
    pub fn encode(&self) -> [u8; 32 + MLKEM768_EK_LEN] {
        let mut out = [0u8; 32 + MLKEM768_EK_LEN];
        out[..32].copy_from_slice(&self.x25519_pk);
        out[32..].copy_from_slice(&self.mlkem768_ek_bytes);
        out
    }

    /// Decode from a 1216-byte flat representation.
    pub fn decode(bytes: &[u8; 32 + MLKEM768_EK_LEN]) -> Self {
        let mut x25519_pk = [0u8; 32];
        let mut mlkem768_ek_bytes = [0u8; MLKEM768_EK_LEN];
        x25519_pk.copy_from_slice(&bytes[..32]);
        mlkem768_ek_bytes.copy_from_slice(&bytes[32..]);
        Self {
            x25519_pk,
            mlkem768_ek_bytes,
        }
    }
}

/// Recipient secret key for the ML-KEM-768 + X25519 hybrid wrapper.
///
/// The X25519 secret key is stored as raw bytes. The ML-KEM-768 decapsulation
/// key is stored as its 64-byte seed (preferred FIPS 203 serialization form).
pub struct MlKem768X25519RecipientSecretKey {
    /// 32-byte X25519 static secret key.
    pub x25519_sk: Zeroizing<[u8; 32]>,
    /// 64-byte ML-KEM-768 decapsulation key seed.
    pub mlkem768_dk_seed: Zeroizing<[u8; MLKEM768_SEED_LEN]>,
}

impl MlKem768X25519RecipientSecretKey {
    /// Construct from raw key material.
    pub fn new(x25519_sk: [u8; 32], mlkem768_dk_seed: [u8; MLKEM768_SEED_LEN]) -> Self {
        Self {
            x25519_sk: Zeroizing::new(x25519_sk),
            mlkem768_dk_seed: Zeroizing::new(mlkem768_dk_seed),
        }
    }

    /// Generate a fresh keypair using the provided RNG.
    pub fn generate_from_rng<R: RngCore>(rng: &mut R) -> Self {
        let mut x25519_sk = Zeroizing::new([0u8; 32]);
        let mut mlkem768_dk_seed = Zeroizing::new([0u8; MLKEM768_SEED_LEN]);
        rng.fill_bytes(x25519_sk.as_mut());
        rng.fill_bytes(mlkem768_dk_seed.as_mut());
        Self {
            x25519_sk,
            mlkem768_dk_seed,
        }
    }

    /// Derive the corresponding public key.
    pub fn public_key(&self) -> MlKem768X25519RecipientPublicKey {
        let x25519_pk = *PublicKey::from(&StaticSecret::from(*self.x25519_sk)).as_bytes();
        let dk = dk_from_seed(&self.mlkem768_dk_seed);
        let ek = dk.encapsulation_key();
        let ek_arr = ek.to_bytes();
        let mut mlkem768_ek_bytes = [0u8; MLKEM768_EK_LEN];
        mlkem768_ek_bytes.copy_from_slice(ek_arr.as_slice());
        MlKem768X25519RecipientPublicKey {
            x25519_pk,
            mlkem768_ek_bytes,
        }
    }
}

/// Decoded ML-KEM-768 + X25519 stanza (1182 bytes on the wire).
pub struct MlKem768X25519Stanza {
    /// 32-byte ephemeral X25519 public key.
    pub eph_x25519_pk: [u8; 32],
    /// 1088-byte ML-KEM-768 ciphertext (encapsulated shared secret).
    pub mlkem768_ct: [u8; MLKEM768_CT_LEN],
    /// 12-byte AES-GCM-SIV nonce for the key wrapping.
    pub wrap_nonce: [u8; AES_GCM_SIV_NONCE_LEN],
    /// 48-byte wrapped key body (ciphertext 32B + tag 16B, without nonce prefix).
    pub wrapped_key: [u8; WRAPPED_KEY_BODY_LEN],
}

impl MlKem768X25519Stanza {
    /// Parse a stanza from its canonical 1182-byte binary representation.
    pub fn parse(bytes: &[u8]) -> Result<Self, MlKem768X25519Error> {
        if bytes.len() != MLKEM768_X25519_STANZA_LEN {
            return Err(MlKem768X25519Error::InvalidLength {
                expected: MLKEM768_X25519_STANZA_LEN,
                actual: bytes.len(),
            });
        }

        let version = u16::from_be_bytes([bytes[0], bytes[1]]);
        if version != STANZA_VERSION {
            return Err(MlKem768X25519Error::UnsupportedStanzaVersion {
                expected: STANZA_VERSION,
                actual: version,
            });
        }

        let mut eph_x25519_pk = [0u8; 32];
        eph_x25519_pk.copy_from_slice(&bytes[EPH_X25519_PK_OFFSET..EPH_X25519_PK_OFFSET + 32]);

        let mut mlkem768_ct = [0u8; MLKEM768_CT_LEN];
        mlkem768_ct
            .copy_from_slice(&bytes[MLKEM768_CT_OFFSET..MLKEM768_CT_OFFSET + MLKEM768_CT_LEN]);

        let mut wrap_nonce = [0u8; AES_GCM_SIV_NONCE_LEN];
        wrap_nonce
            .copy_from_slice(&bytes[WRAP_NONCE_OFFSET..WRAP_NONCE_OFFSET + AES_GCM_SIV_NONCE_LEN]);

        let mut wrapped_key = [0u8; WRAPPED_KEY_BODY_LEN];
        wrapped_key
            .copy_from_slice(&bytes[WRAPPED_KEY_OFFSET..WRAPPED_KEY_OFFSET + WRAPPED_KEY_BODY_LEN]);

        Ok(Self {
            eph_x25519_pk,
            mlkem768_ct,
            wrap_nonce,
            wrapped_key,
        })
    }

    /// Encode this stanza into its canonical 1182-byte binary representation.
    pub fn encode(&self) -> [u8; MLKEM768_X25519_STANZA_LEN] {
        let mut out = [0u8; MLKEM768_X25519_STANZA_LEN];
        out[0..2].copy_from_slice(&STANZA_VERSION.to_be_bytes());
        out[EPH_X25519_PK_OFFSET..EPH_X25519_PK_OFFSET + 32].copy_from_slice(&self.eph_x25519_pk);
        out[MLKEM768_CT_OFFSET..MLKEM768_CT_OFFSET + MLKEM768_CT_LEN]
            .copy_from_slice(&self.mlkem768_ct);
        out[WRAP_NONCE_OFFSET..WRAP_NONCE_OFFSET + AES_GCM_SIV_NONCE_LEN]
            .copy_from_slice(&self.wrap_nonce);
        out[WRAPPED_KEY_OFFSET..WRAPPED_KEY_OFFSET + WRAPPED_KEY_BODY_LEN]
            .copy_from_slice(&self.wrapped_key);
        out
    }

    /// Seal `key` for `recipient_pk` deterministically.
    ///
    /// `eph_x25519_sk_bytes` is the ephemeral X25519 secret key.
    /// `mlkem_encap_rand` is the 32-byte randomness fed to ML-KEM-768's encapsulation.
    ///
    /// **Use `seal_with_rng` in production.** This function exists for deterministic
    /// testing and cross-implementation vector generation.
    pub fn seal(
        key: &SecretKey32,
        recipient_pk: &MlKem768X25519RecipientPublicKey,
        eph_x25519_sk_bytes: &[u8; 32],
        mlkem_encap_rand: &[u8; 32],
        wrap_nonce: [u8; AES_GCM_SIV_NONCE_LEN],
        aad: &[u8],
    ) -> Result<Self, MlKem768X25519Error> {
        // --- X25519 component ---
        let eph_sk = StaticSecret::from(*eph_x25519_sk_bytes);
        let eph_pk = PublicKey::from(&eph_sk);
        let recipient_x25519_pub = PublicKey::from(recipient_pk.x25519_pk);
        let ss_x25519 = eph_sk.diffie_hellman(&recipient_x25519_pub);

        // --- ML-KEM-768 component ---
        let ek = ek_from_bytes(&recipient_pk.mlkem768_ek_bytes)?;
        let mut m = B32::default();
        m.copy_from_slice(mlkem_encap_rand.as_ref());
        let (ct, ss_mlkem) = ek.encapsulate_deterministic(&m);

        let mut mlkem768_ct = [0u8; MLKEM768_CT_LEN];
        mlkem768_ct.copy_from_slice(ct.as_slice());

        // --- KEK derivation ---
        let kek = derive_hybrid_kek(
            ss_x25519.as_bytes(),
            ss_mlkem.as_slice(),
            eph_pk.as_bytes(),
            &recipient_pk.x25519_pk,
        );

        // --- Key wrapping ---
        let wrapped_full =
            wrap_key(&kek, key, &wrap_nonce, aad).map_err(|_| MlKem768X25519Error::WrapFailed)?;

        let mut wrapped_key = [0u8; WRAPPED_KEY_BODY_LEN];
        wrapped_key.copy_from_slice(&wrapped_full[AES_GCM_SIV_NONCE_LEN..]);

        Ok(Self {
            eph_x25519_pk: *eph_pk.as_bytes(),
            mlkem768_ct,
            wrap_nonce,
            wrapped_key,
        })
    }

    /// Seal `key` for `recipient_pk` using fresh random ephemeral key, ML-KEM encapsulation
    /// randomness, and wrap nonce from `rng`.
    pub fn seal_with_rng<R: RngCore>(
        key: &SecretKey32,
        recipient_pk: &MlKem768X25519RecipientPublicKey,
        aad: &[u8],
        rng: &mut R,
    ) -> Result<Self, MlKem768X25519Error> {
        let mut eph_x25519_sk_bytes = Zeroizing::new([0u8; 32]);
        let mut mlkem_encap_rand = [0u8; 32];
        let mut wrap_nonce = [0u8; AES_GCM_SIV_NONCE_LEN];
        rng.fill_bytes(eph_x25519_sk_bytes.as_mut());
        rng.fill_bytes(&mut mlkem_encap_rand);
        rng.fill_bytes(&mut wrap_nonce);
        Self::seal(
            key,
            recipient_pk,
            &eph_x25519_sk_bytes,
            &mlkem_encap_rand,
            wrap_nonce,
            aad,
        )
    }

    /// Open (unwrap) the sealed key using the recipient's secret key.
    ///
    /// `aad` must match the value used during `seal`.
    pub fn open(
        &self,
        recipient_sk: &MlKem768X25519RecipientSecretKey,
        aad: &[u8],
    ) -> Result<SecretKey32, MlKem768X25519Error> {
        // --- X25519 decapsulation ---
        let sk = StaticSecret::from(*recipient_sk.x25519_sk);
        let eph_pk = PublicKey::from(self.eph_x25519_pk);
        let recipient_x25519_pk = PublicKey::from(&sk);
        let ss_x25519 = sk.diffie_hellman(&eph_pk);

        // --- ML-KEM-768 decapsulation ---
        let dk = dk_from_seed(&recipient_sk.mlkem768_dk_seed);
        let mut ct_arr = Ciphertext::<MlKem768>::default();
        ct_arr.copy_from_slice(&self.mlkem768_ct);
        let ss_mlkem = dk.decapsulate(&ct_arr);

        // --- KEK re-derivation ---
        let kek = derive_hybrid_kek(
            ss_x25519.as_bytes(),
            ss_mlkem.as_slice(),
            &self.eph_x25519_pk,
            recipient_x25519_pk.as_bytes(),
        );

        // --- Key unwrapping ---
        let mut wrapped_full = [0u8; WRAPPED_KEY_LEN];
        wrapped_full[..AES_GCM_SIV_NONCE_LEN].copy_from_slice(&self.wrap_nonce);
        wrapped_full[AES_GCM_SIV_NONCE_LEN..].copy_from_slice(&self.wrapped_key);

        unwrap_key(&kek, &wrapped_full, aad).map_err(|e| match e {
            WrapError::DecryptFailed => MlKem768X25519Error::UnwrapFailed,
            _ => MlKem768X25519Error::WrapFailed,
        })
    }
}

/// Construct a `DecapsulationKey768` from a 64-byte seed.
fn dk_from_seed(seed: &[u8; MLKEM768_SEED_LEN]) -> DecapsulationKey768 {
    DecapsulationKey768::new_from_slice(&seed[..]).expect("seed is exactly 64 bytes")
}

/// Validate and construct an `EncapsulationKey768` from raw bytes.
fn ek_from_bytes(
    ek_bytes: &[u8; MLKEM768_EK_LEN],
) -> Result<EncapsulationKey768, MlKem768X25519Error> {
    EncapsulationKey768::new_from_slice(&ek_bytes[..])
        .map_err(|_| MlKem768X25519Error::InvalidRecipientKey)
}

/// Derive the 32-byte hybrid KEK from both shared secrets via HKDF-SHA-512.
///
/// `ikm  = ss_x25519 (32B) || ss_mlkem (32B)` — combines both shared secrets.
/// `salt = eph_x25519_pk (32B) || recipient_x25519_pk (32B)` — binds KEK to the session.
/// `info = "hydralock:v1:mlkem768-x25519-kek"` — domain separation.
fn derive_hybrid_kek(
    ss_x25519: &[u8; 32],
    ss_mlkem: &[u8],
    eph_x25519_pk: &[u8; 32],
    recipient_x25519_pk: &[u8; 32],
) -> Kek {
    // IKM: concatenate both 32-byte shared secrets.
    let mut ikm = Zeroizing::new([0u8; 64]);
    ikm[..32].copy_from_slice(ss_x25519);
    ikm[32..].copy_from_slice(ss_mlkem);

    // Salt: binds KEK to the specific (eph_pk, recipient_pk) pair.
    let mut salt = [0u8; 64];
    salt[..32].copy_from_slice(eph_x25519_pk);
    salt[32..].copy_from_slice(recipient_x25519_pk);

    let hk = Hkdf::<Sha512>::new(Some(&salt), ikm.as_ref());
    let mut kek_bytes = Zeroizing::new([0u8; 32]);
    hk.expand(HKDF_INFO, kek_bytes.as_mut())
        .expect("32 bytes is a valid HKDF-SHA-512 output length");

    Kek(SecretKey32::from_bytes(*kek_bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Fixed test keypair A (recipient).
    fn test_sk_a() -> MlKem768X25519RecipientSecretKey {
        MlKem768X25519RecipientSecretKey::new([0x10u8; 32], [0x11u8; MLKEM768_SEED_LEN])
    }

    fn test_pk_a() -> MlKem768X25519RecipientPublicKey {
        test_sk_a().public_key()
    }

    // Fixed test keypair B (different recipient).
    fn test_sk_b() -> MlKem768X25519RecipientSecretKey {
        MlKem768X25519RecipientSecretKey::new([0x20u8; 32], [0x22u8; MLKEM768_SEED_LEN])
    }

    fn test_pk_b() -> MlKem768X25519RecipientPublicKey {
        test_sk_b().public_key()
    }

    fn test_eph_x25519_sk() -> [u8; 32] {
        [0x30u8; 32]
    }

    fn test_mlkem_encap_rand() -> [u8; 32] {
        [0x40u8; 32]
    }

    fn test_wrap_nonce() -> [u8; AES_GCM_SIV_NONCE_LEN] {
        [0x50u8; AES_GCM_SIV_NONCE_LEN]
    }

    fn test_key() -> SecretKey32 {
        SecretKey32::from_bytes([0xABu8; 32])
    }

    fn test_aad() -> Vec<u8> {
        b"hydralock-mlkem768-x25519-test".to_vec()
    }

    fn test_stanza() -> MlKem768X25519Stanza {
        MlKem768X25519Stanza::seal(
            &test_key(),
            &test_pk_a(),
            &test_eph_x25519_sk(),
            &test_mlkem_encap_rand(),
            test_wrap_nonce(),
            &test_aad(),
        )
        .expect("seal failed")
    }

    #[test]
    fn seal_open_roundtrip() {
        let stanza = test_stanza();
        let recovered = stanza.open(&test_sk_a(), &test_aad()).expect("open failed");
        assert_eq!(recovered.expose(), test_key().expose());
    }

    #[test]
    fn stanza_encode_decode_roundtrip() {
        let stanza = test_stanza();
        let encoded = stanza.encode();
        assert_eq!(encoded.len(), MLKEM768_X25519_STANZA_LEN);
        assert_eq!(MLKEM768_X25519_STANZA_LEN, 1182);

        let decoded = MlKem768X25519Stanza::parse(&encoded).expect("parse failed");
        assert_eq!(decoded.eph_x25519_pk, stanza.eph_x25519_pk);
        assert_eq!(decoded.mlkem768_ct, stanza.mlkem768_ct);
        assert_eq!(decoded.wrap_nonce, stanza.wrap_nonce);
        assert_eq!(decoded.wrapped_key, stanza.wrapped_key);
    }

    #[test]
    fn seal_is_deterministic() {
        let s1 = test_stanza();
        let s2 = test_stanza();
        assert_eq!(s1.eph_x25519_pk, s2.eph_x25519_pk);
        assert_eq!(s1.mlkem768_ct, s2.mlkem768_ct);
        assert_eq!(s1.wrapped_key, s2.wrapped_key);
    }

    #[test]
    fn wrong_x25519_key_fails_open() {
        let stanza = test_stanza();
        let wrong_sk =
            MlKem768X25519RecipientSecretKey::new([0xFFu8; 32], *test_sk_a().mlkem768_dk_seed);
        let err = stanza.open(&wrong_sk, &test_aad());
        assert!(matches!(err, Err(MlKem768X25519Error::UnwrapFailed)));
    }

    #[test]
    fn wrong_mlkem_key_fails_open() {
        let stanza = test_stanza();
        let wrong_sk = MlKem768X25519RecipientSecretKey::new(
            *test_sk_a().x25519_sk,
            [0xFFu8; MLKEM768_SEED_LEN],
        );
        let err = stanza.open(&wrong_sk, &test_aad());
        assert!(matches!(err, Err(MlKem768X25519Error::UnwrapFailed)));
    }

    #[test]
    fn wrong_aad_fails_open() {
        let stanza = test_stanza();
        let err = stanza.open(&test_sk_a(), b"wrong-aad");
        assert!(matches!(err, Err(MlKem768X25519Error::UnwrapFailed)));
    }

    #[test]
    fn tampered_mlkem_ct_fails_open() {
        let mut stanza = test_stanza();
        stanza.mlkem768_ct[0] ^= 0x01;
        let err = stanza.open(&test_sk_a(), &test_aad());
        // ML-KEM decapsulation is always "successful" (implicit rejection) but produces
        // a different shared secret, so the AES-GCM-SIV unwrap will fail.
        assert!(matches!(err, Err(MlKem768X25519Error::UnwrapFailed)));
    }

    #[test]
    fn tampered_wrapped_key_fails_open() {
        let mut stanza = test_stanza();
        stanza.wrapped_key[0] ^= 0x01;
        let err = stanza.open(&test_sk_a(), &test_aad());
        assert!(matches!(err, Err(MlKem768X25519Error::UnwrapFailed)));
    }

    #[test]
    fn seal_with_rng_roundtrip() {
        let mut rng = rand::thread_rng();
        let stanza =
            MlKem768X25519Stanza::seal_with_rng(&test_key(), &test_pk_a(), &test_aad(), &mut rng)
                .expect("seal_with_rng failed");

        let encoded = stanza.encode();
        let decoded = MlKem768X25519Stanza::parse(&encoded).expect("parse failed");
        let recovered = decoded
            .open(&test_sk_a(), &test_aad())
            .expect("open failed");
        assert_eq!(recovered.expose(), test_key().expose());
    }

    #[test]
    fn parse_rejects_wrong_length() {
        let err = MlKem768X25519Stanza::parse(&[0u8; MLKEM768_X25519_STANZA_LEN - 1]);
        assert!(matches!(
            err,
            Err(MlKem768X25519Error::InvalidLength {
                expected: MLKEM768_X25519_STANZA_LEN,
                actual: _,
            })
        ));
    }

    #[test]
    fn parse_rejects_wrong_version() {
        let mut bytes = [0u8; MLKEM768_X25519_STANZA_LEN];
        bytes[0..2].copy_from_slice(&9u16.to_be_bytes());
        let err = MlKem768X25519Stanza::parse(&bytes);
        assert!(matches!(
            err,
            Err(MlKem768X25519Error::UnsupportedStanzaVersion {
                expected: 1,
                actual: 9
            })
        ));
    }

    #[test]
    fn different_recipients_get_different_wrapped_keys() {
        let key = test_key();
        let s1 = MlKem768X25519Stanza::seal(
            &key,
            &test_pk_a(),
            &test_eph_x25519_sk(),
            &test_mlkem_encap_rand(),
            test_wrap_nonce(),
            &test_aad(),
        )
        .unwrap();
        let s2 = MlKem768X25519Stanza::seal(
            &key,
            &test_pk_b(),
            &test_eph_x25519_sk(),
            &test_mlkem_encap_rand(),
            test_wrap_nonce(),
            &test_aad(),
        )
        .unwrap();
        // Different recipient EK → different ML-KEM ct and different KEK → different wrapped key.
        assert_ne!(s1.mlkem768_ct, s2.mlkem768_ct);
        assert_ne!(s1.wrapped_key, s2.wrapped_key);
    }

    #[test]
    fn different_mlkem_encap_rand_produces_different_ct() {
        let key = test_key();
        let s1 = MlKem768X25519Stanza::seal(
            &key,
            &test_pk_a(),
            &test_eph_x25519_sk(),
            &[0x40u8; 32],
            test_wrap_nonce(),
            &test_aad(),
        )
        .unwrap();
        let s2 = MlKem768X25519Stanza::seal(
            &key,
            &test_pk_a(),
            &test_eph_x25519_sk(),
            &[0x41u8; 32],
            test_wrap_nonce(),
            &test_aad(),
        )
        .unwrap();
        assert_ne!(s1.mlkem768_ct, s2.mlkem768_ct);
        assert_ne!(s1.wrapped_key, s2.wrapped_key);
    }

    #[test]
    fn recipient_public_key_encode_decode_roundtrip() {
        let pk = test_pk_a();
        let encoded = pk.encode();
        let decoded = MlKem768X25519RecipientPublicKey::decode(&encoded);
        assert_eq!(decoded.x25519_pk, pk.x25519_pk);
        assert_eq!(decoded.mlkem768_ek_bytes, pk.mlkem768_ek_bytes);
    }
}
