use rand::RngCore;

use crate::crypto::password::{Argon2Params, PasswordError, derive_kek_from_passphrase};
use crate::crypto::secret::SecretKey32;
use crate::crypto::wrap::{
    AES_GCM_SIV_NONCE_LEN, WRAPPED_KEY_LEN, WrapError, unwrap_key, wrap_key,
};

/// Stanza type identifier for the PASS-ARGON2ID wrapper.
pub const WRAPPER_TYPE_PASS_ARGON2ID: u16 = 0x0001;

/// Wire-format stanza version — always 1 in HydraLock v1.
const STANZA_VERSION: u16 = 1;

/// Wire-format Argon2 algorithm version — Argon2id draft v19 (0x13).
const ARGON2_WIRE_VERSION: u32 = 19;

/// Fixed byte length of an encoded PASS-ARGON2ID stanza.
///
/// Layout:
///   Offset  Size  Field
///   0       2     stanza_version (u16)
///   2       4     argon2_version (u32)
///   6       4     memory_kib (u32)
///   10      4     time_cost (u32)
///   14      4     parallelism (u32)
///   18      32    salt
///   50      12    wrap_nonce
///   62      48    wrapped_key (32B ciphertext + 16B tag)
///   Total: 110 bytes
pub const PASS_ARGON2ID_STANZA_LEN: usize = 110;

const SALT_OFFSET: usize = 18;
const NONCE_OFFSET: usize = 50;
const WRAPPED_KEY_OFFSET: usize = 62;

/// Decoded PASS-ARGON2ID stanza.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PassArgon2idStanza {
    /// Argon2id parameters as stored in the stanza.
    pub params: Argon2Params,
    /// The 12-byte AES-GCM-SIV nonce used to wrap the key.
    pub wrap_nonce: [u8; AES_GCM_SIV_NONCE_LEN],
    /// The wrapped key blob: 48 bytes (32B ciphertext + 16B tag).
    pub wrapped_key: [u8; WRAPPED_KEY_LEN - AES_GCM_SIV_NONCE_LEN],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PassArgon2idError {
    /// Stanza bytes length is wrong.
    InvalidLength { expected: usize, actual: usize },
    /// The `stanza_version` field is not 1.
    UnsupportedStanzaVersion { expected: u16, actual: u16 },
    /// The `argon2_version` field is not 19.
    UnsupportedArgon2Version { expected: u32, actual: u32 },
    /// Argon2id parameter values are invalid.
    InvalidArgon2Params,
    /// Key derivation from passphrase failed.
    KeyDerivation(PasswordError),
    /// Key wrapping failed (encryption).
    WrapFailed,
    /// Key unwrapping failed (authentication error or wrong passphrase).
    UnwrapFailed,
}

impl core::fmt::Display for PassArgon2idError {
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
            Self::UnsupportedArgon2Version { expected, actual } => {
                write!(
                    f,
                    "unsupported Argon2 version: expected {expected}, got {actual}"
                )
            }
            Self::InvalidArgon2Params => write!(f, "invalid Argon2id parameters in stanza"),
            Self::KeyDerivation(e) => write!(f, "passphrase key derivation failed: {e}"),
            Self::WrapFailed => write!(f, "key wrapping failed"),
            Self::UnwrapFailed => {
                write!(
                    f,
                    "key unwrapping failed: wrong passphrase or corrupted stanza"
                )
            }
        }
    }
}

impl std::error::Error for PassArgon2idError {}

impl PassArgon2idStanza {
    /// Parse a PASS-ARGON2ID stanza from its 110-byte binary representation.
    pub fn parse(bytes: &[u8]) -> Result<Self, PassArgon2idError> {
        if bytes.len() != PASS_ARGON2ID_STANZA_LEN {
            return Err(PassArgon2idError::InvalidLength {
                expected: PASS_ARGON2ID_STANZA_LEN,
                actual: bytes.len(),
            });
        }

        let stanza_version = u16::from_be_bytes([bytes[0], bytes[1]]);
        if stanza_version != STANZA_VERSION {
            return Err(PassArgon2idError::UnsupportedStanzaVersion {
                expected: STANZA_VERSION,
                actual: stanza_version,
            });
        }

        let argon2_version = u32::from_be_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]);
        if argon2_version != ARGON2_WIRE_VERSION {
            return Err(PassArgon2idError::UnsupportedArgon2Version {
                expected: ARGON2_WIRE_VERSION,
                actual: argon2_version,
            });
        }

        let memory_kib = u32::from_be_bytes([bytes[6], bytes[7], bytes[8], bytes[9]]);
        let time_cost = u32::from_be_bytes([bytes[10], bytes[11], bytes[12], bytes[13]]);
        let parallelism = u32::from_be_bytes([bytes[14], bytes[15], bytes[16], bytes[17]]);

        // Validate parameters eagerly to fail fast on corrupt stanzas.
        argon2::Params::new(memory_kib, time_cost, parallelism, Some(32))
            .map_err(|_| PassArgon2idError::InvalidArgon2Params)?;

        let mut salt = [0u8; 32];
        salt.copy_from_slice(&bytes[SALT_OFFSET..SALT_OFFSET + 32]);

        let mut wrap_nonce = [0u8; AES_GCM_SIV_NONCE_LEN];
        wrap_nonce.copy_from_slice(&bytes[NONCE_OFFSET..NONCE_OFFSET + AES_GCM_SIV_NONCE_LEN]);

        let mut wrapped_key = [0u8; WRAPPED_KEY_LEN - AES_GCM_SIV_NONCE_LEN];
        wrapped_key.copy_from_slice(
            &bytes[WRAPPED_KEY_OFFSET
                ..WRAPPED_KEY_OFFSET + (WRAPPED_KEY_LEN - AES_GCM_SIV_NONCE_LEN)],
        );

        Ok(Self {
            params: Argon2Params {
                version: argon2_version,
                memory_kib,
                time_cost,
                parallelism,
                salt,
            },
            wrap_nonce,
            wrapped_key,
        })
    }

    /// Encode this stanza into its canonical 110-byte binary representation.
    pub fn encode(&self) -> [u8; PASS_ARGON2ID_STANZA_LEN] {
        let mut out = [0u8; PASS_ARGON2ID_STANZA_LEN];
        out[0..2].copy_from_slice(&STANZA_VERSION.to_be_bytes());
        out[2..6].copy_from_slice(&self.params.version.to_be_bytes());
        out[6..10].copy_from_slice(&self.params.memory_kib.to_be_bytes());
        out[10..14].copy_from_slice(&self.params.time_cost.to_be_bytes());
        out[14..18].copy_from_slice(&self.params.parallelism.to_be_bytes());
        out[SALT_OFFSET..SALT_OFFSET + 32].copy_from_slice(&self.params.salt);
        out[NONCE_OFFSET..NONCE_OFFSET + AES_GCM_SIV_NONCE_LEN].copy_from_slice(&self.wrap_nonce);
        out[WRAPPED_KEY_OFFSET..WRAPPED_KEY_OFFSET + (WRAPPED_KEY_LEN - AES_GCM_SIV_NONCE_LEN)]
            .copy_from_slice(&self.wrapped_key);
        out
    }

    /// Seal `key` with `passphrase` using fresh random salt and nonce.
    ///
    /// `params` carries the pre-chosen Argon2id cost parameters and a fresh
    /// random 32-byte salt generated by the caller or by `seal_with_rng`.
    /// `aad` is the wrapper AAD that binds this stanza to the file context.
    pub fn seal(
        key: &SecretKey32,
        params: Argon2Params,
        passphrase: &[u8],
        wrap_nonce: [u8; AES_GCM_SIV_NONCE_LEN],
        aad: &[u8],
    ) -> Result<Self, PassArgon2idError> {
        let kek = derive_kek_from_passphrase(passphrase, &params)
            .map_err(PassArgon2idError::KeyDerivation)?;

        // Build the full wrapped blob: nonce || ciphertext_with_tag
        let wrapped_full =
            wrap_key(&kek, key, &wrap_nonce, aad).map_err(|_| PassArgon2idError::WrapFailed)?;

        // Strip the nonce prefix (nonce is stored separately in the stanza layout)
        let mut wrapped_key = [0u8; WRAPPED_KEY_LEN - AES_GCM_SIV_NONCE_LEN];
        wrapped_key.copy_from_slice(&wrapped_full[AES_GCM_SIV_NONCE_LEN..]);

        Ok(Self {
            params,
            wrap_nonce,
            wrapped_key,
        })
    }

    /// Seal `key` using random salt and nonce drawn from `rng`.
    pub fn seal_with_rng<R: RngCore>(
        key: &SecretKey32,
        argon2_params_no_salt: Argon2Params,
        passphrase: &[u8],
        aad: &[u8],
        rng: &mut R,
    ) -> Result<Self, PassArgon2idError> {
        let mut salt = [0u8; 32];
        rng.fill_bytes(&mut salt);
        let mut wrap_nonce = [0u8; AES_GCM_SIV_NONCE_LEN];
        rng.fill_bytes(&mut wrap_nonce);

        let params = Argon2Params {
            salt,
            ..argon2_params_no_salt
        };

        Self::seal(key, params, passphrase, wrap_nonce, aad)
    }

    /// Open (unwrap) the sealed key using `passphrase`.
    ///
    /// `aad` must match the value used during `seal`.
    pub fn open(&self, passphrase: &[u8], aad: &[u8]) -> Result<SecretKey32, PassArgon2idError> {
        let kek = derive_kek_from_passphrase(passphrase, &self.params)
            .map_err(PassArgon2idError::KeyDerivation)?;

        // Reconstruct the full wrapped blob: nonce || ciphertext_with_tag
        let mut wrapped_full = [0u8; WRAPPED_KEY_LEN];
        wrapped_full[..AES_GCM_SIV_NONCE_LEN].copy_from_slice(&self.wrap_nonce);
        wrapped_full[AES_GCM_SIV_NONCE_LEN..].copy_from_slice(&self.wrapped_key);

        unwrap_key(&kek, &wrapped_full, aad).map_err(|e| match e {
            WrapError::DecryptFailed => PassArgon2idError::UnwrapFailed,
            _ => PassArgon2idError::WrapFailed,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::password::{Argon2Params, Argon2Profile};
    use crate::crypto::secret::SecretKey32;

    fn minimal_params() -> Argon2Params {
        Argon2Params {
            version: 19,
            memory_kib: 64,
            time_cost: 1,
            parallelism: 1,
            salt: [0x55u8; 32],
        }
    }

    fn test_key() -> SecretKey32 {
        SecretKey32::from_bytes([0xABu8; 32])
    }

    fn test_nonce() -> [u8; AES_GCM_SIV_NONCE_LEN] {
        [0x07u8; AES_GCM_SIV_NONCE_LEN]
    }

    #[test]
    fn stanza_encode_decode_roundtrip() {
        let key = test_key();
        let stanza = PassArgon2idStanza::seal(
            &key,
            minimal_params(),
            b"correct horse battery staple",
            test_nonce(),
            b"test-aad",
        )
        .expect("seal");

        let encoded = stanza.encode();
        assert_eq!(encoded.len(), PASS_ARGON2ID_STANZA_LEN);

        let decoded = PassArgon2idStanza::parse(&encoded).expect("parse");
        assert_eq!(decoded, stanza);
    }

    #[test]
    fn open_recovers_correct_key() {
        let key = test_key();
        let stanza = PassArgon2idStanza::seal(
            &key,
            minimal_params(),
            b"my-passphrase",
            test_nonce(),
            b"aad-bytes",
        )
        .expect("seal");

        let recovered = stanza.open(b"my-passphrase", b"aad-bytes").expect("open");
        assert_eq!(recovered.expose(), key.expose());
    }

    #[test]
    fn wrong_passphrase_fails_open() {
        let key = test_key();
        let stanza =
            PassArgon2idStanza::seal(&key, minimal_params(), b"correct", test_nonce(), b"aad")
                .expect("seal");

        let err = stanza.open(b"wrong", b"aad").expect_err("should fail");
        assert_eq!(err, PassArgon2idError::UnwrapFailed);
    }

    #[test]
    fn wrong_aad_fails_open() {
        let key = test_key();
        let stanza = PassArgon2idStanza::seal(
            &key,
            minimal_params(),
            b"pass",
            test_nonce(),
            b"correct-aad",
        )
        .expect("seal");

        let err = stanza.open(b"pass", b"wrong-aad").expect_err("should fail");
        assert_eq!(err, PassArgon2idError::UnwrapFailed);
    }

    #[test]
    fn parse_rejects_wrong_length() {
        let err = PassArgon2idStanza::parse(&[0u8; 109]).expect_err("short input must fail");
        assert_eq!(
            err,
            PassArgon2idError::InvalidLength {
                expected: PASS_ARGON2ID_STANZA_LEN,
                actual: 109,
            }
        );
    }

    #[test]
    fn parse_rejects_wrong_stanza_version() {
        let key = test_key();
        let stanza =
            PassArgon2idStanza::seal(&key, minimal_params(), b"pass", test_nonce(), b"aad")
                .expect("seal");
        let mut encoded = stanza.encode();
        encoded[1] = 2; // stanza_version high byte → 2
        let err = PassArgon2idStanza::parse(&encoded).expect_err("bad version must fail");
        assert_eq!(
            err,
            PassArgon2idError::UnsupportedStanzaVersion {
                expected: 1,
                actual: 2,
            }
        );
    }

    #[test]
    fn seal_with_rng_produces_parseable_stanza() {
        let key = test_key();
        let params_no_salt = Argon2Params::from_profile(Argon2Profile::Interactive, [0u8; 32]);
        let mut rng = rand::thread_rng();
        let stanza = PassArgon2idStanza::seal_with_rng(
            &key,
            params_no_salt,
            b"passphrase",
            b"aad",
            &mut rng,
        )
        .expect("seal_with_rng");

        let encoded = stanza.encode();
        let decoded = PassArgon2idStanza::parse(&encoded).expect("parse");
        let recovered = decoded.open(b"passphrase", b"aad").expect("open");
        assert_eq!(recovered.expose(), key.expose());
    }
}
