use aes_gcm_siv::{
    aead::{Aead, KeyInit, Payload},
    Aes256GcmSiv, Key, Nonce,
};

use crate::crypto::password::Kek;
use crate::crypto::secret::SecretKey32;

/// Auth tag length for AES-256-GCM-SIV.
pub const AES_GCM_SIV_TAG_LEN: usize = 16;

/// Nonce length for AES-256-GCM-SIV (96 bits).
pub const AES_GCM_SIV_NONCE_LEN: usize = 12;

/// Length of a wrapped 32-byte key:
/// nonce (12) + ciphertext (32) + tag (16) = 60 bytes.
pub const WRAPPED_KEY_LEN: usize = AES_GCM_SIV_NONCE_LEN + 32 + AES_GCM_SIV_TAG_LEN;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WrapError {
    /// Encryption failed (should not happen with valid parameters).
    EncryptFailed,
    /// Decryption/authentication failed — wrong key, corrupted data, or wrong AAD.
    DecryptFailed,
    /// Input ciphertext length is incorrect.
    InvalidWrappedLength { expected: usize, actual: usize },
}

impl core::fmt::Display for WrapError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::EncryptFailed => write!(f, "AES-256-GCM-SIV encryption failed"),
            Self::DecryptFailed => {
                write!(f, "AES-256-GCM-SIV decryption failed: authentication error")
            }
            Self::InvalidWrappedLength { expected, actual } => write!(
                f,
                "invalid wrapped key length: expected {expected}, got {actual}"
            ),
        }
    }
}

impl std::error::Error for WrapError {}

/// Wrap a 32-byte key under a KEK using AES-256-GCM-SIV.
///
/// The `nonce` must be 12 bytes and MUST be unique per wrapping operation.
/// The `aad` is authenticated but not encrypted — it binds the wrapped blob
/// to the file and wrapper context, preventing cross-file splicing.
///
/// Output layout: `nonce (12B) || ciphertext_with_tag (48B)` = 60 bytes total.
pub fn wrap_key(
    kek: &Kek,
    key: &SecretKey32,
    nonce: &[u8; AES_GCM_SIV_NONCE_LEN],
    aad: &[u8],
) -> Result<[u8; WRAPPED_KEY_LEN], WrapError> {
    let cipher = Aes256GcmSiv::new(Key::<Aes256GcmSiv>::from_slice(kek.expose()));
    let nonce_ref = Nonce::from_slice(nonce);

    let ct = cipher
        .encrypt(
            nonce_ref,
            Payload {
                msg: key.expose(),
                aad,
            },
        )
        .map_err(|_| WrapError::EncryptFailed)?;

    // ct should be 32 + 16 = 48 bytes.
    debug_assert_eq!(ct.len(), 32 + AES_GCM_SIV_TAG_LEN);

    let mut out = [0u8; WRAPPED_KEY_LEN];
    out[..AES_GCM_SIV_NONCE_LEN].copy_from_slice(nonce);
    out[AES_GCM_SIV_NONCE_LEN..].copy_from_slice(&ct);
    Ok(out)
}

/// Unwrap a 32-byte key from `wrapped` using `kek` and `aad`.
///
/// `wrapped` must be exactly `WRAPPED_KEY_LEN` (60) bytes.
/// If the authentication tag does not verify, returns `DecryptFailed`.
/// The returned `SecretKey32` is zeroized on drop.
pub fn unwrap_key(
    kek: &Kek,
    wrapped: &[u8],
    aad: &[u8],
) -> Result<SecretKey32, WrapError> {
    if wrapped.len() != WRAPPED_KEY_LEN {
        return Err(WrapError::InvalidWrappedLength {
            expected: WRAPPED_KEY_LEN,
            actual: wrapped.len(),
        });
    }

    let nonce = Nonce::from_slice(&wrapped[..AES_GCM_SIV_NONCE_LEN]);
    let ct = &wrapped[AES_GCM_SIV_NONCE_LEN..];

    let cipher = Aes256GcmSiv::new(Key::<Aes256GcmSiv>::from_slice(kek.expose()));
    let pt = cipher
        .decrypt(
            nonce,
            Payload { msg: ct, aad },
        )
        .map_err(|_| WrapError::DecryptFailed)?;

    // pt must be exactly 32 bytes.
    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&pt);
    Ok(SecretKey32::from_bytes(key_bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::password::{derive_kek_from_passphrase, Argon2Params};
    use crate::crypto::secret::SecretKey32;

    fn test_kek() -> Kek {
        let params = Argon2Params {
            version: 19,
            memory_kib: 64,
            time_cost: 1,
            parallelism: 1,
            salt: [0xCCu8; 32],
        };
        derive_kek_from_passphrase(b"test-passphrase", &params).expect("kek derivation")
    }

    fn test_key() -> SecretKey32 {
        SecretKey32::from_bytes([0x42u8; 32])
    }

    fn test_nonce() -> [u8; AES_GCM_SIV_NONCE_LEN] {
        [0x01u8; AES_GCM_SIV_NONCE_LEN]
    }

    #[test]
    fn wrap_unwrap_roundtrip() {
        let kek = test_kek();
        let key = test_key();
        let nonce = test_nonce();
        let aad = b"test-aad-binding";

        let wrapped = wrap_key(&kek, &key, &nonce, aad).expect("wrap should succeed");
        assert_eq!(wrapped.len(), WRAPPED_KEY_LEN);

        let recovered = unwrap_key(&kek, &wrapped, aad).expect("unwrap should succeed");
        assert_eq!(recovered.expose(), key.expose());
    }

    #[test]
    fn wrong_aad_fails_unwrap() {
        let kek = test_kek();
        let key = test_key();
        let nonce = test_nonce();

        let wrapped = wrap_key(&kek, &key, &nonce, b"correct-aad").expect("wrap");
        let err = unwrap_key(&kek, &wrapped, b"wrong-aad").expect_err("should fail");
        assert_eq!(err, WrapError::DecryptFailed);
    }

    #[test]
    fn wrong_kek_fails_unwrap() {
        let kek = test_kek();
        let key = test_key();
        let nonce = test_nonce();
        let aad = b"aad";

        let wrapped = wrap_key(&kek, &key, &nonce, aad).expect("wrap");

        let wrong_params = Argon2Params {
            version: 19,
            memory_kib: 64,
            time_cost: 1,
            parallelism: 1,
            salt: [0xDDu8; 32],
        };
        let wrong_kek =
            derive_kek_from_passphrase(b"wrong-passphrase", &wrong_params).expect("kek");
        let err = unwrap_key(&wrong_kek, &wrapped, aad).expect_err("should fail");
        assert_eq!(err, WrapError::DecryptFailed);
    }

    #[test]
    fn corrupted_ciphertext_fails_unwrap() {
        let kek = test_kek();
        let key = test_key();
        let nonce = test_nonce();
        let aad = b"aad";

        let mut wrapped = wrap_key(&kek, &key, &nonce, aad).expect("wrap");
        // Flip a bit in the ciphertext region
        wrapped[AES_GCM_SIV_NONCE_LEN] ^= 0xFF;
        let err = unwrap_key(&kek, &wrapped, aad).expect_err("should fail");
        assert_eq!(err, WrapError::DecryptFailed);
    }

    #[test]
    fn wrong_wrapped_length_is_rejected() {
        let kek = test_kek();
        let err = unwrap_key(&kek, &[0u8; 59], b"aad").expect_err("short input");
        assert_eq!(
            err,
            WrapError::InvalidWrappedLength {
                expected: WRAPPED_KEY_LEN,
                actual: 59,
            }
        );
    }
}
