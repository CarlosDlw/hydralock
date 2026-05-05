/// Metadata encryption and decryption via AES-256-GCM-SIV.
///
/// Uses control-plane key (`k_control`) to encrypt the metadata plaintext
/// (serialized as CBOR canonical). The nonce is derived deterministically
/// from the plaintext itself via BLAKE3 to ensure reproducibility.
///
/// AAD binds to: header hash, suite_id, section_type, and file_uuid to prevent
/// cross-file splicing and tampering.

use aes_gcm_siv::{Aes256GcmSiv, KeyInit, Nonce, aead::{Aead, Payload}};
use generic_array::GenericArray;

use crate::crypto::secret::SecretKey32;
use crate::format::metadata_plaintext::{MetadataPlaintext, MetadataError as PlaintextError};

/// Metadata-specific AAD section type constant (must match overall AAD scheme).
const METADATA_SECTION_TYPE: u8 = 0x04;

/// Errors during metadata encryption/decryption.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MetadataEncryptionError {
    PlaintextError(String),
    EncodingFailed,
    DecodingFailed,
    EncryptionFailed,
    DecryptionFailed,
    InvalidCiphertextLength,
}

impl std::fmt::Display for MetadataEncryptionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for MetadataEncryptionError {}

impl From<PlaintextError> for MetadataEncryptionError {
    fn from(e: PlaintextError) -> Self {
        MetadataEncryptionError::PlaintextError(format!("{:?}", e))
    }
}

/// Encrypt metadata plaintext.
///
/// Returns: nonce (12B) || ciphertext_with_tag (variable).
/// The plaintext is encoded as CBOR canonical before encryption.
pub fn encrypt_metadata(
    k_control: &SecretKey32,
    metadata: &MetadataPlaintext,
    file_uuid: &[u8; 16],
    suite_id: u16,
    header_hash: &[u8; 32],
) -> Result<Vec<u8>, MetadataEncryptionError> {
    // Encode plaintext as CBOR canonical.
    let plaintext_bytes = metadata.encode()?;

    // Derive nonce from plaintext via BLAKE3-XOF.
    let nonce_bytes = derive_metadata_nonce(&plaintext_bytes);

    // Construct AAD: magic (4) + version (2) + suite (2) + type (1) + uuid (16) + header_hash (32) = 57 bytes
    let mut aad_bytes = Vec::with_capacity(57);
    aad_bytes.extend_from_slice(b"HLK1");                    // magic
    aad_bytes.extend_from_slice(&1u16.to_be_bytes());       // format version
    aad_bytes.extend_from_slice(&suite_id.to_be_bytes());   // suite_id
    aad_bytes.push(METADATA_SECTION_TYPE);                   // section type
    aad_bytes.extend_from_slice(file_uuid);                 // file_uuid
    aad_bytes.extend_from_slice(header_hash);               // header_hash

    // Initialize cipher with k_control.
    let key = GenericArray::from_slice(k_control.expose());
    let nonce = Nonce::from_slice(&nonce_bytes);
    let cipher = Aes256GcmSiv::new(key);

    // Encrypt with AAD.
    let payload = Payload {
        msg: &plaintext_bytes,
        aad: &aad_bytes,
    };
    let ciphertext_with_tag = cipher
        .encrypt(nonce, payload)
        .map_err(|_| MetadataEncryptionError::EncryptionFailed)?;

    // Return: nonce || ciphertext_with_tag
    let mut result = Vec::with_capacity(12 + ciphertext_with_tag.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext_with_tag);
    Ok(result)
}

/// Decrypt metadata from ciphertext.
///
/// Expects input: nonce (12B) || ciphertext_with_tag (variable).
/// Validates AAD and recovers plaintext CBOR, then parses metadata.
pub fn decrypt_metadata(
    k_control: &SecretKey32,
    ciphertext_input: &[u8],
    file_uuid: &[u8; 16],
    suite_id: u16,
    header_hash: &[u8; 32],
) -> Result<MetadataPlaintext, MetadataEncryptionError> {
    // Parse input: nonce (12) || ciphertext_with_tag
    if ciphertext_input.len() < 12 {
        return Err(MetadataEncryptionError::InvalidCiphertextLength);
    }

    let (nonce_bytes, ciphertext_with_tag) = ciphertext_input.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);

    // Construct AAD (must match encryption).
    let mut aad_bytes = Vec::with_capacity(57);
    aad_bytes.extend_from_slice(b"HLK1");
    aad_bytes.extend_from_slice(&1u16.to_be_bytes());
    aad_bytes.extend_from_slice(&suite_id.to_be_bytes());
    aad_bytes.push(METADATA_SECTION_TYPE);
    aad_bytes.extend_from_slice(file_uuid);
    aad_bytes.extend_from_slice(header_hash);

    // Initialize cipher with k_control.
    let key = GenericArray::from_slice(k_control.expose());
    let cipher = Aes256GcmSiv::new(key);

    // Decrypt with AAD.
    let payload = Payload {
        msg: ciphertext_with_tag,
        aad: &aad_bytes,
    };
    let plaintext_bytes = cipher
        .decrypt(nonce, payload)
        .map_err(|_| MetadataEncryptionError::DecryptionFailed)?;

    // Parse CBOR plaintext to metadata struct.
    let metadata = MetadataPlaintext::parse(&plaintext_bytes)?;
    Ok(metadata)
}

/// Derive deterministic nonce from plaintext via BLAKE3-XOF.
///
/// Input: plaintext bytes (variable length)
/// Output: 12-byte nonce
/// Label: "hydralock:v1:metadata-nonce"
fn derive_metadata_nonce(plaintext: &[u8]) -> [u8; 12] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"hydralock:v1:metadata-nonce");
    hasher.update(plaintext);

    let mut nonce = [0u8; 12];
    let mut xof = hasher.finalize_xof();
    xof.fill(&mut nonce);
    nonce
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::metadata_plaintext::PaddingBucket;

    fn test_key() -> SecretKey32 {
        SecretKey32::from_bytes([42u8; 32])
    }

    fn test_uuid() -> [u8; 16] {
        [1u8; 16]
    }

    fn test_header_hash() -> [u8; 32] {
        [2u8; 32]
    }

    fn test_metadata() -> MetadataPlaintext {
        MetadataPlaintext {
            plaintext_size: 1_000_000,
            logical_name: Some("test.bin".to_string()),
            mime_type: Some("application/octet-stream".to_string()),
            created_at: Some(1609459200),
            chunk_size: 65536,
            epoch_size: 100,
            manifest_root: [3u8; 32],
            payload_mode: 0,
            padding_bucket: PaddingBucket::PowerOf2(10),
        }
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let key = test_key();
        let meta = test_metadata();
        let uuid = test_uuid();
        let header_hash = test_header_hash();

        let encrypted = encrypt_metadata(&key, &meta, &uuid, 0x01, &header_hash)
            .expect("encryption failed");
        let decrypted = decrypt_metadata(&key, &encrypted, &uuid, 0x01, &header_hash)
            .expect("decryption failed");

        assert_eq!(meta, decrypted);
    }

    #[test]
    fn ciphertext_with_wrong_key_fails_decrypt() {
        let key = test_key();
        let wrong_key = SecretKey32::from_bytes([99u8; 32]);
        let meta = test_metadata();
        let uuid = test_uuid();
        let header_hash = test_header_hash();

        let encrypted =
            encrypt_metadata(&key, &meta, &uuid, 0x01, &header_hash).expect("encryption failed");
        let err = decrypt_metadata(&wrong_key, &encrypted, &uuid, 0x01, &header_hash);

        assert!(matches!(
            err,
            Err(MetadataEncryptionError::DecryptionFailed)
        ));
    }

    #[test]
    fn wrong_aad_fails_decrypt() {
        let key = test_key();
        let meta = test_metadata();
        let uuid = test_uuid();
        let header_hash = test_header_hash();

        let encrypted =
            encrypt_metadata(&key, &meta, &uuid, 0x01, &header_hash).expect("encryption failed");

        // Wrong header hash
        let wrong_hash = [99u8; 32];
        let err = decrypt_metadata(&key, &encrypted, &uuid, 0x01, &wrong_hash);

        assert!(matches!(
            err,
            Err(MetadataEncryptionError::DecryptionFailed)
        ));
    }

    #[test]
    fn wrong_uuid_fails_decrypt() {
        let key = test_key();
        let meta = test_metadata();
        let uuid = test_uuid();
        let header_hash = test_header_hash();

        let encrypted =
            encrypt_metadata(&key, &meta, &uuid, 0x01, &header_hash).expect("encryption failed");

        // Wrong UUID
        let wrong_uuid = [9u8; 16];
        let err = decrypt_metadata(&key, &encrypted, &wrong_uuid, 0x01, &header_hash);

        assert!(matches!(
            err,
            Err(MetadataEncryptionError::DecryptionFailed)
        ));
    }

    #[test]
    fn tampered_ciphertext_fails_decrypt() {
        let key = test_key();
        let meta = test_metadata();
        let uuid = test_uuid();
        let header_hash = test_header_hash();

        let mut encrypted =
            encrypt_metadata(&key, &meta, &uuid, 0x01, &header_hash).expect("encryption failed");

        // Flip a bit in the ciphertext (after nonce).
        if encrypted.len() > 12 {
            encrypted[12] ^= 0x01;
        }

        let err = decrypt_metadata(&key, &encrypted, &uuid, 0x01, &header_hash);

        assert!(matches!(
            err,
            Err(MetadataEncryptionError::DecryptionFailed)
        ));
    }

    #[test]
    fn truncated_ciphertext_fails_decrypt() {
        let key = test_key();
        let uuid = test_uuid();
        let header_hash = test_header_hash();

        // Too short to contain nonce + tag.
        let truncated = vec![0u8; 11];
        let err = decrypt_metadata(&key, &truncated, &uuid, 0x01, &header_hash);

        assert!(matches!(
            err,
            Err(MetadataEncryptionError::InvalidCiphertextLength)
        ));
    }

    #[test]
    fn nonce_is_deterministic() {
        let meta = test_metadata();
        let uuid = test_uuid();
        let header_hash = test_header_hash();
        let key = test_key();

        let enc1 =
            encrypt_metadata(&key, &meta, &uuid, 0x01, &header_hash).expect("encrypt 1 failed");
        let enc2 =
            encrypt_metadata(&key, &meta, &uuid, 0x01, &header_hash).expect("encrypt 2 failed");

        // Same metadata → same nonce (first 12 bytes should be identical).
        assert_eq!(&enc1[..12], &enc2[..12]);
    }

    #[test]
    fn metadata_without_optionals_roundtrip() {
        let key = test_key();
        let meta = MetadataPlaintext {
            plaintext_size: 500,
            logical_name: None,
            mime_type: None,
            created_at: None,
            chunk_size: 4096,
            epoch_size: 50,
            manifest_root: [7u8; 32],
            payload_mode: 0,
            padding_bucket: PaddingBucket::None,
        };
        let uuid = test_uuid();
        let header_hash = test_header_hash();

        let encrypted =
            encrypt_metadata(&key, &meta, &uuid, 0x01, &header_hash).expect("encryption failed");
        let decrypted = decrypt_metadata(&key, &encrypted, &uuid, 0x01, &header_hash)
            .expect("decryption failed");

        assert_eq!(meta, decrypted);
    }
}
