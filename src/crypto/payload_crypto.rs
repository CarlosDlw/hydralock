/// Payload chunk encryption and decryption via XChaCha20-Poly1305.
///
/// Each chunk is encrypted independently using keys derived per epoch and chunk index.
/// The nonce is also derived per epoch and chunk index via BLAKE3-XOF.
///
/// AAD binds to: header hash, suite_id, file_uuid, epoch_index, chunk_index,
/// plaintext_chunk_len, and final_chunk_flag to prevent reordering and tampering.

use chacha20poly1305::{XChaCha20Poly1305, Key, KeyInit, aead::{Aead, Payload}};
use generic_array::{GenericArray, typenum::U24};

use crate::crypto::secret::SecretKey32;

/// Errors during payload chunk encryption/decryption.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PayloadCryptoError {
    EncryptionFailed,
    DecryptionFailed,
    InvalidNonceLength,
    InvalidCiphertextLength,
}

impl std::fmt::Display for PayloadCryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for PayloadCryptoError {}

/// Encrypt a payload chunk with XChaCha20-Poly1305.
///
/// Returns: ciphertext_with_tag (variable length, includes 16B tag).
pub fn encrypt_chunk(
    k_chunk: &SecretKey32,
    n_chunk: &[u8; 24],
    plaintext: &[u8],
    file_uuid: &[u8; 16],
    suite_id: u16,
    header_hash: &[u8; 32],
    epoch_index: u32,
    chunk_index: u32,
    plaintext_chunk_len: u32,
    is_final: bool,
) -> Result<Vec<u8>, PayloadCryptoError> {
    // Construct AAD: magic (4) + version (2) + suite (2) + uuid (16) + epoch (4) + chunk (4) + len (4) + final (1) + header_hash (32) = 69 bytes
    let mut aad_bytes = Vec::with_capacity(69);
    aad_bytes.extend_from_slice(b"HLK1");                           // magic
    aad_bytes.extend_from_slice(&1u16.to_be_bytes());              // format version
    aad_bytes.extend_from_slice(&suite_id.to_be_bytes());          // suite_id
    aad_bytes.extend_from_slice(file_uuid);                        // file_uuid
    aad_bytes.extend_from_slice(&epoch_index.to_be_bytes());       // epoch_index
    aad_bytes.extend_from_slice(&chunk_index.to_be_bytes());       // chunk_index
    aad_bytes.extend_from_slice(&plaintext_chunk_len.to_be_bytes()); // plaintext_chunk_len
    aad_bytes.push(if is_final { 1 } else { 0 });                  // final_chunk_flag
    aad_bytes.extend_from_slice(header_hash);                      // header_hash

    // Initialize cipher with k_chunk.
    let key = Key::from(*k_chunk.expose());
    let nonce = GenericArray::<u8, U24>::from_slice(n_chunk);
    let cipher = XChaCha20Poly1305::new(&key);

    // Encrypt with AAD.
    let payload = Payload {
        msg: plaintext,
        aad: &aad_bytes,
    };
    let ciphertext_with_tag = cipher
        .encrypt(nonce, payload)
        .map_err(|_| PayloadCryptoError::EncryptionFailed)?;

    Ok(ciphertext_with_tag)
}

/// Decrypt a payload chunk with XChaCha20-Poly1305.
///
/// Expects ciphertext_with_tag as input (plaintext is recovered from decryption).
pub fn decrypt_chunk(
    k_chunk: &SecretKey32,
    n_chunk: &[u8; 24],
    ciphertext_with_tag: &[u8],
    file_uuid: &[u8; 16],
    suite_id: u16,
    header_hash: &[u8; 32],
    epoch_index: u32,
    chunk_index: u32,
    plaintext_chunk_len: u32,
    is_final: bool,
) -> Result<Vec<u8>, PayloadCryptoError> {
    // Construct AAD (must match encryption).
    let mut aad_bytes = Vec::with_capacity(69);
    aad_bytes.extend_from_slice(b"HLK1");
    aad_bytes.extend_from_slice(&1u16.to_be_bytes());
    aad_bytes.extend_from_slice(&suite_id.to_be_bytes());
    aad_bytes.extend_from_slice(file_uuid);
    aad_bytes.extend_from_slice(&epoch_index.to_be_bytes());
    aad_bytes.extend_from_slice(&chunk_index.to_be_bytes());
    aad_bytes.extend_from_slice(&plaintext_chunk_len.to_be_bytes());
    aad_bytes.push(if is_final { 1 } else { 0 });
    aad_bytes.extend_from_slice(header_hash);

    // Initialize cipher with k_chunk.
    let key = Key::from(*k_chunk.expose());
    let nonce = GenericArray::<u8, U24>::from_slice(n_chunk);
    let cipher = XChaCha20Poly1305::new(&key);

    // Decrypt with AAD.
    let payload = Payload {
        msg: ciphertext_with_tag,
        aad: &aad_bytes,
    };
    let plaintext = cipher
        .decrypt(nonce, payload)
        .map_err(|_| PayloadCryptoError::DecryptionFailed)?;

    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_chunk_key() -> SecretKey32 {
        SecretKey32::from_bytes([11u8; 32])
    }

    fn test_chunk_nonce() -> [u8; 24] {
        [22u8; 24]
    }

    fn test_uuid() -> [u8; 16] {
        [3u8; 16]
    }

    fn test_header_hash() -> [u8; 32] {
        [4u8; 32]
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let key = test_chunk_key();
        let nonce = test_chunk_nonce();
        let uuid = test_uuid();
        let header_hash = test_header_hash();
        let plaintext = b"Hello, World!";

        let encrypted = encrypt_chunk(
            &key, &nonce, plaintext, &uuid, 0x01, &header_hash, 0, 0, plaintext.len() as u32,
            false,
        )
        .expect("encryption failed");

        let decrypted = decrypt_chunk(
            &key, &nonce, &encrypted, &uuid, 0x01, &header_hash, 0, 0, plaintext.len() as u32,
            false,
        )
        .expect("decryption failed");

        assert_eq!(plaintext, &decrypted[..]);
    }

    #[test]
    fn wrong_key_fails_decrypt() {
        let key = test_chunk_key();
        let wrong_key = SecretKey32::from_bytes([99u8; 32]);
        let nonce = test_chunk_nonce();
        let uuid = test_uuid();
        let header_hash = test_header_hash();
        let plaintext = b"Secret";

        let encrypted = encrypt_chunk(
            &key, &nonce, plaintext, &uuid, 0x01, &header_hash, 0, 0, plaintext.len() as u32,
            false,
        )
        .expect("encryption failed");

        let err = decrypt_chunk(
            &wrong_key, &nonce, &encrypted, &uuid, 0x01, &header_hash, 0, 0,
            plaintext.len() as u32,
            false,
        );

        assert!(matches!(
            err,
            Err(PayloadCryptoError::DecryptionFailed)
        ));
    }

    #[test]
    fn wrong_aad_fails_decrypt() {
        let key = test_chunk_key();
        let nonce = test_chunk_nonce();
        let uuid = test_uuid();
        let header_hash = test_header_hash();
        let plaintext = b"Data";

        let encrypted = encrypt_chunk(
            &key, &nonce, plaintext, &uuid, 0x01, &header_hash, 0, 0, plaintext.len() as u32,
            false,
        )
        .expect("encryption failed");

        // Wrong epoch index
        let err = decrypt_chunk(
            &key, &nonce, &encrypted, &uuid, 0x01, &header_hash, 1, 0,
            plaintext.len() as u32,
            false,
        );

        assert!(matches!(
            err,
            Err(PayloadCryptoError::DecryptionFailed)
        ));
    }

    #[test]
    fn wrong_final_flag_fails_decrypt() {
        let key = test_chunk_key();
        let nonce = test_chunk_nonce();
        let uuid = test_uuid();
        let header_hash = test_header_hash();
        let plaintext = b"Last";

        let encrypted = encrypt_chunk(
            &key, &nonce, plaintext, &uuid, 0x01, &header_hash, 0, 0, plaintext.len() as u32,
            true, // encrypted as final
        )
        .expect("encryption failed");

        // Try decrypt with is_final=false
        let err = decrypt_chunk(
            &key, &nonce, &encrypted, &uuid, 0x01, &header_hash, 0, 0,
            plaintext.len() as u32,
            false, // wrong flag
        );

        assert!(matches!(
            err,
            Err(PayloadCryptoError::DecryptionFailed)
        ));
    }

    #[test]
    fn tampered_ciphertext_fails_decrypt() {
        let key = test_chunk_key();
        let nonce = test_chunk_nonce();
        let uuid = test_uuid();
        let header_hash = test_header_hash();
        let plaintext = b"Tamper";

        let mut encrypted = encrypt_chunk(
            &key, &nonce, plaintext, &uuid, 0x01, &header_hash, 0, 0,
            plaintext.len() as u32,
            false,
        )
        .expect("encryption failed");

        // Flip a bit
        if !encrypted.is_empty() {
            encrypted[0] ^= 0x01;
        }

        let err = decrypt_chunk(
            &key, &nonce, &encrypted, &uuid, 0x01, &header_hash, 0, 0,
            plaintext.len() as u32,
            false,
        );

        assert!(matches!(
            err,
            Err(PayloadCryptoError::DecryptionFailed)
        ));
    }

    #[test]
    fn large_chunk_roundtrip() {
        let key = test_chunk_key();
        let nonce = test_chunk_nonce();
        let uuid = test_uuid();
        let header_hash = test_header_hash();
        let plaintext = vec![42u8; 65536]; // 64KB

        let encrypted = encrypt_chunk(
            &key, &nonce, &plaintext, &uuid, 0x01, &header_hash, 0, 0,
            plaintext.len() as u32,
            false,
        )
        .expect("encryption failed");

        let decrypted = decrypt_chunk(
            &key, &nonce, &encrypted, &uuid, 0x01, &header_hash, 0, 0,
            plaintext.len() as u32,
            false,
        )
        .expect("decryption failed");

        assert_eq!(plaintext, decrypted);
    }
}
