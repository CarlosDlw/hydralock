//! Streamable payload reader for decrypting chunks produced by PayloadWriter.
//!
//! State machine:
//! - epoch_index / chunk_index_in_epoch advance automatically after each chunk.
//! - Reorder and splice are detected implicitly: if a chunk was encrypted with
//!   different (epoch, chunk) indices, the AEAD tag will fail verification.
//! - Truncation is detected by checking is_final on the last provided chunk;
//!   reading additional chunks after is_final is an error.

use crate::crypto::kdf::{derive_chunk_key, derive_chunk_nonce, derive_epoch_key};
use crate::crypto::payload_crypto::{PayloadCryptoError, decrypt_chunk};
use crate::crypto::secret::SecretKey32;

/// Size of the Poly1305 authentication tag in bytes.
const POLY1305_TAG_SIZE: usize = 16;

/// Errors during payload chunk reading/decryption.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PayloadReaderError {
    /// Ciphertext is shorter than the minimum (tag only, no actual ciphertext).
    CiphertextTooShort { epoch: u32, chunk: u32 },
    /// AEAD verification failed. Covers wrong key, reorder, splice, tampering.
    DecryptionFailed { epoch: u32, chunk: u32 },
    /// Attempted to read after the final chunk was already processed.
    ReadAfterFinal,
    /// Chunk or epoch counter overflowed u32 — container exceeds supported size.
    ChunkCountOverflow,
}

impl std::fmt::Display for PayloadReaderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for PayloadReaderError {}

impl From<PayloadCryptoError> for PayloadReaderError {
    fn from(_: PayloadCryptoError) -> Self {
        // Positional context is added by the caller.
        unreachable!("use map_err with context instead")
    }
}

/// Streamable reader that decrypts payload chunks in order.
pub struct PayloadReader {
    // Cryptographic material
    k_payload_master: SecretKey32,
    file_uuid: [u8; 16],
    suite_id: u16,

    // Configuration
    epoch_size: u32,

    // Position state
    epoch_index: u32,
    chunk_index_in_epoch: u32,

    // Completion flag
    finalized: bool,
}

impl PayloadReader {
    /// Create a new payload reader.
    ///
    /// Parameters must match those used when writing:
    /// - `k_payload_master`: root payload key from the KDF tree.
    /// - `file_uuid`: bound to AAD; prevents cross-file splice.
    /// - `suite_id`: bound to AAD; prevents cross-suite downgrade.
    /// - `epoch_size`: max chunks per epoch (must match writer epoch_size).
    pub fn new(
        k_payload_master: SecretKey32,
        file_uuid: [u8; 16],
        suite_id: u16,
        epoch_size: u32,
    ) -> Self {
        PayloadReader {
            k_payload_master,
            file_uuid,
            suite_id,
            epoch_size,
            epoch_index: 0,
            chunk_index_in_epoch: 0,
            finalized: false,
        }
    }

    /// Decrypt a single chunk and advance the position.
    ///
    /// `ciphertext_with_tag` is the raw AEAD output (plaintext + 16-byte tag).
    /// `is_final` must be `true` for the last chunk in the payload and `false`
    /// for all others. Mismatch causes AEAD verification failure.
    ///
    /// Returns the plaintext bytes on success.
    ///
    /// Errors:
    /// - `ReadAfterFinal`: called after a chunk with `is_final=true`.
    /// - `CiphertextTooShort`: fewer bytes than the 16-byte tag.
    /// - `DecryptionFailed`: AEAD tag mismatch (wrong key, reorder, tamper, splice).
    pub fn read_chunk(
        &mut self,
        ciphertext_with_tag: &[u8],
        is_final: bool,
    ) -> Result<Vec<u8>, PayloadReaderError> {
        if self.finalized {
            return Err(PayloadReaderError::ReadAfterFinal);
        }

        if ciphertext_with_tag.len() < POLY1305_TAG_SIZE {
            return Err(PayloadReaderError::CiphertextTooShort {
                epoch: self.epoch_index,
                chunk: self.chunk_index_in_epoch,
            });
        }

        let plaintext_chunk_len = (ciphertext_with_tag.len() - POLY1305_TAG_SIZE) as u32;

        // Derive keys for the current position.
        let k_epoch = derive_epoch_key(&self.k_payload_master, self.epoch_index);
        let k_chunk = derive_chunk_key(&k_epoch, self.chunk_index_in_epoch);
        let n_chunk = derive_chunk_nonce(&k_epoch, self.chunk_index_in_epoch);

        let epoch = self.epoch_index;
        let chunk = self.chunk_index_in_epoch;

        let plaintext = decrypt_chunk(
            &k_chunk,
            n_chunk.expose(),
            ciphertext_with_tag,
            &self.file_uuid,
            self.suite_id,
            epoch,
            chunk,
            plaintext_chunk_len,
            is_final,
        )
        .map_err(|_| PayloadReaderError::DecryptionFailed { epoch, chunk })?;

        // Advance position with overflow protection.
        self.chunk_index_in_epoch = self
            .chunk_index_in_epoch
            .checked_add(1)
            .ok_or(PayloadReaderError::ChunkCountOverflow)?;
        if self.chunk_index_in_epoch >= self.epoch_size {
            self.epoch_index = self
                .epoch_index
                .checked_add(1)
                .ok_or(PayloadReaderError::ChunkCountOverflow)?;
            self.chunk_index_in_epoch = 0;
        }

        if is_final {
            self.finalized = true;
        }

        Ok(plaintext)
    }

    /// Seek to the start of `epoch_index`, resetting the chunk counter.
    ///
    /// This allows skipping to a known epoch boundary for random access reads.
    /// Does not reset `finalized` — if a final chunk was already read, seek
    /// moves the position but subsequent `read_chunk` calls will still fail.
    pub fn seek_epoch(&mut self, epoch_index: u32) {
        self.epoch_index = epoch_index;
        self.chunk_index_in_epoch = 0;
        self.finalized = false;
    }

    /// Returns `true` if the final chunk was successfully decrypted.
    pub fn is_finalized(&self) -> bool {
        self.finalized
    }

    /// Current epoch index.
    pub fn epoch_index(&self) -> u32 {
        self.epoch_index
    }

    /// Current chunk index within the current epoch.
    pub fn chunk_index_in_epoch(&self) -> u32 {
        self.chunk_index_in_epoch
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::payload_writer::{EncryptedChunkEntry, PayloadWriter};

    fn test_key() -> SecretKey32 {
        SecretKey32::from_bytes([0xABu8; 32])
    }

    fn test_uuid() -> [u8; 16] {
        [0x11u8; 16]
    }

    fn make_writer(chunk_size: u32, epoch_size: u32, data: &[u8]) -> Vec<EncryptedChunkEntry> {
        let mut writer = PayloadWriter::new(
            test_key(),
            test_uuid(),
            0x01,
            chunk_size,
            epoch_size,
            data.len() as u64,
        )
        .unwrap();
        writer.write(data).unwrap();
        writer.finalize().unwrap()
    }

    fn make_reader(epoch_size: u32) -> PayloadReader {
        PayloadReader::new(test_key(), test_uuid(), 0x01, epoch_size)
    }

    fn decrypt_all(
        chunks: &[EncryptedChunkEntry],
        reader: &mut PayloadReader,
    ) -> Result<Vec<u8>, PayloadReaderError> {
        let mut out = Vec::new();
        for chunk in chunks {
            let plaintext = reader.read_chunk(&chunk.ciphertext_with_tag, chunk.is_final)?;
            out.extend_from_slice(&plaintext);
        }
        Ok(out)
    }

    #[test]
    fn single_chunk_roundtrip() {
        let plaintext = b"Hello, HydraLock!";
        let chunks = make_writer(4096, 100, plaintext);

        assert_eq!(chunks.len(), 1);
        assert!(chunks[0].is_final);

        let mut reader = make_reader(100);
        let recovered = decrypt_all(&chunks, &mut reader).unwrap();

        assert_eq!(recovered, plaintext);
        assert!(reader.is_finalized());
    }

    #[test]
    fn multiple_chunks_roundtrip() {
        let plaintext: Vec<u8> = (0u8..=255u8).cycle().take(512).collect();
        let chunks = make_writer(64, 100, &plaintext);

        assert!(chunks.len() > 1);
        assert!(chunks.last().unwrap().is_final);

        let mut reader = make_reader(100);
        let recovered = decrypt_all(&chunks, &mut reader).unwrap();

        assert_eq!(recovered, plaintext);
        assert!(reader.is_finalized());
    }

    #[test]
    fn multi_epoch_roundtrip() {
        // 3 chunks per epoch, 10 chunks total = 4 epochs (3+3+3+1)
        let plaintext: Vec<u8> = (0u8..255u8).cycle().take(1000).collect();
        let chunk_size = 100;
        let epoch_size = 3;
        let chunks = make_writer(chunk_size, epoch_size, &plaintext);

        assert!(chunks.len() > epoch_size as usize);

        let mut reader = make_reader(epoch_size);
        let recovered = decrypt_all(&chunks, &mut reader).unwrap();

        assert_eq!(recovered, plaintext);
        assert!(reader.is_finalized());
    }

    #[test]
    fn read_after_final_is_error() {
        let plaintext = b"Small";
        let chunks = make_writer(4096, 100, plaintext);

        let mut reader = make_reader(100);
        reader
            .read_chunk(&chunks[0].ciphertext_with_tag, true)
            .unwrap();

        // Any read after the final chunk must fail.
        let extra_ct = chunks[0].ciphertext_with_tag.clone();
        let err = reader.read_chunk(&extra_ct, false);
        assert!(matches!(err, Err(PayloadReaderError::ReadAfterFinal)));
    }

    #[test]
    fn tampered_chunk_fails() {
        let plaintext = b"Tamper me";
        let chunks = make_writer(4096, 100, plaintext);

        let mut tampered = chunks[0].ciphertext_with_tag.clone();
        tampered[0] ^= 0x01;

        let mut reader = make_reader(100);
        let err = reader.read_chunk(&tampered, true);
        assert!(matches!(
            err,
            Err(PayloadReaderError::DecryptionFailed { epoch: 0, chunk: 0 })
        ));
    }

    #[test]
    fn reorder_detection() {
        // Write 2 chunks, then try to decrypt chunk[1] first (at position 0).
        let plaintext: Vec<u8> = (0u8..200u8).collect();
        let chunks = make_writer(100, 100, &plaintext);

        assert_eq!(chunks.len(), 2);

        let mut reader = make_reader(100);
        // Feed chunk[1] at position 0 — AAD mismatch causes failure.
        let err = reader.read_chunk(&chunks[1].ciphertext_with_tag, false);
        assert!(matches!(
            err,
            Err(PayloadReaderError::DecryptionFailed { epoch: 0, chunk: 0 })
        ));
    }

    #[test]
    fn seek_epoch_then_decrypt() {
        // Write 4 chunks with epoch_size=2 (2 epochs: 0=[0,1], 1=[2,3]).
        let plaintext: Vec<u8> = (0u8..=255u8).cycle().take(400).collect();
        let chunk_size = 100;
        let epoch_size = 2;
        let chunks = make_writer(chunk_size, epoch_size, &plaintext);
        assert_eq!(chunks.len(), 4);

        // Decrypt only epoch 1 (chunks 2 and 3).
        let mut reader = make_reader(epoch_size);
        reader.seek_epoch(1);

        let c2 = reader
            .read_chunk(&chunks[2].ciphertext_with_tag, chunks[2].is_final)
            .unwrap();
        let c3 = reader
            .read_chunk(&chunks[3].ciphertext_with_tag, chunks[3].is_final)
            .unwrap();

        // Reconstruct what the last 2 chunks should contain.
        let expected = &plaintext[200..];
        let mut got = c2;
        got.extend(c3);
        assert_eq!(got, expected);
        assert!(reader.is_finalized());
    }

    #[test]
    fn ciphertext_too_short_error() {
        let mut reader = make_reader(100);
        // Feed something shorter than the 16-byte tag.
        let err = reader.read_chunk(&[0u8; 15], false);
        assert!(matches!(
            err,
            Err(PayloadReaderError::CiphertextTooShort { epoch: 0, chunk: 0 })
        ));
    }
}
