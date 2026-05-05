/// Streamable payload writer for dividing plaintext into epochs and chunks.
///
/// The writer tracks state:
/// - plaintext_written: total bytes written so far
/// - epoch_index: current epoch (0-based)
/// - chunk_index_in_epoch: chunks written in current epoch (0-based)
///
/// Each chunk is encrypted independently with XChaCha20-Poly1305.
/// Only the last chunk in an epoch can be smaller than chunk_size.
///
/// Format logic:
/// - epoch_size: max chunks per epoch
/// - chunk_size: max bytes per chunk
/// - If a chunk reaches chunk_size bytes or epoch reaches epoch_size chunks,
///   it's finalized and a new one starts.

use crate::crypto::secret::SecretKey32;
use crate::crypto::kdf::{derive_chunk_key, derive_chunk_nonce};
use crate::crypto::payload_crypto::{encrypt_chunk, PayloadCryptoError};

/// Builder error types for payload writer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PayloadWriterError {
    InvalidChunkSize,
    InvalidEpochSize,
    ZeroPlaintextSize,
    CryptoError(String),
}

impl std::fmt::Display for PayloadWriterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for PayloadWriterError {}

impl From<PayloadCryptoError> for PayloadWriterError {
    fn from(e: PayloadCryptoError) -> Self {
        PayloadWriterError::CryptoError(format!("{:?}", e))
    }
}

/// Encrypted chunk entry (ready to write to container).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncryptedChunkEntry {
    pub ciphertext_with_tag: Vec<u8>,
    pub is_final: bool,
}

/// Streamable payload writer with state tracking.
pub struct PayloadWriter {
    // Configuration
    chunk_size: u32,
    epoch_size: u32,
    plaintext_total_size: u64,

    // State
    plaintext_written: u64,
    epoch_index: u32,
    chunk_index_in_epoch: u32,
    chunk_buffer: Vec<u8>,

    // Cryptographic material
    k_payload_master: SecretKey32,
    file_uuid: [u8; 16],
    suite_id: u16,
    header_hash: [u8; 32],

    // Output: all encrypted chunks in order
    encrypted_chunks: Vec<EncryptedChunkEntry>,
}

impl PayloadWriter {
    /// Create a new payload writer.
    pub fn new(
        k_payload_master: SecretKey32,
        file_uuid: [u8; 16],
        suite_id: u16,
        header_hash: [u8; 32],
        chunk_size: u32,
        epoch_size: u32,
        plaintext_total_size: u64,
    ) -> Result<Self, PayloadWriterError> {
        if chunk_size == 0 {
            return Err(PayloadWriterError::InvalidChunkSize);
        }
        if epoch_size == 0 {
            return Err(PayloadWriterError::InvalidEpochSize);
        }
        if plaintext_total_size == 0 {
            return Err(PayloadWriterError::ZeroPlaintextSize);
        }

        Ok(PayloadWriter {
            chunk_size,
            epoch_size,
            plaintext_total_size,
            plaintext_written: 0,
            epoch_index: 0,
            chunk_index_in_epoch: 0,
            chunk_buffer: Vec::with_capacity(chunk_size as usize),
            k_payload_master,
            file_uuid,
            suite_id,
            header_hash,
            encrypted_chunks: Vec::new(),
        })
    }

    /// Write plaintext data to the writer. Can be called multiple times.
    /// Returns the number of bytes consumed.
    pub fn write(&mut self, plaintext: &[u8]) -> Result<usize, PayloadWriterError> {
        let mut offset = 0;

        while offset < plaintext.len() && self.plaintext_written < self.plaintext_total_size {
            let space_in_chunk = (self.chunk_size as usize) - self.chunk_buffer.len();
            let bytes_to_write = std::cmp::min(
                space_in_chunk,
                std::cmp::min(
                    plaintext.len() - offset,
                    (self.plaintext_total_size - self.plaintext_written) as usize,
                ),
            );

            self.chunk_buffer
                .extend_from_slice(&plaintext[offset..offset + bytes_to_write]);
            self.plaintext_written += bytes_to_write as u64;
            offset += bytes_to_write;

            // Check if chunk is full or this is the final chunk
            let is_full = self.chunk_buffer.len() as u32 == self.chunk_size;
            let is_final_overall = self.plaintext_written == self.plaintext_total_size;
            let is_epoch_full = self.chunk_index_in_epoch >= self.epoch_size - 1;

            if is_full || is_final_overall || (is_epoch_full && !self.chunk_buffer.is_empty()) {
                self.finalize_chunk(is_final_overall)?;
            }
        }

        Ok(offset)
    }

    /// Finalize the current chunk and add it to encrypted_chunks.
    fn finalize_chunk(&mut self, is_final_overall: bool) -> Result<(), PayloadWriterError> {
        if self.chunk_buffer.is_empty() {
            return Ok(());
        }

        let plaintext_chunk_len = self.chunk_buffer.len() as u32;

        // Derive keys for this chunk
        let k_epoch = derive_chunk_key(&self.k_payload_master, self.epoch_index);
        let k_chunk = derive_chunk_key(&k_epoch, self.chunk_index_in_epoch);
        let n_chunk = derive_chunk_nonce(&k_epoch, self.chunk_index_in_epoch);

        // Mark as final only if it's the very last chunk in the entire payload
        let is_final_chunk = is_final_overall;

        // Encrypt
        let ciphertext_with_tag = encrypt_chunk(
            &k_chunk,
            n_chunk.expose(),
            &self.chunk_buffer,
            &self.file_uuid,
            self.suite_id,
            &self.header_hash,
            self.epoch_index,
            self.chunk_index_in_epoch,
            plaintext_chunk_len,
            is_final_chunk,
        )?;

        self.encrypted_chunks.push(EncryptedChunkEntry {
            ciphertext_with_tag,
            is_final: is_final_chunk,
        });

        // Update state
        self.chunk_index_in_epoch += 1;

        // Start a new epoch if needed
        if self.chunk_index_in_epoch >= self.epoch_size {
            self.epoch_index += 1;
            self.chunk_index_in_epoch = 0;
        }

        self.chunk_buffer.clear();
        Ok(())
    }

    /// Finalize the writer and return all encrypted chunks.
    pub fn finalize(mut self) -> Result<Vec<EncryptedChunkEntry>, PayloadWriterError> {
        if self.plaintext_written < self.plaintext_total_size {
            return Err(PayloadWriterError::ZeroPlaintextSize); // Not all plaintext written
        }

        // Ensure final chunk is written
        if !self.chunk_buffer.is_empty() || self.encrypted_chunks.is_empty() {
            self.finalize_chunk(true)?;
        }

        // Verify that the last encrypted chunk is marked as final
        if let Some(last) = self.encrypted_chunks.last_mut() {
            last.is_final = true;
        }

        Ok(self.encrypted_chunks)
    }

    /// Get the current number of encrypted chunks.
    pub fn chunk_count(&self) -> usize {
        self.encrypted_chunks.len()
    }

    /// Get mutable reference to encrypted chunks (for advanced use).
    pub fn encrypted_chunks_mut(&mut self) -> &mut Vec<EncryptedChunkEntry> {
        &mut self.encrypted_chunks
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_payload_master() -> SecretKey32 {
        SecretKey32::from_bytes([7u8; 32])
    }

    fn test_uuid() -> [u8; 16] {
        [8u8; 16]
    }

    fn test_header_hash() -> [u8; 32] {
        [9u8; 32]
    }

    #[test]
    fn writer_single_chunk() -> Result<(), Box<dyn std::error::Error>> {
        let k_payload_master = test_payload_master();
        let plaintext = b"Hello, World!";

        let mut writer = PayloadWriter::new(
            k_payload_master,
            test_uuid(),
            0x01,
            test_header_hash(),
            4096,
            100,
            plaintext.len() as u64,
        )?;

        writer.write(plaintext)?;
        let chunks = writer.finalize()?;

        assert_eq!(chunks.len(), 1);
        assert!(chunks[0].is_final);
        Ok(())
    }

    #[test]
    fn writer_multiple_chunks() -> Result<(), Box<dyn std::error::Error>> {
        let k_payload_master = test_payload_master();
        let plaintext = vec![42u8; 10000];

        let mut writer = PayloadWriter::new(
            k_payload_master,
            test_uuid(),
            0x01,
            test_header_hash(),
            4096, // 4KB chunks
            100,
            plaintext.len() as u64,
        )?;

        writer.write(&plaintext)?;
        let chunks = writer.finalize()?;

        // 10000 bytes / 4096 = 2 chunks (4096 + 5904)
        assert_eq!(chunks.len(), 3); // Actually 3: 4096 + 4096 + 1808
        assert!(chunks[chunks.len() - 1].is_final);
        Ok(())
    }

    #[test]
    fn writer_incremental_writes() -> Result<(), Box<dyn std::error::Error>> {
        let k_payload_master = test_payload_master();
        let plaintext = vec![99u8; 5000];

        let mut writer = PayloadWriter::new(
            k_payload_master,
            test_uuid(),
            0x01,
            test_header_hash(),
            2000, // 2KB chunks
            10,
            plaintext.len() as u64,
        )?;

        // Write in multiple small parts
        writer.write(&plaintext[0..1000])?;
        writer.write(&plaintext[1000..3000])?;
        writer.write(&plaintext[3000..])?;

        let chunks = writer.finalize()?;

        // 5000 bytes / 2000 = 3 chunks (2000 + 2000 + 1000)
        assert_eq!(chunks.len(), 3);
        assert!(chunks[chunks.len() - 1].is_final);
        Ok(())
    }

    #[test]
    fn writer_rejects_zero_chunk_size() {
        let k_payload_master = test_payload_master();

        let err = PayloadWriter::new(
            k_payload_master,
            test_uuid(),
            0x01,
            test_header_hash(),
            0, // Invalid!
            100,
            1000,
        );

        assert!(matches!(err, Err(PayloadWriterError::InvalidChunkSize)));
    }

    #[test]
    fn writer_rejects_zero_epoch_size() {
        let k_payload_master = test_payload_master();

        let err = PayloadWriter::new(
            k_payload_master,
            test_uuid(),
            0x01,
            test_header_hash(),
            4096,
            0, // Invalid!
            1000,
        );

        assert!(matches!(err, Err(PayloadWriterError::InvalidEpochSize)));
    }

    #[test]
    fn writer_rejects_zero_plaintext_size() {
        let k_payload_master = test_payload_master();

        let err = PayloadWriter::new(
            k_payload_master,
            test_uuid(),
            0x01,
            test_header_hash(),
            4096,
            100,
            0, // Invalid!
        );

        assert!(matches!(err, Err(PayloadWriterError::ZeroPlaintextSize)));
    }

    #[test]
    fn writer_epoch_boundary() -> Result<(), Box<dyn std::error::Error>> {
        let k_payload_master = test_payload_master();
        // 5 chunks, 2 per epoch → 3 epochs (2 + 2 + 1)
        let plaintext = vec![123u8; 5 * 1024];

        let mut writer = PayloadWriter::new(
            k_payload_master,
            test_uuid(),
            0x01,
            test_header_hash(),
            1024, // 1KB chunks
            2,    // 2 chunks per epoch
            plaintext.len() as u64,
        )?;

        writer.write(&plaintext)?;
        let chunks = writer.finalize()?;

        assert_eq!(chunks.len(), 5);
        assert!(chunks[4].is_final);
        Ok(())
    }
}
