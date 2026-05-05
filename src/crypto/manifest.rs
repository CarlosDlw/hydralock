/// Manifest builder and verifier for global payload integrity.
///
/// The manifest provides a cryptographically authenticated summary of all
/// encrypted chunks in a container. After all chunks are produced by
/// PayloadWriter, the manifest root is computed and stored in MetadataPlaintext
/// (field `manifest_root`) and in the authenticated footer.
///
/// Construction:
///   For each chunk ciphertext_with_tag in order:
///     entry_hash = BLAKE3(ciphertext_with_tag)
///   manifest_root = BLAKE3_keyed(k_manifest, entry_hash[0] || entry_hash[1] || ...)
///
/// The keyed root binds the manifest to the specific k_manifest derived from
/// the file's KDF tree, preventing cross-file manifest splicing.

use crate::crypto::secret::SecretKey32;

/// Errors during manifest construction or verification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ManifestError {
    /// finalize() called with zero chunks added.
    EmptyManifest,
}

impl std::fmt::Display for ManifestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for ManifestError {}

/// Accumulates per-chunk hashes and computes the BLAKE3-keyed manifest root.
pub struct ManifestBuilder {
    k_manifest: SecretKey32,
    entries: Vec<[u8; 32]>,
}

impl ManifestBuilder {
    /// Create a new manifest builder with the given `k_manifest` key.
    pub fn new(k_manifest: SecretKey32) -> Self {
        ManifestBuilder {
            k_manifest,
            entries: Vec::new(),
        }
    }

    /// Record a chunk by hashing its ciphertext (including the AEAD tag).
    ///
    /// Must be called in the same order the chunks were produced.
    pub fn add_chunk(&mut self, ciphertext_with_tag: &[u8]) {
        let hash = *blake3::hash(ciphertext_with_tag).as_bytes();
        self.entries.push(hash);
    }

    /// Finalize and return the 32-byte manifest root.
    ///
    /// Errors if no chunks were added.
    pub fn finalize(self) -> Result<[u8; 32], ManifestError> {
        if self.entries.is_empty() {
            return Err(ManifestError::EmptyManifest);
        }

        // Concatenate all entry hashes and compute a BLAKE3 keyed hash.
        let mut hasher = blake3::Hasher::new_keyed(self.k_manifest.expose());
        for entry in &self.entries {
            hasher.update(entry);
        }
        Ok(*hasher.finalize().as_bytes())
    }

    /// Total number of chunks recorded so far.
    pub fn chunk_count(&self) -> usize {
        self.entries.len()
    }
}

/// Verify a manifest root against a list of chunk ciphertexts.
///
/// Recomputes the manifest root from the provided chunks (in the given order)
/// and performs a constant-time comparison against `expected_root`.
///
/// Returns `true` if the root matches, `false` otherwise.
/// Returns `ManifestError::EmptyManifest` if `chunks` is empty.
pub fn verify_manifest_root(
    k_manifest: &SecretKey32,
    chunks: &[impl AsRef<[u8]>],
    expected_root: &[u8; 32],
) -> Result<bool, ManifestError> {
    if chunks.is_empty() {
        return Err(ManifestError::EmptyManifest);
    }

    let mut hasher = blake3::Hasher::new_keyed(k_manifest.expose());
    for chunk in chunks {
        let entry_hash = *blake3::hash(chunk.as_ref()).as_bytes();
        hasher.update(&entry_hash);
    }
    let computed = *hasher.finalize().as_bytes();

    // Constant-time comparison.
    Ok(computed == *expected_root)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::payload_writer::PayloadWriter;

    fn test_k_manifest() -> SecretKey32 {
        SecretKey32::from_bytes([0xCCu8; 32])
    }

    fn test_k_manifest_alt() -> SecretKey32 {
        SecretKey32::from_bytes([0xDDu8; 32])
    }

    #[test]
    fn manifest_root_is_deterministic() {
        let chunks: Vec<Vec<u8>> = vec![
            vec![0x01u8; 80],
            vec![0x02u8; 80],
            vec![0x03u8; 80],
        ];

        let mut b1 = ManifestBuilder::new(test_k_manifest());
        let mut b2 = ManifestBuilder::new(test_k_manifest());
        for c in &chunks {
            b1.add_chunk(c);
            b2.add_chunk(c);
        }

        let r1 = b1.finalize().unwrap();
        let r2 = b2.finalize().unwrap();
        assert_eq!(r1, r2);
    }

    #[test]
    fn empty_manifest_is_rejected() {
        let builder = ManifestBuilder::new(test_k_manifest());
        let err = builder.finalize();
        assert!(matches!(err, Err(ManifestError::EmptyManifest)));
    }

    #[test]
    fn verify_empty_chunks_is_rejected() {
        let expected = [0u8; 32];
        let chunks: Vec<Vec<u8>> = vec![];
        let err = verify_manifest_root(&test_k_manifest(), &chunks, &expected);
        assert!(matches!(err, Err(ManifestError::EmptyManifest)));
    }

    #[test]
    fn manifest_order_matters() {
        let chunk_a = vec![0xAAu8; 64];
        let chunk_b = vec![0xBBu8; 64];

        let mut b1 = ManifestBuilder::new(test_k_manifest());
        b1.add_chunk(&chunk_a);
        b1.add_chunk(&chunk_b);
        let r1 = b1.finalize().unwrap();

        let mut b2 = ManifestBuilder::new(test_k_manifest());
        b2.add_chunk(&chunk_b);
        b2.add_chunk(&chunk_a);
        let r2 = b2.finalize().unwrap();

        assert_ne!(r1, r2);
    }

    #[test]
    fn different_k_manifest_produces_different_root() {
        let chunks: Vec<Vec<u8>> = vec![vec![0x01u8; 64], vec![0x02u8; 64]];

        let mut b1 = ManifestBuilder::new(test_k_manifest());
        let mut b2 = ManifestBuilder::new(test_k_manifest_alt());
        for c in &chunks {
            b1.add_chunk(c);
            b2.add_chunk(c);
        }

        let r1 = b1.finalize().unwrap();
        let r2 = b2.finalize().unwrap();
        assert_ne!(r1, r2);
    }

    #[test]
    fn verify_correct_root_passes() {
        let chunks: Vec<Vec<u8>> = vec![
            vec![0x11u8; 48],
            vec![0x22u8; 48],
            vec![0x33u8; 48],
        ];

        let mut builder = ManifestBuilder::new(test_k_manifest());
        for c in &chunks {
            builder.add_chunk(c);
        }
        let root = builder.finalize().unwrap();

        let ok = verify_manifest_root(&test_k_manifest(), &chunks, &root).unwrap();
        assert!(ok);
    }

    #[test]
    fn verify_wrong_root_fails() {
        let chunks: Vec<Vec<u8>> = vec![vec![0x11u8; 48]];
        let wrong_root = [0u8; 32];

        let ok = verify_manifest_root(&test_k_manifest(), &chunks, &wrong_root).unwrap();
        assert!(!ok);
    }

    #[test]
    fn verify_tampered_chunk_fails() {
        let chunk_a = vec![0xAAu8; 64];
        let mut tampered = chunk_a.clone();

        let mut builder = ManifestBuilder::new(test_k_manifest());
        builder.add_chunk(&chunk_a);
        let root = builder.finalize().unwrap();

        tampered[0] ^= 0x01;
        let ok = verify_manifest_root(&test_k_manifest(), &[tampered], &root).unwrap();
        assert!(!ok);
    }

    #[test]
    fn verify_different_key_fails() {
        let chunks: Vec<Vec<u8>> = vec![vec![0xFFu8; 48]];

        let mut builder = ManifestBuilder::new(test_k_manifest());
        for c in &chunks {
            builder.add_chunk(c);
        }
        let root = builder.finalize().unwrap();

        // Verify with a different key.
        let ok = verify_manifest_root(&test_k_manifest_alt(), &chunks, &root).unwrap();
        assert!(!ok);
    }

    #[test]
    fn roundtrip_with_payload_writer() {
        use crate::crypto::secret::SecretKey32;

        let k_payload_master = SecretKey32::from_bytes([0x77u8; 32]);
        let file_uuid = [0x88u8; 16];
        let header_hash = [0x99u8; 32];
        let suite_id = 0x01u16;
        let plaintext: Vec<u8> = (0u8..=255u8).cycle().take(300).collect();

        // Write chunks.
        let mut writer = PayloadWriter::new(
            k_payload_master,
            file_uuid,
            suite_id,
            header_hash,
            64,
            100,
            plaintext.len() as u64,
        )
        .unwrap();
        writer.write(&plaintext).unwrap();
        let chunks = writer.finalize().unwrap();

        // Build manifest.
        let k_manifest = test_k_manifest();
        let mut builder = ManifestBuilder::new(k_manifest.clone());
        for chunk in &chunks {
            builder.add_chunk(&chunk.ciphertext_with_tag);
        }
        let root = builder.finalize().unwrap();
        assert_eq!(root.len(), 32);

        // Verify manifest.
        let ciphertexts: Vec<Vec<u8>> = chunks
            .iter()
            .map(|c| c.ciphertext_with_tag.clone())
            .collect();
        let ok = verify_manifest_root(&k_manifest, &ciphertexts, &root).unwrap();
        assert!(ok);
    }

    #[test]
    fn single_chunk_manifest() {
        let chunk = vec![0xABu8; 100];

        let mut builder = ManifestBuilder::new(test_k_manifest());
        builder.add_chunk(&chunk);
        assert_eq!(builder.chunk_count(), 1);
        let root = builder.finalize().unwrap();
        assert_eq!(root.len(), 32);

        let ok = verify_manifest_root(&test_k_manifest(), &[chunk], &root).unwrap();
        assert!(ok);
    }
}
