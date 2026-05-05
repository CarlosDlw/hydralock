/// Section type identifiers used in AAD construction.
///
/// Each constant uniquely identifies a section plane. Using different values
/// across planes prevents cross-section splicing attacks.
pub const SECTION_TYPE_WRAP: u8 = 0x03;
pub const SECTION_TYPE_METADATA: u8 = 0x04;
pub const SECTION_TYPE_PAYLOAD_CHUNK: u8 = 0x05;
pub const SECTION_TYPE_FOOTER: u8 = 0x06;

/// Container magic bytes — identical to the wire format magic.
pub const MAGIC: &[u8; 4] = b"HLK1";

// ── Chunk AAD ────────────────────────────────────────────────────────────────
//
// Layout (39 bytes, all big-endian):
//   Offset  Size  Field
//   0       4     magic ("HLK1")
//   4       2     format_version_major
//   6       2     format_version_minor
//   8       2     suite_id
//   10      16    file_uuid
//   26      4     epoch_index
//   30      4     chunk_index
//   34      4     plaintext_chunk_len
//   38      1     final_chunk_flag (0x01 = final, 0x00 = not final)

pub const CHUNK_AAD_LEN: usize = 39;

/// Input parameters for constructing the per-chunk AAD.
pub struct ChunkAadInput {
    pub suite_id: u16,
    pub format_version_major: u16,
    pub format_version_minor: u16,
    pub file_uuid: [u8; 16],
    pub epoch_index: u32,
    pub chunk_index: u32,
    pub plaintext_chunk_len: u32,
    pub is_final: bool,
}

impl ChunkAadInput {
    /// Encode the chunk AAD into its canonical 39-byte representation.
    pub fn encode(&self) -> [u8; CHUNK_AAD_LEN] {
        let mut out = [0u8; CHUNK_AAD_LEN];
        out[0..4].copy_from_slice(MAGIC);
        out[4..6].copy_from_slice(&self.format_version_major.to_be_bytes());
        out[6..8].copy_from_slice(&self.format_version_minor.to_be_bytes());
        out[8..10].copy_from_slice(&self.suite_id.to_be_bytes());
        out[10..26].copy_from_slice(&self.file_uuid);
        out[26..30].copy_from_slice(&self.epoch_index.to_be_bytes());
        out[30..34].copy_from_slice(&self.chunk_index.to_be_bytes());
        out[34..38].copy_from_slice(&self.plaintext_chunk_len.to_be_bytes());
        out[38] = self.is_final as u8;
        out
    }
}

// ── Metadata AAD ─────────────────────────────────────────────────────────────
//
// Layout (51 bytes, all big-endian):
//   Offset  Size  Field
//   0       2     suite_id
//   2       1     section_type (SECTION_TYPE_METADATA = 0x04)
//   3       16    file_uuid
//   19      32    header_hash (BLAKE3 hash of the fixed header bytes)

pub const METADATA_AAD_LEN: usize = 51;

/// Input parameters for constructing the metadata section AAD.
pub struct MetadataAadInput {
    pub suite_id: u16,
    pub file_uuid: [u8; 16],
    pub header_hash: [u8; 32],
}

impl MetadataAadInput {
    /// Encode the metadata AAD into its canonical 51-byte representation.
    pub fn encode(&self) -> [u8; METADATA_AAD_LEN] {
        let mut out = [0u8; METADATA_AAD_LEN];
        out[0..2].copy_from_slice(&self.suite_id.to_be_bytes());
        out[2] = SECTION_TYPE_METADATA;
        out[3..19].copy_from_slice(&self.file_uuid);
        out[19..51].copy_from_slice(&self.header_hash);
        out
    }
}

// ── Wrapper AAD ───────────────────────────────────────────────────────────────
//
// Layout (53 bytes, all big-endian):
//   Offset  Size  Field
//   0       2     suite_id
//   2       1     section_type (SECTION_TYPE_WRAP = 0x03)
//   3       2     wrapper_index
//   5       16    file_uuid
//   21      32    header_hash (BLAKE3 hash of the fixed header bytes)

pub const WRAPPER_AAD_LEN: usize = 53;

/// Input parameters for constructing the per-wrapper AAD.
pub struct WrapperAadInput {
    pub suite_id: u16,
    pub wrapper_index: u16,
    pub file_uuid: [u8; 16],
    pub header_hash: [u8; 32],
}

impl WrapperAadInput {
    /// Encode the wrapper AAD into its canonical 53-byte representation.
    pub fn encode(&self) -> [u8; WRAPPER_AAD_LEN] {
        let mut out = [0u8; WRAPPER_AAD_LEN];
        out[0..2].copy_from_slice(&self.suite_id.to_be_bytes());
        out[2] = SECTION_TYPE_WRAP;
        out[3..5].copy_from_slice(&self.wrapper_index.to_be_bytes());
        out[5..21].copy_from_slice(&self.file_uuid);
        out[21..53].copy_from_slice(&self.header_hash);
        out
    }
}

// ── Footer AAD ────────────────────────────────────────────────────────────────
//
// Layout (51 bytes, all big-endian):
//   Offset  Size  Field
//   0       2     suite_id
//   2       1     section_type (SECTION_TYPE_FOOTER = 0x06)
//   3       16    file_uuid
//   19      32    header_hash (BLAKE3 hash of the fixed header bytes)

pub const FOOTER_AAD_LEN: usize = 51;

/// Input parameters for constructing the footer section AAD.
pub struct FooterAadInput {
    pub suite_id: u16,
    pub file_uuid: [u8; 16],
    pub header_hash: [u8; 32],
}

impl FooterAadInput {
    /// Encode the footer AAD into its canonical 51-byte representation.
    pub fn encode(&self) -> [u8; FOOTER_AAD_LEN] {
        let mut out = [0u8; FOOTER_AAD_LEN];
        out[0..2].copy_from_slice(&self.suite_id.to_be_bytes());
        out[2] = SECTION_TYPE_FOOTER;
        out[3..19].copy_from_slice(&self.file_uuid);
        out[19..51].copy_from_slice(&self.header_hash);
        out
    }
}

// ── Header hash helper ────────────────────────────────────────────────────────

/// Compute the BLAKE3 hash of the fixed header bytes.
///
/// Used as the `header_hash` field in metadata, wrapper, and footer AADs to
/// bind all AEAD-protected sections to the unencrypted container header.
pub fn hash_header(header_bytes: &[u8]) -> [u8; 32] {
    *blake3::hash(header_bytes).as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_uuid() -> [u8; 16] {
        [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10,
        ]
    }

    fn test_hash() -> [u8; 32] {
        [0xAAu8; 32]
    }

    #[test]
    fn chunk_aad_is_deterministic() {
        let input = ChunkAadInput {
            suite_id: 1,
            format_version_major: 1,
            format_version_minor: 0,
            file_uuid: test_uuid(),
            epoch_index: 0,
            chunk_index: 0,
            plaintext_chunk_len: 65536,
            is_final: false,
        };
        let a = input.encode();
        let b = input.encode();
        assert_eq!(a, b);
    }

    #[test]
    fn chunk_aad_magic_is_correct() {
        let input = ChunkAadInput {
            suite_id: 1,
            format_version_major: 1,
            format_version_minor: 0,
            file_uuid: test_uuid(),
            epoch_index: 0,
            chunk_index: 0,
            plaintext_chunk_len: 1024,
            is_final: false,
        };
        let aad = input.encode();
        assert_eq!(&aad[0..4], b"HLK1");
    }

    #[test]
    fn chunk_aad_final_flag_differs() {
        let base = ChunkAadInput {
            suite_id: 1,
            format_version_major: 1,
            format_version_minor: 0,
            file_uuid: test_uuid(),
            epoch_index: 0,
            chunk_index: 5,
            plaintext_chunk_len: 1000,
            is_final: false,
        };
        let final_input = ChunkAadInput {
            is_final: true,
            ..base
        };
        let aad_nonfinal = base.encode();
        let aad_final = final_input.encode();
        assert_ne!(aad_nonfinal, aad_final);
        assert_eq!(aad_nonfinal[38], 0x00);
        assert_eq!(aad_final[38], 0x01);
    }

    #[test]
    fn chunk_aad_epoch_and_chunk_index_affect_output() {
        let base = ChunkAadInput {
            suite_id: 1,
            format_version_major: 1,
            format_version_minor: 0,
            file_uuid: test_uuid(),
            epoch_index: 0,
            chunk_index: 0,
            plaintext_chunk_len: 65536,
            is_final: false,
        };
        let diff_epoch = ChunkAadInput {
            epoch_index: 1,
            ..base
        };
        let diff_chunk = ChunkAadInput {
            chunk_index: 1,
            ..base
        };
        assert_ne!(base.encode(), diff_epoch.encode());
        assert_ne!(base.encode(), diff_chunk.encode());
        assert_ne!(diff_epoch.encode(), diff_chunk.encode());
    }

    #[test]
    fn metadata_aad_contains_section_type() {
        let input = MetadataAadInput {
            suite_id: 1,
            file_uuid: test_uuid(),
            header_hash: test_hash(),
        };
        let aad = input.encode();
        assert_eq!(aad.len(), METADATA_AAD_LEN);
        assert_eq!(aad[2], SECTION_TYPE_METADATA);
    }

    #[test]
    fn wrapper_aad_index_affects_output() {
        let base = WrapperAadInput {
            suite_id: 1,
            wrapper_index: 0,
            file_uuid: test_uuid(),
            header_hash: test_hash(),
        };
        let other = WrapperAadInput {
            wrapper_index: 1,
            ..base
        };
        assert_ne!(base.encode(), other.encode());
        assert_eq!(base.encode()[2], SECTION_TYPE_WRAP);
    }

    #[test]
    fn footer_aad_contains_section_type() {
        let input = FooterAadInput {
            suite_id: 1,
            file_uuid: test_uuid(),
            header_hash: test_hash(),
        };
        let aad = input.encode();
        assert_eq!(aad.len(), FOOTER_AAD_LEN);
        assert_eq!(aad[2], SECTION_TYPE_FOOTER);
    }

    #[test]
    fn aad_section_types_are_distinct() {
        assert_ne!(SECTION_TYPE_WRAP, SECTION_TYPE_METADATA);
        assert_ne!(SECTION_TYPE_WRAP, SECTION_TYPE_PAYLOAD_CHUNK);
        assert_ne!(SECTION_TYPE_WRAP, SECTION_TYPE_FOOTER);
        assert_ne!(SECTION_TYPE_METADATA, SECTION_TYPE_PAYLOAD_CHUNK);
        assert_ne!(SECTION_TYPE_METADATA, SECTION_TYPE_FOOTER);
        assert_ne!(SECTION_TYPE_PAYLOAD_CHUNK, SECTION_TYPE_FOOTER);
    }

    #[test]
    fn metadata_and_footer_aad_differ_by_section_type() {
        let meta = MetadataAadInput {
            suite_id: 1,
            file_uuid: test_uuid(),
            header_hash: test_hash(),
        };
        let footer = FooterAadInput {
            suite_id: 1,
            file_uuid: test_uuid(),
            header_hash: test_hash(),
        };
        assert_ne!(meta.encode().as_slice(), footer.encode().as_slice());
    }

    #[test]
    fn hash_header_is_deterministic() {
        let bytes = [0x01u8; 70];
        let h1 = hash_header(&bytes);
        let h2 = hash_header(&bytes);
        assert_eq!(h1, h2);
    }

    #[test]
    fn hash_header_differs_for_different_inputs() {
        let a = [0x00u8; 70];
        let b = [0xFFu8; 70];
        assert_ne!(hash_header(&a), hash_header(&b));
    }
}
