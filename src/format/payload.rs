use core::fmt;

pub const PAYLOAD_HEADER_LEN: usize = 16;
pub const CHUNK_ENTRY_HEADER_LEN: usize = 8;

pub const CHUNK_FLAG_FINAL: u16 = 0x0001;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PayloadSection {
    pub payload_version: u16,
    pub flags: u16,
    pub chunk_size: u32,
    pub tag_size: u32,
    pub chunks: Vec<ChunkEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChunkEntry {
    pub flags: u16,
    pub ciphertext: Vec<u8>,
    pub tag: Vec<u8>,
}

impl ChunkEntry {
    pub fn is_final(&self) -> bool {
        self.flags & CHUNK_FLAG_FINAL != 0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PayloadSectionError {
    InvalidLength {
        min: usize,
        actual: usize,
    },
    UnsupportedPayloadVersion {
        expected: u16,
        actual: u16,
    },
    NonZeroReserved,
    ZeroChunkSize,
    ZeroTagSize,
    TruncatedChunkHeader {
        index: usize,
    },
    TruncatedCiphertext {
        index: usize,
        declared: usize,
        actual: usize,
    },
    TruncatedTag {
        index: usize,
        declared: usize,
        actual: usize,
    },
    ZeroCiphertextLen {
        index: usize,
    },
    ChunkSizeViolation {
        index: usize,
        expected: u32,
        actual: usize,
    },
    NoFinalChunk,
    FinalNotLast {
        index: usize,
        total: usize,
    },
    TrailingBytes,
    LengthOverflow,
}

impl fmt::Display for PayloadSectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength { min, actual } => {
                write!(
                    f,
                    "invalid payload section length: expected at least {min}, got {actual}"
                )
            }
            Self::UnsupportedPayloadVersion { expected, actual } => {
                write!(
                    f,
                    "unsupported payload version: expected {expected}, got {actual}"
                )
            }
            Self::NonZeroReserved => write!(f, "reserved bytes must be zero"),
            Self::ZeroChunkSize => write!(f, "chunk_size must be greater than zero"),
            Self::ZeroTagSize => write!(f, "tag_size must be greater than zero"),
            Self::TruncatedChunkHeader { index } => {
                write!(f, "truncated chunk entry header at index {index}")
            }
            Self::TruncatedCiphertext {
                index,
                declared,
                actual,
            } => write!(
                f,
                "truncated ciphertext at chunk {index}: declared {declared}, available {actual}"
            ),
            Self::TruncatedTag {
                index,
                declared,
                actual,
            } => write!(
                f,
                "truncated tag at chunk {index}: declared {declared}, available {actual}"
            ),
            Self::ZeroCiphertextLen { index } => {
                write!(f, "ciphertext_len must not be zero at chunk index {index}")
            }
            Self::ChunkSizeViolation {
                index,
                expected,
                actual,
            } => write!(
                f,
                "non-final chunk {index} has ciphertext_len {actual}, expected {expected}"
            ),
            Self::NoFinalChunk => write!(f, "no chunk is marked as final"),
            Self::FinalNotLast { index, total } => write!(
                f,
                "final chunk is at index {index} but total chunk count is {total}"
            ),
            Self::TrailingBytes => write!(f, "trailing bytes after last declared chunk"),
            Self::LengthOverflow => {
                write!(f, "length overflow while processing payload section")
            }
        }
    }
}

impl std::error::Error for PayloadSectionError {}

impl PayloadSection {
    pub fn parse(bytes: &[u8]) -> Result<Self, PayloadSectionError> {
        if bytes.len() < PAYLOAD_HEADER_LEN {
            return Err(PayloadSectionError::InvalidLength {
                min: PAYLOAD_HEADER_LEN,
                actual: bytes.len(),
            });
        }

        let payload_version = u16::from_be_bytes([bytes[0], bytes[1]]);
        if payload_version != 1 {
            return Err(PayloadSectionError::UnsupportedPayloadVersion {
                expected: 1,
                actual: payload_version,
            });
        }

        let flags = u16::from_be_bytes([bytes[2], bytes[3]]);
        let chunk_size = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        let tag_size = u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
        let reserved = [bytes[12], bytes[13], bytes[14], bytes[15]];

        if reserved != [0, 0, 0, 0] {
            return Err(PayloadSectionError::NonZeroReserved);
        }

        if chunk_size == 0 {
            return Err(PayloadSectionError::ZeroChunkSize);
        }

        if tag_size == 0 {
            return Err(PayloadSectionError::ZeroTagSize);
        }

        let tag_size_usize = tag_size as usize;
        let mut offset = PAYLOAD_HEADER_LEN;
        let mut chunks: Vec<ChunkEntry> = Vec::new();

        while offset < bytes.len() {
            let index = chunks.len();

            let chunk_hdr_end = offset
                .checked_add(CHUNK_ENTRY_HEADER_LEN)
                .ok_or(PayloadSectionError::LengthOverflow)?;

            if chunk_hdr_end > bytes.len() {
                return Err(PayloadSectionError::TruncatedChunkHeader { index });
            }

            let ciphertext_len = u32::from_be_bytes([
                bytes[offset],
                bytes[offset + 1],
                bytes[offset + 2],
                bytes[offset + 3],
            ]) as usize;
            let chunk_flags = u16::from_be_bytes([bytes[offset + 4], bytes[offset + 5]]);
            let chunk_reserved = [bytes[offset + 6], bytes[offset + 7]];
            offset = chunk_hdr_end;

            if chunk_reserved != [0, 0] {
                return Err(PayloadSectionError::NonZeroReserved);
            }

            if ciphertext_len == 0 {
                return Err(PayloadSectionError::ZeroCiphertextLen { index });
            }

            let is_final = chunk_flags & CHUNK_FLAG_FINAL != 0;

            // Non-final chunks must have exactly chunk_size bytes of ciphertext.
            if !is_final && ciphertext_len != chunk_size as usize {
                return Err(PayloadSectionError::ChunkSizeViolation {
                    index,
                    expected: chunk_size,
                    actual: ciphertext_len,
                });
            }

            let ciphertext_end = offset
                .checked_add(ciphertext_len)
                .ok_or(PayloadSectionError::LengthOverflow)?;

            if ciphertext_end > bytes.len() {
                return Err(PayloadSectionError::TruncatedCiphertext {
                    index,
                    declared: ciphertext_len,
                    actual: bytes.len() - offset,
                });
            }

            let ciphertext = bytes[offset..ciphertext_end].to_vec();
            offset = ciphertext_end;

            let tag_end = offset
                .checked_add(tag_size_usize)
                .ok_or(PayloadSectionError::LengthOverflow)?;

            if tag_end > bytes.len() {
                return Err(PayloadSectionError::TruncatedTag {
                    index,
                    declared: tag_size_usize,
                    actual: bytes.len() - offset,
                });
            }

            let tag = bytes[offset..tag_end].to_vec();
            offset = tag_end;

            chunks.push(ChunkEntry {
                flags: chunk_flags,
                ciphertext,
                tag,
            });
        }

        if offset != bytes.len() {
            return Err(PayloadSectionError::TrailingBytes);
        }

        // Exactly one chunk must be marked final, and it must be the last one.
        let final_index = chunks.iter().position(|c| c.is_final());
        let total = chunks.len();

        match final_index {
            None => return Err(PayloadSectionError::NoFinalChunk),
            Some(idx) if idx != total - 1 => {
                return Err(PayloadSectionError::FinalNotLast { index: idx, total });
            }
            _ => {}
        }

        Ok(Self {
            payload_version,
            flags,
            chunk_size,
            tag_size,
            chunks,
        })
    }

    pub fn encode(&self) -> Result<Vec<u8>, PayloadSectionError> {
        if self.payload_version != 1 {
            return Err(PayloadSectionError::UnsupportedPayloadVersion {
                expected: 1,
                actual: self.payload_version,
            });
        }

        if self.chunk_size == 0 {
            return Err(PayloadSectionError::ZeroChunkSize);
        }

        if self.tag_size == 0 {
            return Err(PayloadSectionError::ZeroTagSize);
        }

        let tag_size_usize = self.tag_size as usize;
        let final_index = self.chunks.iter().position(|c| c.is_final());
        let total = self.chunks.len();

        match final_index {
            None => return Err(PayloadSectionError::NoFinalChunk),
            Some(idx) if idx != total - 1 => {
                return Err(PayloadSectionError::FinalNotLast { index: idx, total });
            }
            _ => {}
        }

        let mut out = Vec::new();
        out.extend_from_slice(&self.payload_version.to_be_bytes());
        out.extend_from_slice(&self.flags.to_be_bytes());
        out.extend_from_slice(&self.chunk_size.to_be_bytes());
        out.extend_from_slice(&self.tag_size.to_be_bytes());
        out.extend_from_slice(&[0u8; 4]);

        for (index, chunk) in self.chunks.iter().enumerate() {
            if chunk.ciphertext.is_empty() {
                return Err(PayloadSectionError::ZeroCiphertextLen { index });
            }

            if chunk.tag.len() != tag_size_usize {
                return Err(PayloadSectionError::TruncatedTag {
                    index,
                    declared: tag_size_usize,
                    actual: chunk.tag.len(),
                });
            }

            if !chunk.is_final() && chunk.ciphertext.len() != self.chunk_size as usize {
                return Err(PayloadSectionError::ChunkSizeViolation {
                    index,
                    expected: self.chunk_size,
                    actual: chunk.ciphertext.len(),
                });
            }

            let ciphertext_len = u32::try_from(chunk.ciphertext.len())
                .map_err(|_| PayloadSectionError::LengthOverflow)?;

            out.extend_from_slice(&ciphertext_len.to_be_bytes());
            out.extend_from_slice(&chunk.flags.to_be_bytes());
            out.extend_from_slice(&[0u8; 2]);
            out.extend_from_slice(&chunk.ciphertext);
            out.extend_from_slice(&chunk.tag);
        }

        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::{CHUNK_FLAG_FINAL, ChunkEntry, PayloadSection, PayloadSectionError};

    fn sample_payload() -> PayloadSection {
        PayloadSection {
            payload_version: 1,
            flags: 0,
            chunk_size: 4,
            tag_size: 4,
            chunks: vec![ChunkEntry {
                flags: CHUNK_FLAG_FINAL,
                ciphertext: vec![0xDE, 0xAD, 0xBE, 0xEF],
                tag: vec![0x01, 0x02, 0x03, 0x04],
            }],
        }
    }

    #[test]
    fn payload_roundtrip_is_stable() {
        let payload = sample_payload();
        let encoded = payload.encode().expect("payload should encode");
        let decoded = PayloadSection::parse(&encoded).expect("payload should parse");
        assert_eq!(decoded, payload);
    }

    #[test]
    fn rejects_unsupported_payload_version() {
        let mut encoded = sample_payload().encode().expect("payload should encode");
        encoded[1] = 2;
        let error = PayloadSection::parse(&encoded).expect_err("version must be validated");
        assert_eq!(
            error,
            PayloadSectionError::UnsupportedPayloadVersion {
                expected: 1,
                actual: 2,
            }
        );
    }

    #[test]
    fn rejects_non_zero_reserved() {
        let mut encoded = sample_payload().encode().expect("payload should encode");
        encoded[12] = 1;
        let error = PayloadSection::parse(&encoded).expect_err("reserved must be zero");
        assert_eq!(error, PayloadSectionError::NonZeroReserved);
    }

    #[test]
    fn rejects_zero_chunk_size() {
        let encoded = vec![
            0x00, 0x01, // payload_version = 1
            0x00, 0x00, // flags
            0x00, 0x00, 0x00, 0x00, // chunk_size = 0 (invalid)
            0x00, 0x00, 0x00, 0x10, // tag_size = 16
            0x00, 0x00, 0x00, 0x00, // reserved
        ];
        let error = PayloadSection::parse(&encoded).expect_err("zero chunk_size must fail");
        assert_eq!(error, PayloadSectionError::ZeroChunkSize);
    }

    #[test]
    fn rejects_no_final_chunk() {
        let payload = PayloadSection {
            payload_version: 1,
            flags: 0,
            chunk_size: 4,
            tag_size: 4,
            chunks: vec![ChunkEntry {
                flags: 0, // not final
                ciphertext: vec![0xDE, 0xAD, 0xBE, 0xEF],
                tag: vec![0x01, 0x02, 0x03, 0x04],
            }],
        };
        let error = payload
            .encode()
            .expect_err("missing final chunk must fail on encode");
        assert_eq!(error, PayloadSectionError::NoFinalChunk);
    }

    #[test]
    fn rejects_non_final_chunk_size_mismatch() {
        // Two chunks: first is non-final but has ciphertext_len != chunk_size.
        // Encode directly to bypass encode() checks.
        let mut bytes = vec![
            0x00, 0x01, // payload_version
            0x00, 0x00, // flags
            0x00, 0x00, 0x00, 0x04, // chunk_size = 4
            0x00, 0x00, 0x00, 0x04, // tag_size = 4
            0x00, 0x00, 0x00, 0x00, // reserved
        ];
        // Non-final chunk with only 3 bytes ciphertext (should be 4)
        bytes.extend_from_slice(&[0x00, 0x00, 0x00, 0x03]); // ciphertext_len = 3
        bytes.extend_from_slice(&[0x00, 0x00]); // flags = 0 (not final)
        bytes.extend_from_slice(&[0x00, 0x00]); // reserved
        bytes.extend_from_slice(&[0xAA, 0xBB, 0xCC]); // ciphertext (3 bytes)
        bytes.extend_from_slice(&[0x01, 0x02, 0x03, 0x04]); // tag (4 bytes)
        // Final chunk
        bytes.extend_from_slice(&[0x00, 0x00, 0x00, 0x04]); // ciphertext_len = 4
        bytes.extend_from_slice(&[0x00, 0x01]); // flags = FINAL
        bytes.extend_from_slice(&[0x00, 0x00]); // reserved
        bytes.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]); // ciphertext
        bytes.extend_from_slice(&[0x05, 0x06, 0x07, 0x08]); // tag

        let error = PayloadSection::parse(&bytes).expect_err("size mismatch must fail");
        assert_eq!(
            error,
            PayloadSectionError::ChunkSizeViolation {
                index: 0,
                expected: 4,
                actual: 3,
            }
        );
    }
}
