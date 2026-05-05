use core::fmt;

pub const METADATA_HEADER_LEN: usize = 8;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataSection {
    pub metadata_version: u16,
    pub ciphertext: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MetadataSectionError {
    InvalidLength { min: usize, actual: usize },
    UnsupportedMetadataVersion { expected: u16, actual: u16 },
    NonZeroReserved,
    EmptyCiphertext,
    TruncatedCiphertext { declared: usize, actual: usize },
    InvalidCiphertextLength { declared: usize, actual: usize },
    LengthOverflow,
}

impl fmt::Display for MetadataSectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength { min, actual } => {
                write!(
                    f,
                    "invalid metadata section length: expected at least {min}, got {actual}"
                )
            }
            Self::UnsupportedMetadataVersion { expected, actual } => write!(
                f,
                "unsupported metadata version: expected {expected}, got {actual}"
            ),
            Self::NonZeroReserved => write!(f, "reserved bytes must be zero"),
            Self::EmptyCiphertext => write!(f, "metadata ciphertext must not be empty"),
            Self::TruncatedCiphertext { declared, actual } => write!(
                f,
                "truncated metadata ciphertext: declared {declared}, available {actual}"
            ),
            Self::InvalidCiphertextLength { declared, actual } => write!(
                f,
                "invalid metadata ciphertext length: declared {declared}, actual {actual}"
            ),
            Self::LengthOverflow => write!(f, "length overflow while processing metadata section"),
        }
    }
}

impl std::error::Error for MetadataSectionError {}

impl MetadataSection {
    pub fn parse(bytes: &[u8]) -> Result<Self, MetadataSectionError> {
        if bytes.len() < METADATA_HEADER_LEN {
            return Err(MetadataSectionError::InvalidLength {
                min: METADATA_HEADER_LEN,
                actual: bytes.len(),
            });
        }

        let metadata_version = u16::from_be_bytes([bytes[0], bytes[1]]);
        if metadata_version != 1 {
            return Err(MetadataSectionError::UnsupportedMetadataVersion {
                expected: 1,
                actual: metadata_version,
            });
        }

        let reserved = [bytes[2], bytes[3]];
        if reserved != [0, 0] {
            return Err(MetadataSectionError::NonZeroReserved);
        }

        let ciphertext_len = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]) as usize;

        if ciphertext_len == 0 {
            return Err(MetadataSectionError::EmptyCiphertext);
        }

        let expected_len = METADATA_HEADER_LEN
            .checked_add(ciphertext_len)
            .ok_or(MetadataSectionError::LengthOverflow)?;

        if bytes.len() < expected_len {
            return Err(MetadataSectionError::TruncatedCiphertext {
                declared: ciphertext_len,
                actual: bytes.len() - METADATA_HEADER_LEN,
            });
        }

        if bytes.len() != expected_len {
            return Err(MetadataSectionError::InvalidCiphertextLength {
                declared: ciphertext_len,
                actual: bytes.len() - METADATA_HEADER_LEN,
            });
        }

        Ok(Self {
            metadata_version,
            ciphertext: bytes[METADATA_HEADER_LEN..expected_len].to_vec(),
        })
    }

    pub fn encode(&self) -> Result<Vec<u8>, MetadataSectionError> {
        if self.metadata_version != 1 {
            return Err(MetadataSectionError::UnsupportedMetadataVersion {
                expected: 1,
                actual: self.metadata_version,
            });
        }

        if self.ciphertext.is_empty() {
            return Err(MetadataSectionError::EmptyCiphertext);
        }

        let ciphertext_len = u32::try_from(self.ciphertext.len())
            .map_err(|_| MetadataSectionError::LengthOverflow)?;

        let mut out = Vec::with_capacity(METADATA_HEADER_LEN + self.ciphertext.len());
        out.extend_from_slice(&self.metadata_version.to_be_bytes());
        out.extend_from_slice(&[0, 0]);
        out.extend_from_slice(&ciphertext_len.to_be_bytes());
        out.extend_from_slice(&self.ciphertext);
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::{METADATA_HEADER_LEN, MetadataSection, MetadataSectionError};

    fn sample_metadata() -> MetadataSection {
        MetadataSection {
            metadata_version: 1,
            ciphertext: vec![0xAA, 0xBB, 0xCC],
        }
    }

    #[test]
    fn metadata_roundtrip_is_stable() {
        let metadata = sample_metadata();
        let encoded = metadata.encode().expect("metadata should encode");
        let decoded = MetadataSection::parse(&encoded).expect("metadata should parse");

        assert_eq!(decoded, metadata);
    }

    #[test]
    fn metadata_len_is_header_plus_ciphertext() {
        let metadata = sample_metadata();
        let encoded = metadata.encode().expect("metadata should encode");
        assert_eq!(
            encoded.len(),
            METADATA_HEADER_LEN + metadata.ciphertext.len()
        );
    }

    #[test]
    fn rejects_unsupported_metadata_version() {
        let mut encoded = sample_metadata().encode().expect("metadata should encode");
        encoded[1] = 2;

        let error = MetadataSection::parse(&encoded).expect_err("version must be validated");
        assert_eq!(
            error,
            MetadataSectionError::UnsupportedMetadataVersion {
                expected: 1,
                actual: 2,
            }
        );
    }

    #[test]
    fn rejects_non_zero_reserved() {
        let mut encoded = sample_metadata().encode().expect("metadata should encode");
        encoded[2] = 1;

        let error = MetadataSection::parse(&encoded).expect_err("reserved must be zero");
        assert_eq!(error, MetadataSectionError::NonZeroReserved);
    }

    #[test]
    fn rejects_truncated_ciphertext() {
        let encoded = vec![
            0x00, 0x01, // metadata version
            0x00, 0x00, // reserved
            0x00, 0x00, 0x00, 0x03, // ciphertext_len = 3
            0xAA, 0xBB, // truncated ciphertext
        ];

        let error = MetadataSection::parse(&encoded).expect_err("truncated ciphertext must fail");
        assert_eq!(
            error,
            MetadataSectionError::TruncatedCiphertext {
                declared: 3,
                actual: 2,
            }
        );
    }

    #[test]
    fn rejects_empty_ciphertext() {
        let encoded = vec![
            0x00, 0x01, // metadata version
            0x00, 0x00, // reserved
            0x00, 0x00, 0x00, 0x00, // ciphertext_len = 0
        ];

        let error = MetadataSection::parse(&encoded).expect_err("empty ciphertext must fail");
        assert_eq!(error, MetadataSectionError::EmptyCiphertext);
    }
}
