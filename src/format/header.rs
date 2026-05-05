use core::fmt;

pub const MAGIC: [u8; 4] = *b"HLK1";
pub const RESERVED_LEN: usize = 32;
pub const FIXED_HEADER_LEN: usize = 70;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FixedHeader {
    pub format_version_major: u16,
    pub format_version_minor: u16,
    pub suite_id: u16,
    pub flags: u32,
    pub header_len: u32,
    pub policy_len: u32,
    pub wraps_len: u32,
    pub metadata_len: u32,
    pub payload_offset: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FixedHeaderError {
    InvalidLength { expected: usize, actual: usize },
    InvalidMagic([u8; 4]),
    NonZeroReserved,
    InvalidHeaderLengthField { min: u32, actual: u32 },
    InvalidPayloadOffset { expected: u64, actual: u64 },
}

impl fmt::Display for FixedHeaderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength { expected, actual } => {
                write!(
                    f,
                    "invalid fixed header length: expected {expected}, got {actual}"
                )
            }
            Self::InvalidMagic(magic) => write!(f, "invalid magic bytes: {magic:02x?}"),
            Self::NonZeroReserved => write!(f, "reserved bytes must be zero"),
            Self::InvalidHeaderLengthField { min, actual } => write!(
                f,
                "invalid header_len field: expected at least {min}, got {actual}"
            ),
            Self::InvalidPayloadOffset { expected, actual } => write!(
                f,
                "invalid payload_offset: expected {expected}, got {actual}"
            ),
        }
    }
}

impl std::error::Error for FixedHeaderError {}

impl FixedHeader {
    pub fn parse(bytes: &[u8]) -> Result<Self, FixedHeaderError> {
        if bytes.len() != FIXED_HEADER_LEN {
            return Err(FixedHeaderError::InvalidLength {
                expected: FIXED_HEADER_LEN,
                actual: bytes.len(),
            });
        }

        let magic = [bytes[0], bytes[1], bytes[2], bytes[3]];
        if magic != MAGIC {
            return Err(FixedHeaderError::InvalidMagic(magic));
        }

        let reserved = &bytes[(FIXED_HEADER_LEN - RESERVED_LEN)..FIXED_HEADER_LEN];
        if reserved.iter().any(|byte| *byte != 0) {
            return Err(FixedHeaderError::NonZeroReserved);
        }

        let header = Self {
            format_version_major: u16::from_be_bytes([bytes[4], bytes[5]]),
            format_version_minor: u16::from_be_bytes([bytes[6], bytes[7]]),
            suite_id: u16::from_be_bytes([bytes[8], bytes[9]]),
            flags: u32::from_be_bytes([bytes[10], bytes[11], bytes[12], bytes[13]]),
            header_len: u32::from_be_bytes([bytes[14], bytes[15], bytes[16], bytes[17]]),
            policy_len: u32::from_be_bytes([bytes[18], bytes[19], bytes[20], bytes[21]]),
            wraps_len: u32::from_be_bytes([bytes[22], bytes[23], bytes[24], bytes[25]]),
            metadata_len: u32::from_be_bytes([bytes[26], bytes[27], bytes[28], bytes[29]]),
            payload_offset: u64::from_be_bytes([
                bytes[30], bytes[31], bytes[32], bytes[33], bytes[34], bytes[35], bytes[36],
                bytes[37],
            ]),
        };

        header.validate_layout()?;

        Ok(header)
    }

    pub fn encode(&self) -> [u8; FIXED_HEADER_LEN] {
        let mut out = [0u8; FIXED_HEADER_LEN];

        out[0..4].copy_from_slice(&MAGIC);
        out[4..6].copy_from_slice(&self.format_version_major.to_be_bytes());
        out[6..8].copy_from_slice(&self.format_version_minor.to_be_bytes());
        out[8..10].copy_from_slice(&self.suite_id.to_be_bytes());
        out[10..14].copy_from_slice(&self.flags.to_be_bytes());
        out[14..18].copy_from_slice(&self.header_len.to_be_bytes());
        out[18..22].copy_from_slice(&self.policy_len.to_be_bytes());
        out[22..26].copy_from_slice(&self.wraps_len.to_be_bytes());
        out[26..30].copy_from_slice(&self.metadata_len.to_be_bytes());
        out[30..38].copy_from_slice(&self.payload_offset.to_be_bytes());

        out
    }

    fn validate_layout(&self) -> Result<(), FixedHeaderError> {
        let min_header_len = FIXED_HEADER_LEN as u32;
        if self.header_len < min_header_len {
            return Err(FixedHeaderError::InvalidHeaderLengthField {
                min: min_header_len,
                actual: self.header_len,
            });
        }

        let expected_payload_offset = u64::from(self.header_len)
            + u64::from(self.policy_len)
            + u64::from(self.wraps_len)
            + u64::from(self.metadata_len);

        if self.payload_offset != expected_payload_offset {
            return Err(FixedHeaderError::InvalidPayloadOffset {
                expected: expected_payload_offset,
                actual: self.payload_offset,
            });
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{FIXED_HEADER_LEN, FixedHeader, FixedHeaderError, MAGIC};

    fn sample_header() -> FixedHeader {
        FixedHeader {
            format_version_major: 1,
            format_version_minor: 0,
            suite_id: 1,
            flags: 0x0102_0304,
            header_len: 70,
            policy_len: 128,
            wraps_len: 256,
            metadata_len: 512,
            payload_offset: 966,
        }
    }

    #[test]
    fn fixed_header_roundtrip_is_stable() {
        let header = sample_header();
        let encoded = header.encode();
        let decoded = FixedHeader::parse(&encoded).expect("fixed header should parse");

        assert_eq!(decoded, header);
    }

    #[test]
    fn fixed_header_length_is_stable() {
        let encoded = sample_header().encode();

        assert_eq!(encoded.len(), FIXED_HEADER_LEN);
    }

    #[test]
    fn rejects_invalid_magic() {
        let mut encoded = sample_header().encode();
        encoded[0..4].copy_from_slice(b"BAD!");

        let error = FixedHeader::parse(&encoded).expect_err("magic must be validated");
        assert_eq!(error, FixedHeaderError::InvalidMagic(*b"BAD!"));
    }

    #[test]
    fn rejects_non_zero_reserved_bytes() {
        let mut encoded = sample_header().encode();
        encoded[FIXED_HEADER_LEN - 1] = 1;

        let error = FixedHeader::parse(&encoded).expect_err("reserved bytes must be zero");
        assert_eq!(error, FixedHeaderError::NonZeroReserved);
    }

    #[test]
    fn keeps_magic_constant() {
        assert_eq!(MAGIC, *b"HLK1");
    }

    #[test]
    fn rejects_header_len_smaller_than_fixed_header() {
        let mut header = sample_header();
        header.header_len = (FIXED_HEADER_LEN as u32) - 1;
        header.payload_offset = u64::from(
            header.header_len + header.policy_len + header.wraps_len + header.metadata_len,
        );

        let error = FixedHeader::parse(&header.encode())
            .expect_err("header_len below fixed header length must be rejected");

        assert_eq!(
            error,
            FixedHeaderError::InvalidHeaderLengthField {
                min: FIXED_HEADER_LEN as u32,
                actual: (FIXED_HEADER_LEN as u32) - 1,
            }
        );
    }

    #[test]
    fn rejects_payload_offset_mismatch() {
        let mut header = sample_header();
        header.payload_offset += 1;

        let error =
            FixedHeader::parse(&header.encode()).expect_err("payload_offset mismatch must fail");

        assert_eq!(
            error,
            FixedHeaderError::InvalidPayloadOffset {
                expected: 966,
                actual: 967,
            }
        );
    }
}
