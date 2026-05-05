use core::fmt;
use std::collections::HashSet;

pub const WRAPS_HEADER_LEN: usize = 4;
pub const WRAPPER_ENTRY_HEADER_LEN: usize = 8;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WrapsSection {
    pub wraps_version: u16,
    pub wrappers: Vec<WrapperEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WrapperEntry {
    pub wrapper_type: u16,
    pub wrapper_flags: u16,
    pub wrapper_id: Vec<u8>,
    pub stanza: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WrapsSectionError {
    InvalidLength { min: usize, actual: usize },
    UnsupportedWrapsVersion { expected: u16, actual: u16 },
    TruncatedEntryHeader { index: usize },
    TruncatedField { index: usize, field: &'static str },
    InvalidWrapperCount { declared: u16, actual: usize },
    EmptyWrapperId { index: usize },
    DuplicateWrapperId,
    LengthOverflow,
}

impl fmt::Display for WrapsSectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength { min, actual } => {
                write!(
                    f,
                    "invalid wraps section length: expected at least {min}, got {actual}"
                )
            }
            Self::UnsupportedWrapsVersion { expected, actual } => {
                write!(
                    f,
                    "unsupported wraps version: expected {expected}, got {actual}"
                )
            }
            Self::TruncatedEntryHeader { index } => {
                write!(f, "truncated wrapper entry header at index {index}")
            }
            Self::TruncatedField { index, field } => {
                write!(
                    f,
                    "truncated field '{field}' in wrapper entry at index {index}"
                )
            }
            Self::InvalidWrapperCount { declared, actual } => write!(
                f,
                "invalid wrapper_count: declared {declared}, parsed {actual}"
            ),
            Self::EmptyWrapperId { index } => {
                write!(f, "wrapper_id must not be empty at index {index}")
            }
            Self::DuplicateWrapperId => write!(f, "duplicate wrapper_id entries are not allowed"),
            Self::LengthOverflow => write!(f, "length overflow while processing wraps section"),
        }
    }
}

impl std::error::Error for WrapsSectionError {}

impl WrapsSection {
    pub fn parse(bytes: &[u8]) -> Result<Self, WrapsSectionError> {
        if bytes.len() < WRAPS_HEADER_LEN {
            return Err(WrapsSectionError::InvalidLength {
                min: WRAPS_HEADER_LEN,
                actual: bytes.len(),
            });
        }

        let wraps_version = u16::from_be_bytes([bytes[0], bytes[1]]);
        if wraps_version != 1 {
            return Err(WrapsSectionError::UnsupportedWrapsVersion {
                expected: 1,
                actual: wraps_version,
            });
        }

        let wrapper_count = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;
        let mut offset = WRAPS_HEADER_LEN;
        let mut wrappers = Vec::with_capacity(wrapper_count);

        for index in 0..wrapper_count {
            let entry_header_end = offset
                .checked_add(WRAPPER_ENTRY_HEADER_LEN)
                .ok_or(WrapsSectionError::LengthOverflow)?;
            if entry_header_end > bytes.len() {
                return Err(WrapsSectionError::TruncatedEntryHeader { index });
            }

            let wrapper_type = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]);
            let wrapper_flags = u16::from_be_bytes([bytes[offset + 2], bytes[offset + 3]]);
            let wrapper_id_len =
                u16::from_be_bytes([bytes[offset + 4], bytes[offset + 5]]) as usize;
            let stanza_len = u16::from_be_bytes([bytes[offset + 6], bytes[offset + 7]]) as usize;
            offset = entry_header_end;

            if wrapper_id_len == 0 {
                return Err(WrapsSectionError::EmptyWrapperId { index });
            }

            let wrapper_id_end = offset
                .checked_add(wrapper_id_len)
                .ok_or(WrapsSectionError::LengthOverflow)?;
            if wrapper_id_end > bytes.len() {
                return Err(WrapsSectionError::TruncatedField {
                    index,
                    field: "wrapper_id",
                });
            }
            let wrapper_id = bytes[offset..wrapper_id_end].to_vec();
            offset = wrapper_id_end;

            let stanza_end = offset
                .checked_add(stanza_len)
                .ok_or(WrapsSectionError::LengthOverflow)?;
            if stanza_end > bytes.len() {
                return Err(WrapsSectionError::TruncatedField {
                    index,
                    field: "stanza",
                });
            }
            let stanza = bytes[offset..stanza_end].to_vec();
            offset = stanza_end;

            wrappers.push(WrapperEntry {
                wrapper_type,
                wrapper_flags,
                wrapper_id,
                stanza,
            });
        }

        if offset != bytes.len() {
            return Err(WrapsSectionError::InvalidWrapperCount {
                declared: wrapper_count as u16,
                actual: wrappers.len(),
            });
        }

        let mut seen_ids = HashSet::with_capacity(wrappers.len());
        for wrapper in &wrappers {
            if !seen_ids.insert(wrapper.wrapper_id.clone()) {
                return Err(WrapsSectionError::DuplicateWrapperId);
            }
        }

        Ok(Self {
            wraps_version,
            wrappers,
        })
    }

    pub fn encode(&self) -> Result<Vec<u8>, WrapsSectionError> {
        if self.wraps_version != 1 {
            return Err(WrapsSectionError::UnsupportedWrapsVersion {
                expected: 1,
                actual: self.wraps_version,
            });
        }

        let mut seen_ids = HashSet::with_capacity(self.wrappers.len());
        let mut out = Vec::new();
        out.extend_from_slice(&self.wraps_version.to_be_bytes());
        out.extend_from_slice(&(self.wrappers.len() as u16).to_be_bytes());

        for (index, wrapper) in self.wrappers.iter().enumerate() {
            if wrapper.wrapper_id.is_empty() {
                return Err(WrapsSectionError::EmptyWrapperId { index });
            }

            if !seen_ids.insert(wrapper.wrapper_id.clone()) {
                return Err(WrapsSectionError::DuplicateWrapperId);
            }

            let wrapper_id_len = u16::try_from(wrapper.wrapper_id.len())
                .map_err(|_| WrapsSectionError::LengthOverflow)?;
            let stanza_len = u16::try_from(wrapper.stanza.len())
                .map_err(|_| WrapsSectionError::LengthOverflow)?;

            out.extend_from_slice(&wrapper.wrapper_type.to_be_bytes());
            out.extend_from_slice(&wrapper.wrapper_flags.to_be_bytes());
            out.extend_from_slice(&wrapper_id_len.to_be_bytes());
            out.extend_from_slice(&stanza_len.to_be_bytes());
            out.extend_from_slice(&wrapper.wrapper_id);
            out.extend_from_slice(&wrapper.stanza);
        }

        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::{WrapperEntry, WrapsSection, WrapsSectionError};

    fn sample_wraps() -> WrapsSection {
        WrapsSection {
            wraps_version: 1,
            wrappers: vec![WrapperEntry {
                wrapper_type: 1,
                wrapper_flags: 0,
                wrapper_id: b"test".to_vec(),
                stanza: vec![0x01, 0x02, 0x03],
            }],
        }
    }

    #[test]
    fn wraps_roundtrip_is_stable() {
        let wraps = sample_wraps();
        let encoded = wraps.encode().expect("wraps should encode");
        let decoded = WrapsSection::parse(&encoded).expect("wraps should parse");

        assert_eq!(decoded, wraps);
    }

    #[test]
    fn rejects_unsupported_wraps_version() {
        let mut encoded = sample_wraps().encode().expect("wraps should encode");
        encoded[1] = 2;

        let error = WrapsSection::parse(&encoded).expect_err("version must be validated");
        assert_eq!(
            error,
            WrapsSectionError::UnsupportedWrapsVersion {
                expected: 1,
                actual: 2,
            }
        );
    }

    #[test]
    fn rejects_truncated_stanza() {
        let encoded = vec![
            0x00, 0x01, // version
            0x00, 0x01, // wrapper count
            0x00, 0x01, // wrapper type
            0x00, 0x00, // wrapper flags
            0x00, 0x04, // wrapper id len
            0x00, 0x03, // stanza len
            b't', b'e', b's', b't', // wrapper id
            0x01, 0x02, // stanza truncated (should be 3)
        ];

        let error = WrapsSection::parse(&encoded).expect_err("stanza truncation must fail");
        assert_eq!(
            error,
            WrapsSectionError::TruncatedField {
                index: 0,
                field: "stanza",
            }
        );
    }

    #[test]
    fn rejects_duplicate_wrapper_ids() {
        let wraps = WrapsSection {
            wraps_version: 1,
            wrappers: vec![
                WrapperEntry {
                    wrapper_type: 1,
                    wrapper_flags: 0,
                    wrapper_id: b"dup".to_vec(),
                    stanza: vec![0x01],
                },
                WrapperEntry {
                    wrapper_type: 2,
                    wrapper_flags: 0,
                    wrapper_id: b"dup".to_vec(),
                    stanza: vec![0x02],
                },
            ],
        };

        let error = wraps
            .encode()
            .expect_err("duplicate wrapper ids should fail on encode");
        assert_eq!(error, WrapsSectionError::DuplicateWrapperId);
    }
}
