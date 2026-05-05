use core::fmt;

pub const FOOTER_HEADER_LEN: usize = 12;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FooterSection {
    pub footer_version: u16,
    pub flags: u16,
    pub manifest_root: Vec<u8>,
    pub auth_tag: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FooterSectionError {
    InvalidLength { min: usize, actual: usize },
    UnsupportedFooterVersion { expected: u16, actual: u16 },
    NonZeroReserved,
    EmptyManifestRoot,
    EmptyAuthTag,
    TruncatedField { field: &'static str, declared: usize, actual: usize },
    InvalidFooterLength { declared: usize, actual: usize },
    LengthOverflow,
}

impl fmt::Display for FooterSectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength { min, actual } => {
                write!(f, "invalid footer section length: expected at least {min}, got {actual}")
            }
            Self::UnsupportedFooterVersion { expected, actual } => {
                write!(f, "unsupported footer version: expected {expected}, got {actual}")
            }
            Self::NonZeroReserved => write!(f, "reserved bytes must be zero"),
            Self::EmptyManifestRoot => write!(f, "manifest_root must not be empty"),
            Self::EmptyAuthTag => write!(f, "auth_tag must not be empty"),
            Self::TruncatedField {
                field,
                declared,
                actual,
            } => write!(
                f,
                "truncated footer field '{field}': declared {declared}, available {actual}"
            ),
            Self::InvalidFooterLength { declared, actual } => {
                write!(f, "invalid footer length: declared {declared}, actual {actual}")
            }
            Self::LengthOverflow => write!(f, "length overflow while processing footer section"),
        }
    }
}

impl std::error::Error for FooterSectionError {}

impl FooterSection {
    pub fn parse(bytes: &[u8]) -> Result<Self, FooterSectionError> {
        if bytes.len() < FOOTER_HEADER_LEN {
            return Err(FooterSectionError::InvalidLength {
                min: FOOTER_HEADER_LEN,
                actual: bytes.len(),
            });
        }

        let footer_version = u16::from_be_bytes([bytes[0], bytes[1]]);
        if footer_version != 1 {
            return Err(FooterSectionError::UnsupportedFooterVersion {
                expected: 1,
                actual: footer_version,
            });
        }

        let flags = u16::from_be_bytes([bytes[2], bytes[3]]);
        let manifest_root_len = u16::from_be_bytes([bytes[4], bytes[5]]) as usize;
        let auth_tag_len = u16::from_be_bytes([bytes[6], bytes[7]]) as usize;
        let reserved = [bytes[8], bytes[9], bytes[10], bytes[11]];

        if reserved != [0, 0, 0, 0] {
            return Err(FooterSectionError::NonZeroReserved);
        }

        if manifest_root_len == 0 {
            return Err(FooterSectionError::EmptyManifestRoot);
        }

        if auth_tag_len == 0 {
            return Err(FooterSectionError::EmptyAuthTag);
        }

        let manifest_start = FOOTER_HEADER_LEN;
        let manifest_end = manifest_start
            .checked_add(manifest_root_len)
            .ok_or(FooterSectionError::LengthOverflow)?;

        if manifest_end > bytes.len() {
            return Err(FooterSectionError::TruncatedField {
                field: "manifest_root",
                declared: manifest_root_len,
                actual: bytes.len() - manifest_start,
            });
        }

        let auth_start = manifest_end;
        let auth_end = auth_start
            .checked_add(auth_tag_len)
            .ok_or(FooterSectionError::LengthOverflow)?;

        if auth_end > bytes.len() {
            return Err(FooterSectionError::TruncatedField {
                field: "auth_tag",
                declared: auth_tag_len,
                actual: bytes.len() - auth_start,
            });
        }

        if auth_end != bytes.len() {
            let declared = FOOTER_HEADER_LEN + manifest_root_len + auth_tag_len;
            return Err(FooterSectionError::InvalidFooterLength {
                declared,
                actual: bytes.len(),
            });
        }

        Ok(Self {
            footer_version,
            flags,
            manifest_root: bytes[manifest_start..manifest_end].to_vec(),
            auth_tag: bytes[auth_start..auth_end].to_vec(),
        })
    }

    pub fn encode(&self) -> Result<Vec<u8>, FooterSectionError> {
        if self.footer_version != 1 {
            return Err(FooterSectionError::UnsupportedFooterVersion {
                expected: 1,
                actual: self.footer_version,
            });
        }

        if self.manifest_root.is_empty() {
            return Err(FooterSectionError::EmptyManifestRoot);
        }

        if self.auth_tag.is_empty() {
            return Err(FooterSectionError::EmptyAuthTag);
        }

        let manifest_root_len =
            u16::try_from(self.manifest_root.len()).map_err(|_| FooterSectionError::LengthOverflow)?;
        let auth_tag_len =
            u16::try_from(self.auth_tag.len()).map_err(|_| FooterSectionError::LengthOverflow)?;

        let mut out = Vec::with_capacity(FOOTER_HEADER_LEN + self.manifest_root.len() + self.auth_tag.len());
        out.extend_from_slice(&self.footer_version.to_be_bytes());
        out.extend_from_slice(&self.flags.to_be_bytes());
        out.extend_from_slice(&manifest_root_len.to_be_bytes());
        out.extend_from_slice(&auth_tag_len.to_be_bytes());
        out.extend_from_slice(&[0, 0, 0, 0]);
        out.extend_from_slice(&self.manifest_root);
        out.extend_from_slice(&self.auth_tag);

        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::{FooterSection, FooterSectionError, FOOTER_HEADER_LEN};

    fn sample_footer() -> FooterSection {
        FooterSection {
            footer_version: 1,
            flags: 0,
            manifest_root: b"root".to_vec(),
            auth_tag: vec![
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
            ],
        }
    }

    #[test]
    fn footer_roundtrip_is_stable() {
        let footer = sample_footer();
        let encoded = footer.encode().expect("footer should encode");
        let decoded = FooterSection::parse(&encoded).expect("footer should parse");

        assert_eq!(decoded, footer);
    }

    #[test]
    fn footer_len_is_header_plus_fields() {
        let footer = sample_footer();
        let encoded = footer.encode().expect("footer should encode");

        assert_eq!(
            encoded.len(),
            FOOTER_HEADER_LEN + footer.manifest_root.len() + footer.auth_tag.len()
        );
    }

    #[test]
    fn rejects_unsupported_footer_version() {
        let mut encoded = sample_footer().encode().expect("footer should encode");
        encoded[1] = 2;

        let error = FooterSection::parse(&encoded).expect_err("version must be validated");
        assert_eq!(
            error,
            FooterSectionError::UnsupportedFooterVersion {
                expected: 1,
                actual: 2,
            }
        );
    }

    #[test]
    fn rejects_non_zero_reserved() {
        let mut encoded = sample_footer().encode().expect("footer should encode");
        encoded[8] = 1;

        let error = FooterSection::parse(&encoded).expect_err("reserved must be zero");
        assert_eq!(error, FooterSectionError::NonZeroReserved);
    }

    #[test]
    fn rejects_truncated_auth_tag() {
        let encoded = vec![
            0x00, 0x01, // footer_version
            0x00, 0x00, // flags
            0x00, 0x04, // manifest_root_len = 4
            0x00, 0x10, // auth_tag_len = 16
            0x00, 0x00, 0x00, 0x00, // reserved
            b'r', b'o', b'o', b't', // manifest_root
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, // 15 bytes (truncated)
        ];

        let error = FooterSection::parse(&encoded).expect_err("truncated auth_tag must fail");
        assert_eq!(
            error,
            FooterSectionError::TruncatedField {
                field: "auth_tag",
                declared: 16,
                actual: 15,
            }
        );
    }

    #[test]
    fn rejects_empty_manifest_root() {
        let encoded = vec![
            0x00, 0x01, // footer_version
            0x00, 0x00, // flags
            0x00, 0x00, // manifest_root_len = 0
            0x00, 0x10, // auth_tag_len = 16
            0x00, 0x00, 0x00, 0x00, // reserved
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        ];

        let error = FooterSection::parse(&encoded).expect_err("empty manifest_root must fail");
        assert_eq!(error, FooterSectionError::EmptyManifestRoot);
    }
}
