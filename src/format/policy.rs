use core::fmt;

pub const POLICY_SECTION_LEN: usize = 8;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicySection {
    pub policy_version: u16,
    pub threshold: u8,
    pub total_shares: u8,
    pub wrapper_count: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicySectionError {
    InvalidLength {
        expected: usize,
        actual: usize,
    },
    UnsupportedPolicyVersion {
        expected: u16,
        actual: u16,
    },
    InvalidTotalShares,
    InvalidThreshold {
        threshold: u8,
        total_shares: u8,
    },
    InvalidWrapperCount {
        wrapper_count: u16,
        total_shares: u8,
    },
    NonZeroReserved,
}

impl fmt::Display for PolicySectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength { expected, actual } => {
                write!(
                    f,
                    "invalid policy section length: expected {expected}, got {actual}"
                )
            }
            Self::UnsupportedPolicyVersion { expected, actual } => write!(
                f,
                "unsupported policy version: expected {expected}, got {actual}"
            ),
            Self::InvalidTotalShares => write!(f, "total_shares must be greater than zero"),
            Self::InvalidThreshold {
                threshold,
                total_shares,
            } => write!(
                f,
                "invalid threshold {threshold} for total_shares {total_shares}"
            ),
            Self::InvalidWrapperCount {
                wrapper_count,
                total_shares,
            } => write!(
                f,
                "invalid wrapper_count {wrapper_count} for total_shares {total_shares}"
            ),
            Self::NonZeroReserved => write!(f, "reserved bytes must be zero"),
        }
    }
}

impl std::error::Error for PolicySectionError {}

impl PolicySection {
    pub fn parse(bytes: &[u8]) -> Result<Self, PolicySectionError> {
        if bytes.len() != POLICY_SECTION_LEN {
            return Err(PolicySectionError::InvalidLength {
                expected: POLICY_SECTION_LEN,
                actual: bytes.len(),
            });
        }

        let policy_version = u16::from_be_bytes([bytes[0], bytes[1]]);
        if policy_version != 1 {
            return Err(PolicySectionError::UnsupportedPolicyVersion {
                expected: 1,
                actual: policy_version,
            });
        }

        let threshold = bytes[2];
        let total_shares = bytes[3];
        let wrapper_count = u16::from_be_bytes([bytes[4], bytes[5]]);
        let reserved = [bytes[6], bytes[7]];

        if reserved != [0, 0] {
            return Err(PolicySectionError::NonZeroReserved);
        }

        if total_shares == 0 {
            return Err(PolicySectionError::InvalidTotalShares);
        }

        if threshold == 0 || threshold > total_shares {
            return Err(PolicySectionError::InvalidThreshold {
                threshold,
                total_shares,
            });
        }

        if wrapper_count < u16::from(total_shares) {
            return Err(PolicySectionError::InvalidWrapperCount {
                wrapper_count,
                total_shares,
            });
        }

        Ok(Self {
            policy_version,
            threshold,
            total_shares,
            wrapper_count,
        })
    }

    pub fn encode(&self) -> Result<[u8; POLICY_SECTION_LEN], PolicySectionError> {
        if self.policy_version != 1 {
            return Err(PolicySectionError::UnsupportedPolicyVersion {
                expected: 1,
                actual: self.policy_version,
            });
        }

        if self.total_shares == 0 {
            return Err(PolicySectionError::InvalidTotalShares);
        }

        if self.threshold == 0 || self.threshold > self.total_shares {
            return Err(PolicySectionError::InvalidThreshold {
                threshold: self.threshold,
                total_shares: self.total_shares,
            });
        }

        if self.wrapper_count < u16::from(self.total_shares) {
            return Err(PolicySectionError::InvalidWrapperCount {
                wrapper_count: self.wrapper_count,
                total_shares: self.total_shares,
            });
        }

        let mut out = [0u8; POLICY_SECTION_LEN];
        out[0..2].copy_from_slice(&self.policy_version.to_be_bytes());
        out[2] = self.threshold;
        out[3] = self.total_shares;
        out[4..6].copy_from_slice(&self.wrapper_count.to_be_bytes());
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::{POLICY_SECTION_LEN, PolicySection, PolicySectionError};

    fn sample_policy() -> PolicySection {
        PolicySection {
            policy_version: 1,
            threshold: 2,
            total_shares: 3,
            wrapper_count: 3,
        }
    }

    #[test]
    fn policy_roundtrip_is_stable() {
        let policy = sample_policy();
        let encoded = policy.encode().expect("policy should encode");
        let decoded = PolicySection::parse(&encoded).expect("policy should parse");

        assert_eq!(decoded, policy);
    }

    #[test]
    fn policy_length_is_stable() {
        let encoded = sample_policy().encode().expect("policy should encode");
        assert_eq!(encoded.len(), POLICY_SECTION_LEN);
    }

    #[test]
    fn rejects_invalid_policy_version() {
        let mut encoded = sample_policy().encode().expect("policy should encode");
        encoded[1] = 2;

        let error = PolicySection::parse(&encoded).expect_err("version must be validated");
        assert_eq!(
            error,
            PolicySectionError::UnsupportedPolicyVersion {
                expected: 1,
                actual: 2,
            }
        );
    }

    #[test]
    fn rejects_non_zero_reserved() {
        let mut encoded = sample_policy().encode().expect("policy should encode");
        encoded[6] = 1;

        let error = PolicySection::parse(&encoded).expect_err("reserved must be zero");
        assert_eq!(error, PolicySectionError::NonZeroReserved);
    }

    #[test]
    fn rejects_invalid_threshold() {
        let mut encoded = sample_policy().encode().expect("policy should encode");
        encoded[2] = 4;

        let error = PolicySection::parse(&encoded).expect_err("threshold must be valid");
        assert_eq!(
            error,
            PolicySectionError::InvalidThreshold {
                threshold: 4,
                total_shares: 3,
            }
        );
    }

    #[test]
    fn rejects_wrapper_count_below_total_shares() {
        let mut encoded = sample_policy().encode().expect("policy should encode");
        encoded[4..6].copy_from_slice(&2u16.to_be_bytes());

        let error =
            PolicySection::parse(&encoded).expect_err("wrapper_count must be >= total_shares");
        assert_eq!(
            error,
            PolicySectionError::InvalidWrapperCount {
                wrapper_count: 2,
                total_shares: 3,
            }
        );
    }
}
