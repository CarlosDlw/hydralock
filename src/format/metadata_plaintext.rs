/// Metadata plaintext structure — internal, encrypted contents.
///
/// Serialized as CBOR canonical array to ensure deterministic encoding.
/// All fields MUST be present in the exact order specified.
///
/// Array layout:
///   [0] plaintext_size: u64
///   [1] logical_name: text string | null (optional)
///   [2] mime_type: text string | null (optional)
///   [3] created_at: i64 | null (optional, Unix timestamp)
///   [4] chunk_size: u32
///   [5] epoch_size: u32
///   [6] manifest_root: byte string (32 bytes)
///   [7] payload_mode: u8
///   [8] padding_bucket: array [type, value?]
///   [9] reserved: 4 zero bytes (future extensibility)

use serde::{Deserialize, Serialize};

/// Padding strategy for metadata and payload size obfuscation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PaddingBucket {
    /// No padding applied.
    None,
    /// Padding to nearest power-of-2 bucket size (in bytes).
    /// Parameter is log2(bucket_size), e.g., 10 means 1024-byte buckets.
    PowerOf2(u8),
    /// Custom padding to exact byte boundary.
    Custom(u32),
}

impl PaddingBucket {
    /// Serialize to CBOR-compatible format: [type_u8, value?].
    pub fn to_cbor_array(&self) -> (u8, Option<u64>) {
        match self {
            PaddingBucket::None => (0, None),
            PaddingBucket::PowerOf2(log2) => (1, Some(*log2 as u64)),
            PaddingBucket::Custom(size) => (2, Some(*size as u64)),
        }
    }

    /// Deserialize from CBOR-compatible format: (type_u8, value?).
    pub fn from_cbor_array(type_u8: u8, value: Option<u64>) -> Result<Self, MetadataError> {
        match type_u8 {
            0 => Ok(PaddingBucket::None),
            1 => {
                let val = value.ok_or(MetadataError::MissingPaddingValue)?;
                if val > u8::MAX as u64 {
                    return Err(MetadataError::InvalidPaddingValue);
                }
                Ok(PaddingBucket::PowerOf2(val as u8))
            }
            2 => {
                let val = value.ok_or(MetadataError::MissingPaddingValue)?;
                if val > u32::MAX as u64 {
                    return Err(MetadataError::InvalidPaddingValue);
                }
                Ok(PaddingBucket::Custom(val as u32))
            }
            _ => Err(MetadataError::UnknownPaddingType),
        }
    }
}

/// Metadata plaintext — canonically serializable, deterministic.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MetadataPlaintext {
    /// Total plaintext size of payload in bytes.
    pub plaintext_size: u64,
    /// Optional human-readable name (UTF-8, max 255 bytes).
    pub logical_name: Option<String>,
    /// Optional MIME type (UTF-8, max 255 bytes).
    pub mime_type: Option<String>,
    /// Optional creation timestamp (Unix seconds).
    pub created_at: Option<i64>,
    /// Fixed chunk size for payload (bytes).
    pub chunk_size: u32,
    /// Fixed epoch size (number of chunks per epoch).
    pub epoch_size: u32,
    /// Root hash of manifest tree (32 bytes, BLAKE3).
    pub manifest_root: [u8; 32],
    /// Payload encryption mode (reserved: 0 = XChaCha20-Poly1305).
    pub payload_mode: u8,
    /// Padding strategy for obfuscation.
    pub padding_bucket: PaddingBucket,
}

impl MetadataPlaintext {
    /// Encode to CBOR canonical byte array (no trailing bytes).
    pub fn encode(&self) -> Result<Vec<u8>, MetadataError> {
        // Use ciborium Value API to construct the structure explicitly.
        let (pad_type, pad_val) = self.padding_bucket.to_cbor_array();

        let pad_array: Vec<ciborium::Value> = if let Some(val) = pad_val {
            vec![
                ciborium::Value::Integer((pad_type as i64).into()),
                ciborium::Value::Integer((val as i64).into()),
            ]
        } else {
            vec![ciborium::Value::Integer((pad_type as i64).into())]
        };

        let array = ciborium::Value::Array(vec![
            ciborium::Value::Integer((self.plaintext_size as i64).into()),
            self.logical_name.as_ref().map(|s| ciborium::Value::Text(s.clone()))
                .unwrap_or(ciborium::Value::Null),
            self.mime_type.as_ref().map(|s| ciborium::Value::Text(s.clone()))
                .unwrap_or(ciborium::Value::Null),
            self.created_at.map(|t| ciborium::Value::Integer((t as i64).into()))
                .unwrap_or(ciborium::Value::Null),
            ciborium::Value::Integer((self.chunk_size as i64).into()),
            ciborium::Value::Integer((self.epoch_size as i64).into()),
            ciborium::Value::Bytes(self.manifest_root.to_vec()),
            ciborium::Value::Integer((self.payload_mode as i64).into()),
            ciborium::Value::Array(pad_array),
            ciborium::Value::Bytes(vec![0, 0, 0, 0]),
        ]);

        let mut buf = Vec::new();
        ciborium::ser::into_writer(&array, &mut buf)
            .map_err(|_| MetadataError::EncodingFailed)?;
        Ok(buf)
    }

    /// Parse from CBOR canonical byte array (strict, fail-closed).
    pub fn parse(bytes: &[u8]) -> Result<Self, MetadataError> {
        // Deserialize CBOR array.
        let value: ciborium::Value =
            ciborium::de::from_reader(bytes).map_err(|_| MetadataError::DecodingFailed)?;

        let arr = match value {
            ciborium::Value::Array(a) => a,
            _ => return Err(MetadataError::NotAnArray),
        };

        if arr.len() != 10 {
            return Err(MetadataError::InvalidArrayLength);
        }

        // [0] plaintext_size: u64
        let plaintext_size: u64 = match &arr[0] {
            ciborium::Value::Integer(i) => {
                let val: i128 = (*i).into();
                if val < 0 {
                    return Err(MetadataError::NegativeSize);
                }
                val as u64
            }
            _ => return Err(MetadataError::InvalidPlaintextSize),
        };

        // [1] logical_name: text | null
        let logical_name = match &arr[1] {
            ciborium::Value::Text(s) => {
                if s.len() > 255 {
                    return Err(MetadataError::NameTooLong);
                }
                Some(s.clone())
            }
            ciborium::Value::Null => None,
            _ => return Err(MetadataError::InvalidLogicalName),
        };

        // [2] mime_type: text | null
        let mime_type = match &arr[2] {
            ciborium::Value::Text(s) => {
                if s.len() > 255 {
                    return Err(MetadataError::MimeTypeTooLong);
                }
                Some(s.clone())
            }
            ciborium::Value::Null => None,
            _ => return Err(MetadataError::InvalidMimeType),
        };

        // [3] created_at: i64 | null
        let created_at = match &arr[3] {
            ciborium::Value::Integer(i) => {
                let val: i128 = (*i).into();
                Some(val as i64)
            }
            ciborium::Value::Null => None,
            _ => return Err(MetadataError::InvalidCreatedAt),
        };

        // [4] chunk_size: u32
        let chunk_size = match &arr[4] {
            ciborium::Value::Integer(i) => {
                let val: i128 = (*i).into();
                if val < 0 || val > u32::MAX as i128 {
                    return Err(MetadataError::InvalidChunkSize);
                }
                val as u32
            }
            _ => return Err(MetadataError::InvalidChunkSize),
        };
        if chunk_size == 0 {
            return Err(MetadataError::ZeroChunkSize);
        }

        // [5] epoch_size: u32
        let epoch_size = match &arr[5] {
            ciborium::Value::Integer(i) => {
                let val: i128 = (*i).into();
                if val < 0 || val > u32::MAX as i128 {
                    return Err(MetadataError::InvalidEpochSize);
                }
                val as u32
            }
            _ => return Err(MetadataError::InvalidEpochSize),
        };
        if epoch_size == 0 {
            return Err(MetadataError::ZeroEpochSize);
        }

        // [6] manifest_root: 32-byte string
        let manifest_root = match &arr[6] {
            ciborium::Value::Bytes(b) => {
                if b.len() != 32 {
                    return Err(MetadataError::InvalidManifestRootLen);
                }
                let mut root = [0u8; 32];
                root.copy_from_slice(b);
                root
            }
            _ => return Err(MetadataError::InvalidManifestRoot),
        };

        // [7] payload_mode: u8
        let payload_mode = match &arr[7] {
            ciborium::Value::Integer(i) => {
                let val: i128 = (*i).into();
                if val < 0 || val > u8::MAX as i128 {
                    return Err(MetadataError::InvalidPayloadMode);
                }
                val as u8
            }
            _ => return Err(MetadataError::InvalidPayloadMode),
        };

        // [8] padding_bucket: [type, value?]
        let padding_bucket = match &arr[8] {
            ciborium::Value::Array(pad_arr) => {
                if pad_arr.is_empty() || pad_arr.len() > 2 {
                    return Err(MetadataError::InvalidPaddingBucketArray);
                }
                let pad_type = match &pad_arr[0] {
                    ciborium::Value::Integer(i) => {
                        let val: i128 = (*i).into();
                        if val < 0 || val > u8::MAX as i128 {
                            return Err(MetadataError::InvalidPaddingType);
                        }
                        val as u8
                    }
                    _ => return Err(MetadataError::InvalidPaddingType),
                };
                let pad_val = if pad_arr.len() > 1 {
                    match &pad_arr[1] {
                        ciborium::Value::Integer(i) => {
                            let val: i128 = (*i).into();
                            if val < 0 {
                                return Err(MetadataError::NegativePaddingValue);
                            }
                            Some(val as u64)
                        }
                        _ => return Err(MetadataError::InvalidPaddingValue),
                    }
                } else {
                    None
                };
                PaddingBucket::from_cbor_array(pad_type, pad_val)?
            }
            _ => return Err(MetadataError::InvalidPaddingBucket),
        };

        // [9] reserved: 4 zero bytes
        let reserved = match &arr[9] {
            ciborium::Value::Bytes(b) => {
                if b.len() != 4 {
                    return Err(MetadataError::InvalidReservedLen);
                }
                b
            }
            _ => return Err(MetadataError::InvalidReserved),
        };
        if reserved.as_slice() != [0, 0, 0, 0] {
            return Err(MetadataError::NonZeroReserved);
        }

        Ok(MetadataPlaintext {
            plaintext_size,
            logical_name,
            mime_type,
            created_at,
            chunk_size,
            epoch_size,
            manifest_root,
            payload_mode,
            padding_bucket,
        })
    }
}

/// Metadata encoding/parsing errors.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MetadataError {
    EncodingFailed,
    DecodingFailed,
    NotAnArray,
    InvalidArrayLength,
    NegativeSize,
    InvalidPlaintextSize,
    NameTooLong,
    InvalidLogicalName,
    MimeTypeTooLong,
    InvalidMimeType,
    InvalidCreatedAt,
    InvalidChunkSize,
    ZeroChunkSize,
    InvalidEpochSize,
    ZeroEpochSize,
    InvalidManifestRootLen,
    InvalidManifestRoot,
    InvalidPayloadMode,
    InvalidPaddingBucketArray,
    InvalidPaddingType,
    InvalidPaddingValue,
    NegativePaddingValue,
    MissingPaddingValue,
    UnknownPaddingType,
    InvalidPaddingBucket,
    InvalidReservedLen,
    InvalidReserved,
    NonZeroReserved,
}

impl std::fmt::Display for MetadataError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for MetadataError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_roundtrip_is_stable() {
        let original = MetadataPlaintext {
            plaintext_size: 1_000_000,
            logical_name: Some("MyFile".to_string()),
            mime_type: Some("application/octet-stream".to_string()),
            created_at: Some(1609459200),
            chunk_size: 65536,
            epoch_size: 100,
            manifest_root: [42u8; 32],
            payload_mode: 0,
            padding_bucket: PaddingBucket::PowerOf2(10),
        };

        let encoded = original.encode().expect("encode failed");
        let decoded = MetadataPlaintext::parse(&encoded).expect("decode failed");
        assert_eq!(original, decoded);
    }

    #[test]
    fn metadata_without_optionals_roundtrip() {
        let original = MetadataPlaintext {
            plaintext_size: 500,
            logical_name: None,
            mime_type: None,
            created_at: None,
            chunk_size: 4096,
            epoch_size: 50,
            manifest_root: [1u8; 32],
            payload_mode: 0,
            padding_bucket: PaddingBucket::None,
        };

        let encoded = original.encode().expect("encode failed");
        let decoded = MetadataPlaintext::parse(&encoded).expect("decode failed");
        assert_eq!(original, decoded);
    }

    #[test]
    fn metadata_with_custom_padding_roundtrip() {
        let original = MetadataPlaintext {
            plaintext_size: 12345,
            logical_name: Some("Test".to_string()),
            mime_type: None,
            created_at: None,
            chunk_size: 8192,
            epoch_size: 200,
            manifest_root: [255u8; 32],
            payload_mode: 0,
            padding_bucket: PaddingBucket::Custom(4096),
        };

        let encoded = original.encode().expect("encode failed");
        let decoded = MetadataPlaintext::parse(&encoded).expect("decode failed");
        assert_eq!(original, decoded);
    }

    #[test]
    fn rejects_invalid_array_length() {
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&(1u64, 2u64, 3u64), &mut buf).unwrap();
        let err = MetadataPlaintext::parse(&buf).unwrap_err();
        assert_eq!(err, MetadataError::InvalidArrayLength);
    }

    #[test]
    fn rejects_zero_chunk_size() {
        let mut buf = Vec::new();
        ciborium::ser::into_writer(
            &(
                1000u64,
                None::<String>,
                None::<String>,
                None::<i64>,
                0u32, // zero chunk_size
                100u32,
                [0u8; 32],
                0u8,
                (0u8, None::<u64>),
                [0u8; 4],
            ),
            &mut buf,
        )
        .unwrap();
        let err = MetadataPlaintext::parse(&buf).unwrap_err();
        assert_eq!(err, MetadataError::ZeroChunkSize);
    }

    #[test]
    fn rejects_zero_epoch_size() {
        let mut buf = Vec::new();
        ciborium::ser::into_writer(
            &(
                1000u64,
                None::<String>,
                None::<String>,
                None::<i64>,
                4096u32,
                0u32, // zero epoch_size
                [0u8; 32],
                0u8,
                (0u8, None::<u64>),
                [0u8; 4],
            ),
            &mut buf,
        )
        .unwrap();
        let err = MetadataPlaintext::parse(&buf).unwrap_err();
        assert_eq!(err, MetadataError::ZeroEpochSize);
    }

    #[test]
    fn rejects_wrong_manifest_root_length() {
        // Construct a CBOR array manually with wrong manifest_root length
        let array = ciborium::Value::Array(vec![
            ciborium::Value::Integer(1000i64.into()),
            ciborium::Value::Null,
            ciborium::Value::Null,
            ciborium::Value::Null,
            ciborium::Value::Integer(4096i64.into()),
            ciborium::Value::Integer(100i64.into()),
            ciborium::Value::Bytes(vec![0u8; 16]), // wrong: 16 instead of 32
            ciborium::Value::Integer(0i64.into()),
            ciborium::Value::Array(vec![ciborium::Value::Integer(0i64.into())]),
            ciborium::Value::Bytes(vec![0, 0, 0, 0]),
        ]);

        let mut buf = Vec::new();
        ciborium::ser::into_writer(&array, &mut buf).unwrap();
        let err = MetadataPlaintext::parse(&buf).unwrap_err();
        assert_eq!(err, MetadataError::InvalidManifestRootLen);
    }

    #[test]
    fn rejects_non_zero_reserved() {
        let array = ciborium::Value::Array(vec![
            ciborium::Value::Integer(1000i64.into()),
            ciborium::Value::Null,
            ciborium::Value::Null,
            ciborium::Value::Null,
            ciborium::Value::Integer(4096i64.into()),
            ciborium::Value::Integer(100i64.into()),
            ciborium::Value::Bytes(vec![0u8; 32]),
            ciborium::Value::Integer(0i64.into()),
            ciborium::Value::Array(vec![ciborium::Value::Integer(0i64.into())]),
            ciborium::Value::Bytes(vec![0u8, 1u8, 0u8, 0u8]), // non-zero reserved
        ]);

        let mut buf = Vec::new();
        ciborium::ser::into_writer(&array, &mut buf).unwrap();
        let err = MetadataPlaintext::parse(&buf).unwrap_err();
        assert_eq!(err, MetadataError::NonZeroReserved);
    }

    #[test]
    fn rejects_name_too_long() {
        let long_name = "a".repeat(256);
        let mut buf = Vec::new();
        ciborium::ser::into_writer(
            &(
                1000u64,
                Some(long_name),
                None::<String>,
                None::<i64>,
                4096u32,
                100u32,
                [0u8; 32],
                0u8,
                (0u8, None::<u64>),
                [0u8; 4],
            ),
            &mut buf,
        )
        .unwrap();
        let err = MetadataPlaintext::parse(&buf).unwrap_err();
        assert_eq!(err, MetadataError::NameTooLong);
    }

    #[test]
    fn encoding_is_deterministic() {
        let meta = MetadataPlaintext {
            plaintext_size: 1000,
            logical_name: Some("Test".to_string()),
            mime_type: Some("text/plain".to_string()),
            created_at: Some(1609459200),
            chunk_size: 4096,
            epoch_size: 100,
            manifest_root: [55u8; 32],
            payload_mode: 0,
            padding_bucket: PaddingBucket::PowerOf2(12),
        };

        let enc1 = meta.encode().expect("encode 1 failed");
        let enc2 = meta.encode().expect("encode 2 failed");
        assert_eq!(enc1, enc2, "encoding must be deterministic");
    }

    #[test]
    fn padding_bucket_none_roundtrip() {
        let (t, v) = PaddingBucket::None.to_cbor_array();
        let result = PaddingBucket::from_cbor_array(t, v).unwrap();
        assert_eq!(result, PaddingBucket::None);
    }

    #[test]
    fn padding_bucket_power_of_2_roundtrip() {
        let original = PaddingBucket::PowerOf2(10);
        let (t, v) = original.to_cbor_array();
        let result = PaddingBucket::from_cbor_array(t, v).unwrap();
        assert_eq!(result, original);
    }

    #[test]
    fn padding_bucket_custom_roundtrip() {
        let original = PaddingBucket::Custom(8192);
        let (t, v) = original.to_cbor_array();
        let result = PaddingBucket::from_cbor_array(t, v).unwrap();
        assert_eq!(result, original);
    }
}
