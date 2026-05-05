use std::fs;
use std::path::PathBuf;

use hydralock::format::metadata::{MetadataSection, MetadataSectionError};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct Expected {
    case_id: String,
    version: String,
    operation: String,
    expect: String,
    parsed: Option<Parsed>,
    error: Option<ExpectedError>,
}

#[derive(Debug, Deserialize)]
struct Parsed {
    metadata_version: u16,
    ciphertext_len: usize,
}

#[derive(Debug, Deserialize)]
struct ExpectedError {
    code: String,
}

fn vectors_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("vectors")
}

fn load_expected(case_id: &str) -> Expected {
    let expected_path = vectors_root().join(case_id).join("expected.json");
    let raw = fs::read_to_string(expected_path).expect("expected.json must exist");
    serde_json::from_str(&raw).expect("expected.json must be valid")
}

fn load_input(case_id: &str) -> Vec<u8> {
    let input_path = vectors_root().join(case_id).join("input.hlock");
    fs::read(input_path).expect("input.hlock must exist")
}

fn error_code(error: &MetadataSectionError) -> &'static str {
    match error {
        MetadataSectionError::InvalidLength { .. } => "InvalidLength",
        MetadataSectionError::UnsupportedMetadataVersion { .. } => "UnsupportedMetadataVersion",
        MetadataSectionError::NonZeroReserved => "NonZeroReserved",
        MetadataSectionError::EmptyCiphertext => "EmptyCiphertext",
        MetadataSectionError::TruncatedCiphertext { .. } => "TruncatedCiphertext",
        MetadataSectionError::InvalidCiphertextLength { .. } => "InvalidCiphertextLength",
        MetadataSectionError::LengthOverflow => "LengthOverflow",
    }
}

fn assert_accept_case(case_id: &str) {
    let expected = load_expected(case_id);
    let input = load_input(case_id);

    assert_eq!(expected.case_id, case_id);
    assert_eq!(expected.version, "1");
    assert_eq!(expected.operation, "parse_metadata_section");
    assert_eq!(expected.expect, "accept");

    let parsed = MetadataSection::parse(&input).expect("vector should parse");
    let expected_parsed = expected.parsed.expect("parsed section required");

    assert_eq!(parsed.metadata_version, expected_parsed.metadata_version);
    assert_eq!(parsed.ciphertext.len(), expected_parsed.ciphertext_len);
}

fn assert_reject_case(case_id: &str) {
    let expected = load_expected(case_id);
    let input = load_input(case_id);

    assert_eq!(expected.case_id, case_id);
    assert_eq!(expected.version, "1");
    assert_eq!(expected.operation, "parse_metadata_section");
    assert_eq!(expected.expect, "reject");

    let error = MetadataSection::parse(&input).expect_err("vector should be rejected");
    let expected_error = expected.error.expect("error section required");
    assert_eq!(error_code(&error), expected_error.code);
}

#[test]
fn vector_metadata_accept_001() {
    assert_accept_case("METADATA-ACCEPT-001");
}

#[test]
fn vector_metadata_reject_001() {
    assert_reject_case("METADATA-REJECT-001");
}

#[test]
fn vector_metadata_reject_002() {
    assert_reject_case("METADATA-REJECT-002");
}

#[test]
fn vector_metadata_reject_003() {
    assert_reject_case("METADATA-REJECT-003");
}

#[test]
fn vector_metadata_reject_004() {
    assert_reject_case("METADATA-REJECT-004");
}

#[test]
fn vector_metadata_reject_005() {
    assert_reject_case("METADATA-REJECT-005");
}
