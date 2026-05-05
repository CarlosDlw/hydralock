use std::fs;
use std::path::PathBuf;

use hydralock::format::header::{FixedHeader, FixedHeaderError, MAGIC};
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
    magic: String,
    format_version_major: u16,
    format_version_minor: u16,
    suite_id: u16,
    flags: u32,
    header_len: u32,
    policy_len: u32,
    wraps_len: u32,
    metadata_len: u32,
    payload_offset: u64,
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

fn error_code(error: &FixedHeaderError) -> &'static str {
    match error {
        FixedHeaderError::InvalidLength { .. } => "InvalidLength",
        FixedHeaderError::InvalidMagic(_) => "InvalidMagic",
        FixedHeaderError::NonZeroReserved => "NonZeroReserved",
        FixedHeaderError::InvalidHeaderLengthField { .. } => "InvalidHeaderLengthField",
        FixedHeaderError::InvalidPayloadOffset { .. } => "InvalidPayloadOffset",
    }
}

fn assert_accept_case(case_id: &str) {
    let expected = load_expected(case_id);
    let input = load_input(case_id);

    assert_eq!(expected.case_id, case_id);
    assert_eq!(expected.version, "1");
    assert_eq!(expected.operation, "parse_fixed_header");
    assert_eq!(expected.expect, "accept");

    let parsed = FixedHeader::parse(&input).expect("vector should parse");
    let expected_parsed = expected.parsed.expect("parsed section required");

    assert_eq!(expected_parsed.magic.as_bytes(), &MAGIC);
    assert_eq!(parsed.format_version_major, expected_parsed.format_version_major);
    assert_eq!(parsed.format_version_minor, expected_parsed.format_version_minor);
    assert_eq!(parsed.suite_id, expected_parsed.suite_id);
    assert_eq!(parsed.flags, expected_parsed.flags);
    assert_eq!(parsed.header_len, expected_parsed.header_len);
    assert_eq!(parsed.policy_len, expected_parsed.policy_len);
    assert_eq!(parsed.wraps_len, expected_parsed.wraps_len);
    assert_eq!(parsed.metadata_len, expected_parsed.metadata_len);
    assert_eq!(parsed.payload_offset, expected_parsed.payload_offset);
}

fn assert_reject_case(case_id: &str) {
    let expected = load_expected(case_id);
    let input = load_input(case_id);

    assert_eq!(expected.case_id, case_id);
    assert_eq!(expected.version, "1");
    assert_eq!(expected.operation, "parse_fixed_header");
    assert_eq!(expected.expect, "reject");

    let error = FixedHeader::parse(&input).expect_err("vector should be rejected");
    let expected_error = expected.error.expect("error section required");
    assert_eq!(error_code(&error), expected_error.code);
}

#[test]
fn vector_fh_accept_001() {
    assert_accept_case("FH-ACCEPT-001");
}

#[test]
fn vector_fh_reject_001() {
    assert_reject_case("FH-REJECT-001");
}

#[test]
fn vector_fh_reject_002() {
    assert_reject_case("FH-REJECT-002");
}

#[test]
fn vector_fh_reject_003() {
    assert_reject_case("FH-REJECT-003");
}
