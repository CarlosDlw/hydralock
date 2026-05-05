use std::fs;
use std::path::PathBuf;

use hydralock::format::payload::{PayloadSection, PayloadSectionError};
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
    payload_version: u16,
    flags: u16,
    chunk_size: u32,
    tag_size: u32,
    chunk_count: usize,
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

fn error_code(error: &PayloadSectionError) -> &'static str {
    match error {
        PayloadSectionError::InvalidLength { .. } => "InvalidLength",
        PayloadSectionError::UnsupportedPayloadVersion { .. } => "UnsupportedPayloadVersion",
        PayloadSectionError::NonZeroReserved => "NonZeroReserved",
        PayloadSectionError::ZeroChunkSize => "ZeroChunkSize",
        PayloadSectionError::ZeroTagSize => "ZeroTagSize",
        PayloadSectionError::TruncatedChunkHeader { .. } => "TruncatedChunkHeader",
        PayloadSectionError::TruncatedCiphertext { .. } => "TruncatedCiphertext",
        PayloadSectionError::TruncatedTag { .. } => "TruncatedTag",
        PayloadSectionError::ZeroCiphertextLen { .. } => "ZeroCiphertextLen",
        PayloadSectionError::ChunkSizeViolation { .. } => "ChunkSizeViolation",
        PayloadSectionError::NoFinalChunk => "NoFinalChunk",
        PayloadSectionError::FinalNotLast { .. } => "FinalNotLast",
        PayloadSectionError::TrailingBytes => "TrailingBytes",
        PayloadSectionError::LengthOverflow => "LengthOverflow",
    }
}

fn assert_accept_case(case_id: &str) {
    let expected = load_expected(case_id);
    let input = load_input(case_id);

    assert_eq!(expected.case_id, case_id);
    assert_eq!(expected.version, "1");
    assert_eq!(expected.operation, "parse_payload_section");
    assert_eq!(expected.expect, "accept");

    let parsed = PayloadSection::parse(&input).expect("vector should parse");
    let expected_parsed = expected.parsed.expect("parsed section required");

    assert_eq!(parsed.payload_version, expected_parsed.payload_version);
    assert_eq!(parsed.flags, expected_parsed.flags);
    assert_eq!(parsed.chunk_size, expected_parsed.chunk_size);
    assert_eq!(parsed.tag_size, expected_parsed.tag_size);
    assert_eq!(parsed.chunks.len(), expected_parsed.chunk_count);
}

fn assert_reject_case(case_id: &str) {
    let expected = load_expected(case_id);
    let input = load_input(case_id);

    assert_eq!(expected.case_id, case_id);
    assert_eq!(expected.version, "1");
    assert_eq!(expected.operation, "parse_payload_section");
    assert_eq!(expected.expect, "reject");

    let error = PayloadSection::parse(&input).expect_err("vector should be rejected");
    let expected_error = expected.error.expect("error section required");
    assert_eq!(error_code(&error), expected_error.code);
}

#[test]
fn vector_payload_accept_001() {
    assert_accept_case("PAYLOAD-ACCEPT-001");
}

#[test]
fn vector_payload_reject_001() {
    assert_reject_case("PAYLOAD-REJECT-001");
}

#[test]
fn vector_payload_reject_002() {
    assert_reject_case("PAYLOAD-REJECT-002");
}

#[test]
fn vector_payload_reject_003() {
    assert_reject_case("PAYLOAD-REJECT-003");
}

#[test]
fn vector_payload_reject_004() {
    assert_reject_case("PAYLOAD-REJECT-004");
}

#[test]
fn vector_payload_reject_005() {
    assert_reject_case("PAYLOAD-REJECT-005");
}
