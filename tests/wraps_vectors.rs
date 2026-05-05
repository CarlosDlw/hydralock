use std::fs;
use std::path::PathBuf;

use hydralock::format::wraps::{WrapsSection, WrapsSectionError};
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
    wraps_version: u16,
    wrapper_count: usize,
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

fn error_code(error: &WrapsSectionError) -> &'static str {
    match error {
        WrapsSectionError::InvalidLength { .. } => "InvalidLength",
        WrapsSectionError::UnsupportedWrapsVersion { .. } => "UnsupportedWrapsVersion",
        WrapsSectionError::TruncatedEntryHeader { .. } => "TruncatedEntryHeader",
        WrapsSectionError::TruncatedField { field, .. } => {
            if *field == "stanza" {
                "TruncatedStanza"
            } else {
                "TruncatedWrapperId"
            }
        }
        WrapsSectionError::InvalidWrapperCount { .. } => "InvalidWrapperCount",
        WrapsSectionError::EmptyWrapperId { .. } => "EmptyWrapperId",
        WrapsSectionError::DuplicateWrapperId => "DuplicateWrapperId",
        WrapsSectionError::LengthOverflow => "LengthOverflow",
    }
}

fn assert_accept_case(case_id: &str) {
    let expected = load_expected(case_id);
    let input = load_input(case_id);

    assert_eq!(expected.case_id, case_id);
    assert_eq!(expected.version, "1");
    assert_eq!(expected.operation, "parse_wraps_section");
    assert_eq!(expected.expect, "accept");

    let parsed = WrapsSection::parse(&input).expect("vector should parse");
    let expected_parsed = expected.parsed.expect("parsed section required");

    assert_eq!(parsed.wraps_version, expected_parsed.wraps_version);
    assert_eq!(parsed.wrappers.len(), expected_parsed.wrapper_count);
}

fn assert_reject_case(case_id: &str) {
    let expected = load_expected(case_id);
    let input = load_input(case_id);

    assert_eq!(expected.case_id, case_id);
    assert_eq!(expected.version, "1");
    assert_eq!(expected.operation, "parse_wraps_section");
    assert_eq!(expected.expect, "reject");

    let error = WrapsSection::parse(&input).expect_err("vector should be rejected");
    let expected_error = expected.error.expect("error section required");
    assert_eq!(error_code(&error), expected_error.code);
}

#[test]
fn vector_wraps_accept_001() {
    assert_accept_case("WRAPS-ACCEPT-001");
}

#[test]
fn vector_wraps_reject_001() {
    assert_reject_case("WRAPS-REJECT-001");
}

#[test]
fn vector_wraps_reject_002() {
    assert_reject_case("WRAPS-REJECT-002");
}

#[test]
fn vector_wraps_reject_003() {
    assert_reject_case("WRAPS-REJECT-003");
}

#[test]
fn vector_wraps_reject_004() {
    assert_reject_case("WRAPS-REJECT-004");
}
