use std::fs;
use std::path::PathBuf;

use hydralock::format::policy::{PolicySection, PolicySectionError};
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
    policy_version: u16,
    threshold: u8,
    total_shares: u8,
    wrapper_count: u16,
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

fn error_code(error: &PolicySectionError) -> &'static str {
    match error {
        PolicySectionError::InvalidLength { .. } => "InvalidLength",
        PolicySectionError::UnsupportedPolicyVersion { .. } => "UnsupportedPolicyVersion",
        PolicySectionError::InvalidTotalShares => "InvalidTotalShares",
        PolicySectionError::InvalidThreshold { .. } => "InvalidThreshold",
        PolicySectionError::InvalidWrapperCount { .. } => "InvalidWrapperCount",
        PolicySectionError::NonZeroReserved => "NonZeroReserved",
    }
}

fn assert_accept_case(case_id: &str) {
    let expected = load_expected(case_id);
    let input = load_input(case_id);

    assert_eq!(expected.case_id, case_id);
    assert_eq!(expected.version, "1");
    assert_eq!(expected.operation, "parse_policy_section");
    assert_eq!(expected.expect, "accept");

    let parsed = PolicySection::parse(&input).expect("vector should parse");
    let expected_parsed = expected.parsed.expect("parsed section required");

    assert_eq!(parsed.policy_version, expected_parsed.policy_version);
    assert_eq!(parsed.threshold, expected_parsed.threshold);
    assert_eq!(parsed.total_shares, expected_parsed.total_shares);
    assert_eq!(parsed.wrapper_count, expected_parsed.wrapper_count);
}

fn assert_reject_case(case_id: &str) {
    let expected = load_expected(case_id);
    let input = load_input(case_id);

    assert_eq!(expected.case_id, case_id);
    assert_eq!(expected.version, "1");
    assert_eq!(expected.operation, "parse_policy_section");
    assert_eq!(expected.expect, "reject");

    let error = PolicySection::parse(&input).expect_err("vector should be rejected");
    let expected_error = expected.error.expect("error section required");
    assert_eq!(error_code(&error), expected_error.code);
}

#[test]
fn vector_policy_accept_001() {
    assert_accept_case("POLICY-ACCEPT-001");
}

#[test]
fn vector_policy_reject_001() {
    assert_reject_case("POLICY-REJECT-001");
}

#[test]
fn vector_policy_reject_002() {
    assert_reject_case("POLICY-REJECT-002");
}

#[test]
fn vector_policy_reject_003() {
    assert_reject_case("POLICY-REJECT-003");
}

#[test]
fn vector_policy_reject_004() {
    assert_reject_case("POLICY-REJECT-004");
}

#[test]
fn vector_policy_reject_005() {
    assert_reject_case("POLICY-REJECT-005");
}
