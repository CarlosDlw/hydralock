use std::fs;
use std::path::PathBuf;

use hydralock::format::footer::{FooterSection, FooterSectionError};
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
    footer_version: u16,
    flags: u16,
    manifest_root_len: usize,
    auth_tag_len: usize,
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

fn error_code(error: &FooterSectionError) -> &'static str {
    match error {
        FooterSectionError::InvalidLength { .. } => "InvalidLength",
        FooterSectionError::UnsupportedFooterVersion { .. } => "UnsupportedFooterVersion",
        FooterSectionError::NonZeroReserved => "NonZeroReserved",
        FooterSectionError::EmptyManifestRoot => "EmptyManifestRoot",
        FooterSectionError::EmptyAuthTag => "EmptyAuthTag",
        FooterSectionError::TruncatedField { field, .. } => {
            if *field == "manifest_root" {
                "TruncatedManifestRoot"
            } else {
                "TruncatedAuthTag"
            }
        }
        FooterSectionError::InvalidFooterLength { .. } => "InvalidFooterLength",
        FooterSectionError::LengthOverflow => "LengthOverflow",
    }
}

fn assert_accept_case(case_id: &str) {
    let expected = load_expected(case_id);
    let input = load_input(case_id);

    assert_eq!(expected.case_id, case_id);
    assert_eq!(expected.version, "1");
    assert_eq!(expected.operation, "parse_footer_section");
    assert_eq!(expected.expect, "accept");

    let parsed = FooterSection::parse(&input).expect("vector should parse");
    let expected_parsed = expected.parsed.expect("parsed section required");

    assert_eq!(parsed.footer_version, expected_parsed.footer_version);
    assert_eq!(parsed.flags, expected_parsed.flags);
    assert_eq!(parsed.manifest_root.len(), expected_parsed.manifest_root_len);
    assert_eq!(parsed.auth_tag.len(), expected_parsed.auth_tag_len);
}

fn assert_reject_case(case_id: &str) {
    let expected = load_expected(case_id);
    let input = load_input(case_id);

    assert_eq!(expected.case_id, case_id);
    assert_eq!(expected.version, "1");
    assert_eq!(expected.operation, "parse_footer_section");
    assert_eq!(expected.expect, "reject");

    let error = FooterSection::parse(&input).expect_err("vector should be rejected");
    let expected_error = expected.error.expect("error section required");
    assert_eq!(error_code(&error), expected_error.code);
}

#[test]
fn vector_footer_accept_001() {
    assert_accept_case("FOOTER-ACCEPT-001");
}

#[test]
fn vector_footer_reject_001() {
    assert_reject_case("FOOTER-REJECT-001");
}

#[test]
fn vector_footer_reject_002() {
    assert_reject_case("FOOTER-REJECT-002");
}

#[test]
fn vector_footer_reject_003() {
    assert_reject_case("FOOTER-REJECT-003");
}

#[test]
fn vector_footer_reject_004() {
    assert_reject_case("FOOTER-REJECT-004");
}

#[test]
fn vector_footer_reject_005() {
    assert_reject_case("FOOTER-REJECT-005");
}
