/// Differential test vector harness.
///
/// Loads the binary containers in vectors/DIFF-*/ (committed to the repo)
/// and validates that the Rust implementation produces the expected outputs
/// for decrypt, inspect, and verify.
///
/// A second implementation in any language must pass the same set of vectors
/// by reading container.hlock + key_material.json and producing outputs that
/// match expected.json.
use std::fs;
use std::path::PathBuf;

use hydralock::format::header::{FIXED_HEADER_LEN, FixedHeader};
use hydralock::format::policy::PolicySection;
use hydralock::format::wraps::WrapsSection;
use hydralock::ops::decrypt::{OpenKeyMaterial, decrypt};
use hydralock::wrapper::mlkem768_x25519::{MLKEM768_SEED_LEN, MlKem768X25519RecipientSecretKey};
use serde::Deserialize;

fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("vectors")
}

fn load_bytes(case_id: &str, filename: &str) -> Vec<u8> {
    let path = vectors_dir().join(case_id).join(filename);
    fs::read(&path).unwrap_or_else(|e| panic!("failed to read {}/{filename}: {e}", case_id))
}

fn load_json<T: for<'de> Deserialize<'de>>(case_id: &str, filename: &str) -> T {
    let path = vectors_dir().join(case_id).join(filename);
    let raw = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed to read {}/{filename}: {e}", case_id));
    serde_json::from_str(&raw)
        .unwrap_or_else(|e| panic!("failed to parse {}/{filename}: {e}", case_id))
}

#[derive(Debug, Deserialize)]
struct KeyMaterialJson {
    wrapper_type: String,
    #[serde(default)]
    passphrase_hex: Option<String>,
    #[serde(default)]
    recipient_sk_hex: Option<String>,
    #[serde(default)]
    x25519_sk_hex: Option<String>,
    #[serde(default)]
    mlkem_dk_seed_hex: Option<String>,
}

#[derive(Debug, Deserialize)]
struct InspectFields {
    format_version_major: u16,
    format_version_minor: u16,
    suite_id: u16,
    wrapper_count: usize,
    wrapper_types: Vec<String>,
    threshold: u8,
    total_shares: u8,
    total_container_bytes: usize,
    header_hash: String,
}

#[derive(Debug, Deserialize)]
struct ExpectedJson {
    case_id: String,
    plaintext_hex: String,
    logical_name: String,
    inspect: InspectFields,
    verify: VerifyExpected,
}

#[derive(Debug, Deserialize)]
struct VerifyExpected {
    result: String,
}

fn run_differential_vector(case_id: &str) {
    let container = load_bytes(case_id, "container.hlock");
    let plaintext_expected = load_bytes(case_id, "plaintext.bin");
    let km: KeyMaterialJson = load_json(case_id, "key_material.json");
    let expected: ExpectedJson = load_json(case_id, "expected.json");

    // ── 0. Sanity: case_id in expected.json must match the directory name ────
    assert_eq!(
        expected.case_id, case_id,
        "expected.json case_id does not match directory name",
    );

    // ── 1. Verify expected.json is self-consistent with plaintext.bin ────────
    assert_eq!(
        hex::decode(&expected.plaintext_hex).expect("plaintext_hex must be valid hex"),
        plaintext_expected,
        "[{case_id}] expected.json plaintext_hex does not match plaintext.bin",
    );

    // ── 2. Decrypt ───────────────────────────────────────────────────────────
    let key_material = build_key_material(&km);
    let result = decrypt(&container, &key_material)
        .unwrap_or_else(|e| panic!("[{case_id}] decrypt failed: {e}"));

    assert_eq!(
        result.plaintext, plaintext_expected,
        "[{case_id}] decrypted plaintext does not match plaintext.bin",
    );
    assert_eq!(
        result.metadata.logical_name.as_deref(),
        Some(expected.logical_name.as_str()),
        "[{case_id}] logical_name mismatch after decrypt",
    );

    // ── 3. Inspect (structural fields from plaintext sections) ──────────────
    assert!(
        container.len() >= FIXED_HEADER_LEN,
        "[{case_id}] container too short for fixed header",
    );

    let fh = FixedHeader::parse(&container[..FIXED_HEADER_LEN])
        .unwrap_or_else(|e| panic!("[{case_id}] fixed header parse failed: {e}"));

    assert_eq!(
        fh.format_version_major, expected.inspect.format_version_major,
        "[{case_id}] format_version_major mismatch",
    );
    assert_eq!(
        fh.format_version_minor, expected.inspect.format_version_minor,
        "[{case_id}] format_version_minor mismatch",
    );
    assert_eq!(
        fh.suite_id, expected.inspect.suite_id,
        "[{case_id}] suite_id mismatch",
    );

    let header_hash = hex::encode(blake3::hash(&container[..FIXED_HEADER_LEN]).as_bytes());
    assert_eq!(
        header_hash, expected.inspect.header_hash,
        "[{case_id}] header_hash mismatch — container was regenerated without committing",
    );

    let policy_end = FIXED_HEADER_LEN + fh.policy_len as usize;
    let wraps_end = policy_end + fh.wraps_len as usize;

    let policy = PolicySection::parse(&container[FIXED_HEADER_LEN..policy_end])
        .unwrap_or_else(|e| panic!("[{case_id}] policy parse failed: {e:?}"));
    let wraps = WrapsSection::parse(&container[policy_end..wraps_end])
        .unwrap_or_else(|e| panic!("[{case_id}] wraps parse failed: {e}"));

    assert_eq!(
        policy.threshold, expected.inspect.threshold,
        "[{case_id}] threshold mismatch",
    );
    assert_eq!(
        policy.total_shares, expected.inspect.total_shares,
        "[{case_id}] total_shares mismatch",
    );
    assert_eq!(
        wraps.wrappers.len(),
        expected.inspect.wrapper_count,
        "[{case_id}] wrapper_count mismatch",
    );

    let actual_wrapper_types: Vec<String> = wraps
        .wrappers
        .iter()
        .map(|w| {
            use hydralock::wrapper::mlkem768_x25519::WRAPPER_TYPE_MLKEM768_X25519;
            use hydralock::wrapper::passargon2id::WRAPPER_TYPE_PASS_ARGON2ID;
            use hydralock::wrapper::x25519::WRAPPER_TYPE_X25519;
            match w.wrapper_type {
                WRAPPER_TYPE_PASS_ARGON2ID => "PASS-ARGON2ID".to_string(),
                WRAPPER_TYPE_X25519 => "X25519".to_string(),
                WRAPPER_TYPE_MLKEM768_X25519 => "MLKEM768-X25519".to_string(),
                t => format!("UNKNOWN-0x{t:04x}"),
            }
        })
        .collect();
    assert_eq!(
        actual_wrapper_types, expected.inspect.wrapper_types,
        "[{case_id}] wrapper_types mismatch",
    );
    assert_eq!(
        container.len(),
        expected.inspect.total_container_bytes,
        "[{case_id}] total_container_bytes mismatch — container was regenerated without committing",
    );

    // ── 4. Verify ────────────────────────────────────────────────────────────
    // decrypt() internally calls verify_container_no_decrypt and verifies the
    // footer auth tag; if we reached this point the full chain is authenticated.
    assert_eq!(
        expected.verify.result, "valid",
        "[{case_id}] expected.json verify.result must be 'valid'",
    );
}

fn build_key_material(km: &KeyMaterialJson) -> OpenKeyMaterial {
    match km.wrapper_type.as_str() {
        "PassArgon2id" => {
            let hex = km
                .passphrase_hex
                .as_deref()
                .expect("passphrase_hex required for PassArgon2id");
            let bytes = hex::decode(hex).expect("passphrase_hex must be valid hex");
            OpenKeyMaterial::Passphrase(bytes)
        }
        "X25519" => {
            let hex = km
                .recipient_sk_hex
                .as_deref()
                .expect("recipient_sk_hex required for X25519");
            let bytes = hex::decode(hex).expect("recipient_sk_hex must be valid hex");
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            OpenKeyMaterial::X25519SecretKey(arr)
        }
        "MlKem768X25519" => {
            let x_hex = km
                .x25519_sk_hex
                .as_deref()
                .expect("x25519_sk_hex required for MlKem768X25519");
            let m_hex = km
                .mlkem_dk_seed_hex
                .as_deref()
                .expect("mlkem_dk_seed_hex required for MlKem768X25519");
            let x_bytes = hex::decode(x_hex).expect("x25519_sk_hex must be valid hex");
            let m_bytes = hex::decode(m_hex).expect("mlkem_dk_seed_hex must be valid hex");
            let mut x_arr = [0u8; 32];
            let mut m_arr = [0u8; MLKEM768_SEED_LEN];
            x_arr.copy_from_slice(&x_bytes);
            m_arr.copy_from_slice(&m_bytes);
            OpenKeyMaterial::MlKem768X25519SecretKey(MlKem768X25519RecipientSecretKey::new(
                x_arr, m_arr,
            ))
        }
        t => panic!("unknown wrapper_type in key_material.json: {t}"),
    }
}

#[test]
fn differential_pass_001() {
    run_differential_vector("DIFF-PASS-001");
}

#[test]
fn differential_x25519_001() {
    run_differential_vector("DIFF-X25519-001");
}

#[test]
fn differential_mlkem_001() {
    run_differential_vector("DIFF-MLKEM-001");
}
