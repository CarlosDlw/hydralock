/// Vector generator for HydraLock v1 official test vectors.
///
/// Run with:
///   cargo test --test gen_vectors -- generate_all_vectors --include-ignored
///
/// This overwrites vectors/ entries for every case generated here.
/// Existing vectors not covered by this generator are left untouched.
use std::fs;
use std::path::Path;

use hydralock::crypto::aad::WrapperAadInput;
use hydralock::crypto::password::Argon2Profile;
use hydralock::crypto::secret::SecretKey32;
use hydralock::format::header::{FIXED_HEADER_LEN, FixedHeader};
use hydralock::format::metadata_plaintext::PaddingBucket;
use hydralock::format::payload::{CHUNK_ENTRY_HEADER_LEN, PAYLOAD_HEADER_LEN};
use hydralock::format::policy::PolicySection;
use hydralock::format::wraps::{WrapperEntry, WrapsSection};
use hydralock::ops::decrypt::{
    OpenKeyMaterial, decrypt, extract_file_uuid, scan_payload_end, try_unwrap_fmk,
};
use hydralock::ops::encrypt::{
    DEFAULT_CHUNK_SIZE, DEFAULT_EPOCH_SIZE, EncryptInput, WrapperSpec, encrypt,
};
use hydralock::ops::rewrap::{compute_rewrap_header_hash, rewrap_container};
use hydralock::wrapper::mlkem768_x25519::{
    MLKEM768_SEED_LEN, MlKem768X25519RecipientPublicKey, MlKem768X25519RecipientSecretKey,
    WRAPPER_TYPE_MLKEM768_X25519,
};
use hydralock::wrapper::passargon2id::WRAPPER_TYPE_PASS_ARGON2ID;
use hydralock::wrapper::threshold::{
    SHARE_STANZA_LEN, WRAPPER_TYPE_THRESHOLD, seal as threshold_seal,
};
use hydralock::wrapper::x25519::WRAPPER_TYPE_X25519;
use rand::rngs::OsRng;
use serde_json::{Value, json};

// ── Helpers ──────────────────────────────────────────────────────────────────

fn vectors_base() -> &'static Path {
    Path::new("vectors")
}

fn write_vector_file(case_id: &str, filename: &str, data: &[u8]) {
    let dir = vectors_base().join(case_id);
    fs::create_dir_all(&dir).expect("create vector dir");
    fs::write(dir.join(filename), data).expect("write vector file");
}

fn write_json_file(case_id: &str, filename: &str, v: &Value) {
    let pretty = serde_json::to_string_pretty(v).expect("json serialize");
    write_vector_file(case_id, filename, pretty.as_bytes());
}

/// Parse the fixed header + policy + wraps and produce the "inspect" JSON object.
fn inspect_json(container: &[u8]) -> Value {
    let fh = FixedHeader::parse(&container[..FIXED_HEADER_LEN]).expect("parse fh");
    let policy_start = FIXED_HEADER_LEN;
    let policy_end = policy_start + fh.policy_len as usize;
    let wraps_start = policy_end;
    let wraps_end = wraps_start + fh.wraps_len as usize;
    let policy =
        hydralock::format::policy::PolicySection::parse(&container[policy_start..policy_end])
            .expect("parse policy");
    let wraps = WrapsSection::parse(&container[wraps_start..wraps_end]).expect("parse wraps");
    let header_hash = hex::encode(blake3::hash(&container[..FIXED_HEADER_LEN]).as_bytes());

    let wrapper_types: Vec<&str> = wraps
        .wrappers
        .iter()
        .map(|w| match w.wrapper_type {
            WRAPPER_TYPE_PASS_ARGON2ID => "PASS-ARGON2ID",
            WRAPPER_TYPE_X25519 => "X25519",
            WRAPPER_TYPE_MLKEM768_X25519 => "MLKEM768-X25519",
            WRAPPER_TYPE_THRESHOLD => "THRESHOLD",
            _ => "UNKNOWN",
        })
        .collect();

    json!({
        "format_version_major": fh.format_version_major,
        "format_version_minor": fh.format_version_minor,
        "suite_id": fh.suite_id,
        "header_hash": header_hash,
        "threshold": policy.threshold,
        "total_shares": policy.total_shares,
        "wrapper_count": policy.wrapper_count,
        "wrapper_types": wrapper_types,
        "total_container_bytes": container.len(),
    })
}

/// Encrypt with passphrase and return the container bytes.
fn encrypt_pass(
    plaintext: &[u8],
    passphrase: &[u8],
    logical_name: &str,
    chunk_size: u32,
    epoch_size: u32,
    padding: PaddingBucket,
) -> Vec<u8> {
    let mut rng = OsRng;
    let wrappers = vec![WrapperSpec::PassArgon2id {
        passphrase: passphrase.to_vec(),
        profile: Argon2Profile::Interactive,
        wrapper_id: b"pass".to_vec(),
    }];
    let input = EncryptInput {
        plaintext,
        logical_name: Some(logical_name.to_string()),
        mime_type: None,
        created_at: Some(0),
        chunk_size,
        epoch_size,
        padding,
    };
    encrypt(&input, &wrappers, &mut rng).expect("encrypt_pass")
}

// ── §3.2 Acceptance vectors ───────────────────────────────────────────────────

fn gen_pass_accept_001() {
    // Minimal plaintext: single chunk, well below chunk_size.
    let case_id = "PASS-ACCEPT-001";
    let passphrase = b"hydralock-test-pass";
    let plaintext: &[u8] = b"hello hydralock!";

    let container = encrypt_pass(
        plaintext,
        passphrase,
        "minimal.bin",
        DEFAULT_CHUNK_SIZE,
        DEFAULT_EPOCH_SIZE,
        PaddingBucket::None,
    );

    // verify decrypt round-trips
    let result = decrypt(
        &container,
        &OpenKeyMaterial::Passphrase(passphrase.to_vec()),
    )
    .unwrap();
    assert_eq!(result.plaintext, plaintext);

    write_vector_file(case_id, "container.hlock", &container);
    write_vector_file(case_id, "plaintext.bin", plaintext);

    write_json_file(
        case_id,
        "key_material.json",
        &json!({
            "passphrase_hex": hex::encode(passphrase),
            "wrapper_id_label": "pass",
            "wrapper_type": "PassArgon2id"
        }),
    );
    write_json_file(
        case_id,
        "expected.json",
        &json!({
            "case_id": case_id,
            "version": "1",
            "wrapper_type": "PassArgon2id",
            "logical_name": "minimal.bin",
            "plaintext_hex": hex::encode(plaintext),
            "inspect": inspect_json(&container),
            "verify": { "result": "valid" }
        }),
    );
}

fn gen_pass_accept_002() {
    let case_id = "PASS-ACCEPT-002";
    let passphrase = b"hydralock-test-pass";
    let plaintext: &[u8] = &[0x42];

    let container = encrypt_pass(
        plaintext,
        passphrase,
        "one-byte.bin",
        DEFAULT_CHUNK_SIZE,
        DEFAULT_EPOCH_SIZE,
        PaddingBucket::None,
    );

    let result = decrypt(
        &container,
        &OpenKeyMaterial::Passphrase(passphrase.to_vec()),
    )
    .unwrap();
    assert_eq!(result.plaintext, plaintext);

    write_vector_file(case_id, "container.hlock", &container);
    write_vector_file(case_id, "plaintext.bin", plaintext);
    write_json_file(
        case_id,
        "key_material.json",
        &json!({
            "passphrase_hex": hex::encode(passphrase),
            "wrapper_id_label": "pass",
            "wrapper_type": "PassArgon2id"
        }),
    );
    write_json_file(
        case_id,
        "expected.json",
        &json!({
            "case_id": case_id,
            "version": "1",
            "wrapper_type": "PassArgon2id",
            "logical_name": "one-byte.bin",
            "plaintext_hex": hex::encode(plaintext),
            "inspect": inspect_json(&container),
            "verify": { "result": "valid" }
        }),
    );
}

fn gen_pass_accept_003() {
    let case_id = "PASS-ACCEPT-003";
    let passphrase = b"hydralock-test-pass";
    let plaintext: Vec<u8> = vec![0x55u8; 65536];

    let container = encrypt_pass(
        &plaintext,
        passphrase,
        "64kib.bin",
        DEFAULT_CHUNK_SIZE,
        DEFAULT_EPOCH_SIZE,
        PaddingBucket::None,
    );

    let result = decrypt(
        &container,
        &OpenKeyMaterial::Passphrase(passphrase.to_vec()),
    )
    .unwrap();
    assert_eq!(result.plaintext, plaintext);

    write_vector_file(case_id, "container.hlock", &container);
    write_vector_file(case_id, "plaintext.bin", &plaintext);
    write_json_file(
        case_id,
        "key_material.json",
        &json!({
            "passphrase_hex": hex::encode(passphrase),
            "wrapper_id_label": "pass",
            "wrapper_type": "PassArgon2id"
        }),
    );
    write_json_file(
        case_id,
        "expected.json",
        &json!({
            "case_id": case_id,
            "version": "1",
            "wrapper_type": "PassArgon2id",
            "logical_name": "64kib.bin",
            "plaintext_hex": hex::encode(&plaintext),
            "inspect": inspect_json(&container),
            "verify": { "result": "valid" }
        }),
    );
}

fn gen_pass_accept_004() {
    // Multiple epochs: chunk_size=64, epoch_size=2 → 512 bytes → 8 chunks, 4 epochs.
    let case_id = "PASS-ACCEPT-004";
    let passphrase = b"hydralock-test-pass";
    let plaintext: Vec<u8> = (0u8..=255).cycle().take(512).collect();

    let container = encrypt_pass(
        &plaintext,
        passphrase,
        "multi-epoch.bin",
        64,
        2,
        PaddingBucket::None,
    );

    let result = decrypt(
        &container,
        &OpenKeyMaterial::Passphrase(passphrase.to_vec()),
    )
    .unwrap();
    assert_eq!(result.plaintext, plaintext);

    write_vector_file(case_id, "container.hlock", &container);
    write_vector_file(case_id, "plaintext.bin", &plaintext);
    write_json_file(
        case_id,
        "key_material.json",
        &json!({
            "passphrase_hex": hex::encode(passphrase),
            "wrapper_id_label": "pass",
            "wrapper_type": "PassArgon2id",
            "chunk_size": 64,
            "epoch_size": 2
        }),
    );
    write_json_file(
        case_id,
        "expected.json",
        &json!({
            "case_id": case_id,
            "version": "1",
            "wrapper_type": "PassArgon2id",
            "logical_name": "multi-epoch.bin",
            "plaintext_hex": hex::encode(&plaintext),
            "notes": "chunk_size=64 epoch_size=2 → 8 chunks across 4 epochs",
            "inspect": inspect_json(&container),
            "verify": { "result": "valid" }
        }),
    );
}

fn gen_x25519_accept_001() {
    let case_id = "X25519-ACCEPT-001";
    let sk_bytes: [u8; 32] = [0xaau8; 32];
    let sk = x25519_dalek::StaticSecret::from(sk_bytes);
    let pk: [u8; 32] = x25519_dalek::PublicKey::from(&sk).to_bytes();

    let plaintext = b"hydralock x25519 acceptance test vector";
    let mut rng = OsRng;
    let wrappers = vec![WrapperSpec::X25519 {
        recipient_pk: pk,
        wrapper_id: b"x25519".to_vec(),
    }];
    let input = EncryptInput {
        plaintext,
        logical_name: Some("x25519-test.bin".to_string()),
        mime_type: None,
        created_at: Some(0),
        chunk_size: DEFAULT_CHUNK_SIZE,
        epoch_size: DEFAULT_EPOCH_SIZE,
        padding: PaddingBucket::None,
    };
    let container = encrypt(&input, &wrappers, &mut rng).expect("encrypt x25519");
    let result = decrypt(&container, &OpenKeyMaterial::X25519SecretKey(sk_bytes)).unwrap();
    assert_eq!(result.plaintext, plaintext);

    write_vector_file(case_id, "container.hlock", &container);
    write_vector_file(case_id, "plaintext.bin", plaintext);
    write_json_file(
        case_id,
        "key_material.json",
        &json!({
            "recipient_sk_hex": hex::encode(sk_bytes),
            "recipient_pk_hex": hex::encode(pk),
            "wrapper_id_label": "x25519",
            "wrapper_type": "X25519"
        }),
    );
    write_json_file(
        case_id,
        "expected.json",
        &json!({
            "case_id": case_id,
            "version": "1",
            "wrapper_type": "X25519",
            "logical_name": "x25519-test.bin",
            "plaintext_hex": hex::encode(plaintext),
            "inspect": inspect_json(&container),
            "verify": { "result": "valid" }
        }),
    );
}

fn gen_mlkem_accept_001() {
    let case_id = "MLKEM-ACCEPT-001";
    // Fixed seed for reproducibility: x25519_sk=[0x10;32], mlkem_seed=[0x11;64]
    let x25519_sk = [0x10u8; 32];
    let mlkem_seed = [0x11u8; MLKEM768_SEED_LEN];
    let sk = MlKem768X25519RecipientSecretKey::new(x25519_sk, mlkem_seed);
    let pk: MlKem768X25519RecipientPublicKey = sk.public_key();

    let x25519_pk: [u8; 32] =
        x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(x25519_sk)).to_bytes();

    let plaintext = b"hydralock mlkem-768+x25519 acceptance test vector";
    let mut rng = OsRng;
    let wrappers = vec![WrapperSpec::MlKem768X25519 {
        recipient_pk: Box::new(pk),
        wrapper_id: b"mlkem".to_vec(),
    }];
    let input = EncryptInput {
        plaintext,
        logical_name: Some("mlkem-test.bin".to_string()),
        mime_type: None,
        created_at: Some(0),
        chunk_size: DEFAULT_CHUNK_SIZE,
        epoch_size: DEFAULT_EPOCH_SIZE,
        padding: PaddingBucket::None,
    };
    let container = encrypt(&input, &wrappers, &mut rng).expect("encrypt mlkem");
    let result = decrypt(&container, &OpenKeyMaterial::MlKem768X25519SecretKey(sk)).unwrap();
    assert_eq!(result.plaintext, plaintext);

    let sk2 = MlKem768X25519RecipientSecretKey::new(x25519_sk, mlkem_seed);
    write_vector_file(case_id, "container.hlock", &container);
    write_vector_file(case_id, "plaintext.bin", plaintext);
    write_json_file(
        case_id,
        "key_material.json",
        &json!({
            "x25519_sk_hex": hex::encode(x25519_sk),
            "x25519_pk_hex": hex::encode(x25519_pk),
            "mlkem_dk_seed_hex": hex::encode(mlkem_seed),
            "recipient_pk_mlkem_ek_hex": hex::encode(sk2.public_key().mlkem768_ek_bytes),
            "wrapper_id_label": "mlkem",
            "wrapper_type": "MlKem768X25519"
        }),
    );
    write_json_file(
        case_id,
        "expected.json",
        &json!({
            "case_id": case_id,
            "version": "1",
            "wrapper_type": "MlKem768X25519",
            "logical_name": "mlkem-test.bin",
            "plaintext_hex": hex::encode(plaintext),
            "inspect": inspect_json(&container),
            "verify": { "result": "valid" }
        }),
    );
}

fn gen_thresh_accept_001() {
    let case_id = "THRESH-ACCEPT-001";
    let passphrase = b"hydralock-thresh-pass";
    let plaintext = b"hydralock 2-of-3 threshold acceptance test vector";

    // 1. Encrypt with passphrase to get a base container and extract FMK.
    let base_container = encrypt_pass(
        plaintext,
        passphrase,
        "thresh-test.bin",
        DEFAULT_CHUNK_SIZE,
        DEFAULT_EPOCH_SIZE,
        PaddingBucket::None,
    );

    // 2. Extract file_uuid from the container.
    let fh = FixedHeader::parse(&base_container[..FIXED_HEADER_LEN]).unwrap();
    let wraps_start = FIXED_HEADER_LEN + fh.policy_len as usize;
    let wraps_end = wraps_start + fh.wraps_len as usize;
    let wraps = WrapsSection::parse(&base_container[wraps_start..wraps_end]).unwrap();
    let file_uuid = extract_file_uuid(&wraps.wrappers).unwrap();

    // 3. Recover FMK using passphrase.
    let header_hash: [u8; 32] = *blake3::hash(&base_container[..FIXED_HEADER_LEN]).as_bytes();
    let fmk = try_unwrap_fmk(
        &wraps.wrappers,
        &OpenKeyMaterial::Passphrase(passphrase.to_vec()),
        fh.suite_id,
        &header_hash,
        &file_uuid,
    )
    .unwrap();

    // 4. Fixed k_share_root for this vector.
    let k_share_root_bytes: [u8; 32] = [0xCCu8; 32];
    let k_share_root = SecretKey32::from_bytes(k_share_root_bytes);

    // 5. Compute what the new header_hash will be for 3 threshold wrappers (t=2, n=3).
    // label = "share-N" → 7 bytes; wrapper_id = file_uuid (16) + label = 23 bytes
    // stanza = ShareStanza = 65 bytes
    let label_len = 7usize; // "share-1", "share-2", "share-3"
    let entry_sizes: Vec<(usize, usize)> =
        (0..3).map(|_| (16 + label_len, SHARE_STANZA_LEN)).collect();
    let new_policy = PolicySection {
        policy_version: 1,
        threshold: 2,
        total_shares: 3,
        wrapper_count: 3,
    };
    let new_header_hash = compute_rewrap_header_hash(&fh, &new_policy, &entry_sizes).unwrap();

    // 6. Build outer_aad for threshold seal (wrapper_index=0 for all shares).
    let outer_aad = WrapperAadInput {
        suite_id: fh.suite_id,
        wrapper_index: 0,
        file_uuid,
        header_hash: new_header_hash,
    }
    .encode();

    // 7. Seal: Shamir-split FMK into 3 shares, wrap with k_share_root.
    let fmk_key = SecretKey32::from_bytes(*hydralock::crypto::secret::fmk_expose(&fmk));
    let mut rng = OsRng;
    let stanzas = threshold_seal(&fmk_key, 2, 3, &k_share_root, &outer_aad, &mut rng).unwrap();

    // 8. Build WrapperEntry for each share.
    let new_wrappers: Vec<WrapperEntry> = stanzas
        .iter()
        .enumerate()
        .map(|(i, s)| {
            let label = format!("share-{}", i + 1);
            let mut wire_id = Vec::with_capacity(16 + label.len());
            wire_id.extend_from_slice(&file_uuid);
            wire_id.extend_from_slice(label.as_bytes());
            WrapperEntry {
                wrapper_type: WRAPPER_TYPE_THRESHOLD,
                wrapper_flags: 0,
                wrapper_id: wire_id,
                stanza: s.encode().to_vec(),
            }
        })
        .collect();

    // 9. Rewrap the container with threshold wrappers.
    let container =
        rewrap_container(&base_container, &fmk, &file_uuid, new_policy, new_wrappers).unwrap();

    // 10. Verify decrypt with k_share_root (all 3 shares available).
    let result = decrypt(
        &container,
        &OpenKeyMaterial::ThresholdShareRoot(k_share_root_bytes),
    )
    .unwrap();
    assert_eq!(result.plaintext, plaintext.as_slice());

    write_vector_file(case_id, "container.hlock", &container);
    write_vector_file(case_id, "plaintext.bin", plaintext);
    write_json_file(
        case_id,
        "key_material.json",
        &json!({
            "k_share_root_hex": hex::encode(k_share_root_bytes),
            "threshold_t": 2,
            "total_n": 3,
            "wrapper_type": "Threshold",
            "note": "provide any 2 of 3 THRESHOLD stanzas to reconstruct FMK"
        }),
    );
    write_json_file(
        case_id,
        "expected.json",
        &json!({
            "case_id": case_id,
            "version": "1",
            "wrapper_type": "Threshold",
            "logical_name": "thresh-test.bin",
            "plaintext_hex": hex::encode(plaintext),
            "inspect": inspect_json(&container),
            "verify": { "result": "valid" }
        }),
    );
}

fn gen_pass_meta_001() {
    // Passphrase + UTF-8 logical name with non-ASCII characters.
    let case_id = "PASS-META-001";
    let passphrase = b"hydralock-test-pass";
    let plaintext = b"metadata utf-8 test payload";
    let logical_name = "μεταδεδομένα.bin"; // Greek UTF-8

    let mut rng = OsRng;
    let wrappers = vec![WrapperSpec::PassArgon2id {
        passphrase: passphrase.to_vec(),
        profile: Argon2Profile::Interactive,
        wrapper_id: b"pass".to_vec(),
    }];
    let input = EncryptInput {
        plaintext,
        logical_name: Some(logical_name.to_string()),
        mime_type: Some("application/octet-stream".to_string()),
        created_at: Some(1_700_000_000),
        chunk_size: DEFAULT_CHUNK_SIZE,
        epoch_size: DEFAULT_EPOCH_SIZE,
        padding: PaddingBucket::None,
    };
    let container = encrypt(&input, &wrappers, &mut rng).unwrap();
    let result = decrypt(
        &container,
        &OpenKeyMaterial::Passphrase(passphrase.to_vec()),
    )
    .unwrap();
    assert_eq!(result.plaintext, plaintext);
    assert_eq!(result.metadata.logical_name.as_deref(), Some(logical_name));

    write_vector_file(case_id, "container.hlock", &container);
    write_vector_file(case_id, "plaintext.bin", plaintext);
    write_json_file(
        case_id,
        "key_material.json",
        &json!({
            "passphrase_hex": hex::encode(passphrase),
            "wrapper_id_label": "pass",
            "wrapper_type": "PassArgon2id"
        }),
    );
    write_json_file(
        case_id,
        "expected.json",
        &json!({
            "case_id": case_id,
            "version": "1",
            "wrapper_type": "PassArgon2id",
            "logical_name": logical_name,
            "mime_type": "application/octet-stream",
            "created_at": 1_700_000_000i64,
            "plaintext_hex": hex::encode(plaintext),
            "inspect": inspect_json(&container),
            "verify": { "result": "valid" }
        }),
    );
}

fn gen_pass_pad_001() {
    // Passphrase + padding enabled (PowerOf2 with log2=10 → pad to next multiple of 1024).
    let case_id = "PASS-PAD-001";
    let passphrase = b"hydralock-test-pass";
    let plaintext = b"padding test payload with short content";

    let container = encrypt_pass(
        plaintext,
        passphrase,
        "padded.bin",
        DEFAULT_CHUNK_SIZE,
        DEFAULT_EPOCH_SIZE,
        PaddingBucket::PowerOf2(10), // ceil to next power-of-2 * 1024
    );
    let result = decrypt(
        &container,
        &OpenKeyMaterial::Passphrase(passphrase.to_vec()),
    )
    .unwrap();
    assert_eq!(result.plaintext, plaintext.as_slice());

    write_vector_file(case_id, "container.hlock", &container);
    write_vector_file(case_id, "plaintext.bin", plaintext);
    write_json_file(
        case_id,
        "key_material.json",
        &json!({
            "passphrase_hex": hex::encode(passphrase),
            "wrapper_id_label": "pass",
            "wrapper_type": "PassArgon2id",
            "padding": "PowerOf2(10)"
        }),
    );
    write_json_file(
        case_id,
        "expected.json",
        &json!({
            "case_id": case_id,
            "version": "1",
            "wrapper_type": "PassArgon2id",
            "logical_name": "padded.bin",
            "plaintext_hex": hex::encode(plaintext),
            "notes": "metadata is padded to the next power-of-2 multiple of 1024 bytes",
            "inspect": inspect_json(&container),
            "verify": { "result": "valid" }
        }),
    );
}

// ── §3.3 Corruption vectors ───────────────────────────────────────────────────

/// PAYLOAD-CORRUPT-001: container truncated mid-payload.
fn gen_payload_corrupt_001() {
    let case_id = "PAYLOAD-CORRUPT-001";
    let passphrase = b"hydralock-test-pass";
    let plaintext = b"payload truncation corruption test content";

    let container = encrypt_pass(
        plaintext,
        passphrase,
        "test.bin",
        DEFAULT_CHUNK_SIZE,
        DEFAULT_EPOCH_SIZE,
        PaddingBucket::None,
    );

    let fh = FixedHeader::parse(&container[..FIXED_HEADER_LEN]).unwrap();
    // Truncate 50 bytes from the end (removes footer and part of payload).
    let truncated = container[..container.len() - 50].to_vec();

    write_vector_file(case_id, "input.hlock", &truncated);
    write_json_file(
        case_id,
        "expected.json",
        &json!({
            "case_id": case_id,
            "version": "1",
            "operation": "decrypt",
            "expect": "reject",
            "error": { "code": "ContainerTooShort" },
            "notes": format!(
                "original container {} bytes, truncated to {} bytes (50 bytes removed from end)",
                container.len(),
                truncated.len()
            )
        }),
    );
    // Include key material so implementors can attempt decryption
    write_json_file(
        case_id,
        "key_material.json",
        &json!({
            "passphrase_hex": hex::encode(passphrase),
            "wrapper_id_label": "pass",
            "wrapper_type": "PassArgon2id"
        }),
    );
    let _ = fh; // suppress unused warning
}

/// WRAP-CORRUPT-001: one bit flipped in the first wrapper stanza.
fn gen_wrap_corrupt_001() {
    let case_id = "WRAP-CORRUPT-001";
    let passphrase = b"hydralock-test-pass";
    let plaintext = b"wrapper stanza bit-flip corruption test";

    let container = encrypt_pass(
        plaintext,
        passphrase,
        "test.bin",
        DEFAULT_CHUNK_SIZE,
        DEFAULT_EPOCH_SIZE,
        PaddingBucket::None,
    );

    let fh = FixedHeader::parse(&container[..FIXED_HEADER_LEN]).unwrap();
    let wraps_start = FIXED_HEADER_LEN + fh.policy_len as usize;
    let wraps_end = wraps_start + fh.wraps_len as usize;

    // Parse wraps to find the first stanza.
    let wraps = WrapsSection::parse(&container[wraps_start..wraps_end]).unwrap();
    // Wraps wire: 2B version + 2B count, then per-entry: 2+2+2+2 header + id + stanza
    // Find offset of first stanza within the container.
    let entry_header_off = wraps_start + 4; // skip wraps_version (2) + wrapper_count (2)
    let id_len = wraps.wrappers[0].wrapper_id.len();
    // Per-entry header: wrapper_type(2) + wrapper_flags(2) + wrapper_id_len(2) + stanza_len(2) = 8 bytes
    let stanza_off = entry_header_off + 8 + id_len;

    let mut corrupted = container.clone();
    corrupted[stanza_off] ^= 0x01; // flip first bit of stanza

    // Verify that the original decrypts OK.
    decrypt(
        &container,
        &OpenKeyMaterial::Passphrase(passphrase.to_vec()),
    )
    .expect("original must decrypt");
    // Verify that the corrupted does NOT decrypt.
    let err = match decrypt(
        &corrupted,
        &OpenKeyMaterial::Passphrase(passphrase.to_vec()),
    ) {
        Err(e) => e,
        Ok(_) => panic!("WRAP-CORRUPT-001: expected error but decrypt succeeded"),
    };
    assert!(
        matches!(
            err,
            hydralock::ops::decrypt::DecryptError::NoMatchingWrapper
        ),
        "expected NoMatchingWrapper, got {err:?}"
    );

    write_vector_file(case_id, "input.hlock", &corrupted);
    write_json_file(
        case_id,
        "key_material.json",
        &json!({
            "passphrase_hex": hex::encode(passphrase),
            "wrapper_id_label": "pass",
            "wrapper_type": "PassArgon2id"
        }),
    );
    write_json_file(
        case_id,
        "expected.json",
        &json!({
            "case_id": case_id,
            "version": "1",
            "operation": "decrypt",
            "expect": "reject",
            "error": { "code": "NoMatchingWrapper" },
            "notes": format!(
                "byte at offset {} (first stanza byte) XOR'd with 0x01",
                stanza_off
            )
        }),
    );
}

/// META-CORRUPT-001: one bit flipped in the metadata ciphertext.
fn gen_meta_corrupt_001() {
    let case_id = "META-CORRUPT-001";
    let passphrase = b"hydralock-test-pass";
    let plaintext = b"metadata ciphertext bit-flip corruption test";

    let container = encrypt_pass(
        plaintext,
        passphrase,
        "test.bin",
        DEFAULT_CHUNK_SIZE,
        DEFAULT_EPOCH_SIZE,
        PaddingBucket::None,
    );

    let fh = FixedHeader::parse(&container[..FIXED_HEADER_LEN]).unwrap();
    let meta_start = FIXED_HEADER_LEN + fh.policy_len as usize + fh.wraps_len as usize;

    // Metadata section is raw crypto bytes: nonce(12) + AEAD_ciphertext_with_tag.
    // Flip a byte in the middle of the ciphertext (after the nonce).
    let meta_ct_start = meta_start + 12; // skip nonce
    let meta_ct_mid = meta_ct_start + (fh.metadata_len as usize - 12) / 2;

    let mut corrupted = container.clone();
    corrupted[meta_ct_mid] ^= 0x55;

    decrypt(
        &container,
        &OpenKeyMaterial::Passphrase(passphrase.to_vec()),
    )
    .expect("original must decrypt");
    let err = match decrypt(
        &corrupted,
        &OpenKeyMaterial::Passphrase(passphrase.to_vec()),
    ) {
        Err(e) => e,
        Ok(_) => panic!("META-CORRUPT-001: expected error but decrypt succeeded"),
    };
    assert!(
        matches!(
            err,
            hydralock::ops::decrypt::DecryptError::MetadataDecrypt(_)
        ) || matches!(err, hydralock::ops::decrypt::DecryptError::VerifyFailed),
        "expected MetadataDecrypt or VerifyFailed, got {err:?}"
    );

    write_vector_file(case_id, "input.hlock", &corrupted);
    write_json_file(
        case_id,
        "key_material.json",
        &json!({
            "passphrase_hex": hex::encode(passphrase),
            "wrapper_id_label": "pass",
            "wrapper_type": "PassArgon2id"
        }),
    );
    write_json_file(
        case_id,
        "expected.json",
        &json!({
            "case_id": case_id,
            "version": "1",
            "operation": "decrypt",
            "expect": "reject",
            "error": { "code": "VerifyFailed" },
            "notes": format!(
                "byte at metadata ciphertext offset {} XOR'd with 0x55; footer MAC fails before metadata decrypt",
                meta_ct_mid
            )
        }),
    );
}

/// CHUNK-CORRUPT-001: one bit flipped in the first chunk ciphertext.
fn gen_chunk_corrupt_001() {
    let case_id = "CHUNK-CORRUPT-001";
    let passphrase = b"hydralock-test-pass";
    let plaintext = b"chunk ciphertext bit-flip corruption test payload content";

    let container = encrypt_pass(
        plaintext,
        passphrase,
        "test.bin",
        DEFAULT_CHUNK_SIZE,
        DEFAULT_EPOCH_SIZE,
        PaddingBucket::None,
    );

    let fh = FixedHeader::parse(&container[..FIXED_HEADER_LEN]).unwrap();
    let payload_off = fh.payload_offset as usize;

    // Payload section: skip 16-byte header, then first chunk:
    // chunk_entry_header (8 bytes): ciphertext_len(4) + flags(2) + reserved(2)
    let first_chunk_ct_start = payload_off + PAYLOAD_HEADER_LEN + CHUNK_ENTRY_HEADER_LEN;

    let mut corrupted = container.clone();
    corrupted[first_chunk_ct_start] ^= 0xFF;

    decrypt(
        &container,
        &OpenKeyMaterial::Passphrase(passphrase.to_vec()),
    )
    .expect("original must decrypt");
    let err = match decrypt(
        &corrupted,
        &OpenKeyMaterial::Passphrase(passphrase.to_vec()),
    ) {
        Err(e) => e,
        Ok(_) => panic!("CHUNK-CORRUPT-001: expected error but decrypt succeeded"),
    };
    assert!(
        matches!(
            err,
            hydralock::ops::decrypt::DecryptError::VerifyFailed
                | hydralock::ops::decrypt::DecryptError::PayloadDecrypt(_)
        ),
        "expected VerifyFailed or PayloadDecrypt, got {err:?}"
    );

    write_vector_file(case_id, "input.hlock", &corrupted);
    write_json_file(
        case_id,
        "key_material.json",
        &json!({
            "passphrase_hex": hex::encode(passphrase),
            "wrapper_id_label": "pass",
            "wrapper_type": "PassArgon2id"
        }),
    );
    write_json_file(
        case_id,
        "expected.json",
        &json!({
            "case_id": case_id,
            "version": "1",
            "operation": "decrypt",
            "expect": "reject",
            "error": { "code": "VerifyFailed" },
            "notes": format!(
                "byte at first chunk ciphertext offset {} XOR'd with 0xFF",
                first_chunk_ct_start
            )
        }),
    );
}

/// CHUNK-REORDER-001: swap chunk[0] and chunk[1] in the payload section.
/// Requires chunk_size=64 and plaintext > 128 bytes so there are at least 2 chunks.
fn gen_chunk_reorder_001() {
    let case_id = "CHUNK-REORDER-001";
    let passphrase = b"hydralock-test-pass";
    // 3 full chunks: 3 × 64 = 192 bytes
    let plaintext: Vec<u8> = (0u8..192).collect();

    let container = encrypt_pass(
        &plaintext,
        passphrase,
        "test.bin",
        64,
        DEFAULT_EPOCH_SIZE,
        PaddingBucket::None,
    );

    let fh = FixedHeader::parse(&container[..FIXED_HEADER_LEN]).unwrap();
    let payload_off = fh.payload_offset as usize;

    // Payload header: 16 bytes.
    // Each non-final chunk entry: 8 header + 64 ct + 16 tag = 88 bytes.
    // Final chunk entry: 8 + ct_len + 16 (ct_len ≤ chunk_size=64).
    let chunk0_start = payload_off + PAYLOAD_HEADER_LEN;
    let chunk_entry_size = CHUNK_ENTRY_HEADER_LEN + 64 + 16; // 88 bytes (non-final chunk)
    let chunk1_start = chunk0_start + chunk_entry_size;

    // Swap the two full-size chunks (both are 88 bytes, neither is final since we have 3 chunks).
    let mut corrupted = container.clone();
    let c0 = container[chunk0_start..chunk0_start + chunk_entry_size].to_vec();
    let c1 = container[chunk1_start..chunk1_start + chunk_entry_size].to_vec();
    corrupted[chunk0_start..chunk0_start + chunk_entry_size].copy_from_slice(&c1);
    corrupted[chunk1_start..chunk1_start + chunk_entry_size].copy_from_slice(&c0);

    decrypt(
        &container,
        &OpenKeyMaterial::Passphrase(passphrase.to_vec()),
    )
    .expect("original must decrypt");
    let err = match decrypt(
        &corrupted,
        &OpenKeyMaterial::Passphrase(passphrase.to_vec()),
    ) {
        Err(e) => e,
        Ok(_) => panic!("CHUNK-REORDER-001: expected error but decrypt succeeded"),
    };
    assert!(
        matches!(
            err,
            hydralock::ops::decrypt::DecryptError::VerifyFailed
                | hydralock::ops::decrypt::DecryptError::PayloadDecrypt(_)
        ),
        "expected VerifyFailed or PayloadDecrypt on reorder, got {err:?}"
    );

    write_vector_file(case_id, "input.hlock", &corrupted);
    write_json_file(
        case_id,
        "key_material.json",
        &json!({
            "passphrase_hex": hex::encode(passphrase),
            "wrapper_id_label": "pass",
            "wrapper_type": "PassArgon2id",
            "chunk_size": 64
        }),
    );
    write_json_file(
        case_id,
        "expected.json",
        &json!({
            "case_id": case_id,
            "version": "1",
            "operation": "decrypt",
            "expect": "reject",
            "error": { "code": "VerifyFailed" },
            "notes": "chunk[0] and chunk[1] swapped in payload section; chunk_size=64; AAD bound to position breaks AEAD"
        }),
    );
}

/// SPLICE-001: payload section from container B spliced into container A.
/// Container A and B have the same passphrase but different plaintexts.
/// The manifest root in A's footer won't match B's chunk ciphertexts.
fn gen_splice_001() {
    let case_id = "SPLICE-001";
    let passphrase = b"hydralock-test-pass";
    let plaintext_a = b"splice test: this is container A's plaintext content";
    let plaintext_b = b"splice test: this is container B's DIFFERENT payload!!!";

    let container_a = encrypt_pass(
        plaintext_a,
        passphrase,
        "a.bin",
        DEFAULT_CHUNK_SIZE,
        DEFAULT_EPOCH_SIZE,
        PaddingBucket::None,
    );
    let container_b = encrypt_pass(
        plaintext_b,
        passphrase,
        "b.bin",
        DEFAULT_CHUNK_SIZE,
        DEFAULT_EPOCH_SIZE,
        PaddingBucket::None,
    );

    let fh_a = FixedHeader::parse(&container_a[..FIXED_HEADER_LEN]).unwrap();
    let payload_off_a = fh_a.payload_offset as usize;
    let footer_start_a = scan_payload_end(&container_a, payload_off_a).unwrap();

    let fh_b = FixedHeader::parse(&container_b[..FIXED_HEADER_LEN]).unwrap();
    let payload_off_b = fh_b.payload_offset as usize;
    let footer_start_b = scan_payload_end(&container_b, payload_off_b).unwrap();

    // Splice: A's [0, payload_off_a) + B's [payload_off_b, footer_start_b) + A's [footer_start_a, end)
    let mut spliced = Vec::new();
    spliced.extend_from_slice(&container_a[..payload_off_a]);
    spliced.extend_from_slice(&container_b[payload_off_b..footer_start_b]);
    spliced.extend_from_slice(&container_a[footer_start_a..]);

    // Note: the spliced container will fail because the footer auth_tag (which covers the pre-footer
    // bytes) won't match — the payload bytes changed.
    decrypt(
        &container_a,
        &OpenKeyMaterial::Passphrase(passphrase.to_vec()),
    )
    .expect("a must decrypt");
    let err = match decrypt(&spliced, &OpenKeyMaterial::Passphrase(passphrase.to_vec())) {
        Err(e) => e,
        Ok(_) => panic!("SPLICE-001: expected error but decrypt succeeded"),
    };
    assert!(
        matches!(err, hydralock::ops::decrypt::DecryptError::VerifyFailed),
        "expected VerifyFailed on splice, got {err:?}"
    );

    write_vector_file(case_id, "input.hlock", &spliced);
    write_json_file(
        case_id,
        "key_material.json",
        &json!({
            "passphrase_hex": hex::encode(passphrase),
            "wrapper_id_label": "pass",
            "wrapper_type": "PassArgon2id",
            "note": "passphrase valid for container A; payload bytes are from container B"
        }),
    );
    write_json_file(
        case_id,
        "expected.json",
        &json!({
            "case_id": case_id,
            "version": "1",
            "operation": "decrypt",
            "expect": "reject",
            "error": { "code": "VerifyFailed" },
            "notes": "payload bytes from container B spliced into container A; footer auth_tag mismatch"
        }),
    );
}

/// DOWNGRADE-001: suite_id field in fixed header changed from 0x0001 to 0x0002.
fn gen_downgrade_001() {
    let case_id = "DOWNGRADE-001";
    let passphrase = b"hydralock-test-pass";
    let plaintext = b"suite downgrade attack test vector";

    let container = encrypt_pass(
        plaintext,
        passphrase,
        "test.bin",
        DEFAULT_CHUNK_SIZE,
        DEFAULT_EPOCH_SIZE,
        PaddingBucket::None,
    );

    let mut corrupted = container.clone();
    // suite_id is at bytes [8..10] in the fixed header.
    corrupted[8] = 0x00;
    corrupted[9] = 0x02; // change to 0x0002

    // Original decrypts OK.
    decrypt(
        &container,
        &OpenKeyMaterial::Passphrase(passphrase.to_vec()),
    )
    .expect("original must decrypt");
    // Corrupted should fail at header parse in decrypt (unsupported suite).
    let err = match decrypt(
        &corrupted,
        &OpenKeyMaterial::Passphrase(passphrase.to_vec()),
    ) {
        Err(e) => e,
        Ok(_) => panic!("DOWNGRADE-001: expected error but decrypt succeeded"),
    };
    assert!(
        matches!(
            err,
            hydralock::ops::decrypt::DecryptError::HeaderParseFailed(_)
                | hydralock::ops::decrypt::DecryptError::UnsupportedSuiteId(_)
        ),
        "expected HeaderParseFailed or UnsupportedSuiteId on downgrade, got {err:?}"
    );

    write_vector_file(case_id, "input.hlock", &corrupted);
    write_json_file(
        case_id,
        "expected.json",
        &json!({
            "case_id": case_id,
            "version": "1",
            "operation": "decrypt",
            "expect": "reject",
            "error": { "code": "UnsupportedSuiteId" },
            "notes": "suite_id field (bytes 8-9) changed from 0x0001 to 0x0002; also corrupts validate_layout payload_offset check"
        }),
    );
}

/// SIZE-INCONS-001: payload_offset field inflated to claim it's beyond actual data.
/// This makes validate_layout fail at FixedHeader::parse time.
fn gen_size_incons_001() {
    let case_id = "SIZE-INCONS-001";
    let passphrase = b"hydralock-test-pass";
    let plaintext = b"size inconsistency corruption test vector";

    let container = encrypt_pass(
        plaintext,
        passphrase,
        "test.bin",
        DEFAULT_CHUNK_SIZE,
        DEFAULT_EPOCH_SIZE,
        PaddingBucket::None,
    );

    // Inflate metadata_len by 65536, also inflate payload_offset by 65536
    // so that validate_layout passes on header (payload_offset = header_len + policy_len + wraps_len + metadata_len).
    // BUT the actual container bytes don't have the extra metadata → ContainerTooShort in decrypt.
    let fh = FixedHeader::parse(&container[..FIXED_HEADER_LEN]).unwrap();
    let inflation: u32 = 65_536;
    let new_metadata_len = fh.metadata_len + inflation;
    let new_payload_offset = fh.payload_offset + inflation as u64;

    let mut corrupted = container.clone();
    // metadata_len at bytes [26..30]
    corrupted[26..30].copy_from_slice(&new_metadata_len.to_be_bytes());
    // payload_offset at bytes [30..38]
    corrupted[30..38].copy_from_slice(&new_payload_offset.to_be_bytes());

    decrypt(
        &container,
        &OpenKeyMaterial::Passphrase(passphrase.to_vec()),
    )
    .expect("original must decrypt");
    let err = match decrypt(
        &corrupted,
        &OpenKeyMaterial::Passphrase(passphrase.to_vec()),
    ) {
        Err(e) => e,
        Ok(_) => panic!("SIZE-INCONS-001: expected error but decrypt succeeded"),
    };
    assert!(
        matches!(
            err,
            hydralock::ops::decrypt::DecryptError::ContainerTooShort
                | hydralock::ops::decrypt::DecryptError::HeaderParseFailed(_)
        ),
        "expected ContainerTooShort or HeaderParseFailed, got {err:?}"
    );

    write_vector_file(case_id, "input.hlock", &corrupted);
    write_json_file(
        case_id,
        "key_material.json",
        &json!({
            "passphrase_hex": hex::encode(passphrase),
            "wrapper_id_label": "pass",
            "wrapper_type": "PassArgon2id"
        }),
    );
    write_json_file(
        case_id,
        "expected.json",
        &json!({
            "case_id": case_id,
            "version": "1",
            "operation": "decrypt",
            "expect": "reject",
            "error": { "code": "ContainerTooShort" },
            "notes": format!(
                "metadata_len inflated by {} bytes (bytes 26-29) and payload_offset adjusted consistently; \
                 actual container has no extra bytes → ContainerTooShort",
                inflation
            )
        }),
    );
}

// ── Entry point ───────────────────────────────────────────────────────────────

#[test]
#[ignore]
fn generate_all_vectors() {
    println!("Generating §3.2 acceptance vectors...");
    gen_pass_accept_001();
    println!("  PASS-ACCEPT-001 ok");
    gen_pass_accept_002();
    println!("  PASS-ACCEPT-002 ok");
    gen_pass_accept_003();
    println!("  PASS-ACCEPT-003 ok (64 KiB)");
    gen_pass_accept_004();
    println!("  PASS-ACCEPT-004 ok (multi-epoch)");
    gen_x25519_accept_001();
    println!("  X25519-ACCEPT-001 ok");
    gen_mlkem_accept_001();
    println!("  MLKEM-ACCEPT-001 ok");
    gen_thresh_accept_001();
    println!("  THRESH-ACCEPT-001 ok (2-of-3)");
    gen_pass_meta_001();
    println!("  PASS-META-001 ok (UTF-8 name)");
    gen_pass_pad_001();
    println!("  PASS-PAD-001 ok (padding)");

    println!("Generating §3.3 corruption vectors...");
    gen_payload_corrupt_001();
    println!("  PAYLOAD-CORRUPT-001 ok (truncation)");
    gen_wrap_corrupt_001();
    println!("  WRAP-CORRUPT-001 ok (wrapper bit-flip)");
    gen_meta_corrupt_001();
    println!("  META-CORRUPT-001 ok (metadata bit-flip)");
    gen_chunk_corrupt_001();
    println!("  CHUNK-CORRUPT-001 ok (chunk bit-flip)");
    gen_chunk_reorder_001();
    println!("  CHUNK-REORDER-001 ok (chunk reorder)");
    gen_splice_001();
    println!("  SPLICE-001 ok (payload splice)");
    gen_downgrade_001();
    println!("  DOWNGRADE-001 ok (suite_id downgrade)");
    gen_size_incons_001();
    println!("  SIZE-INCONS-001 ok (size inconsistency)");

    println!("\nAll 17 vectors generated successfully.");
}
