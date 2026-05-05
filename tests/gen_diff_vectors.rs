/// Differential test vector generator.
///
/// Run once with:
///   cargo test gen_diff -- --ignored --nocapture
///
/// This produces the canonical binary vectors in vectors/DIFF-*/ that are
/// committed to the repository. Re-run only when the wire format changes.
use std::fs;
use std::path::PathBuf;

use hydralock::crypto::password::Argon2Profile;
use hydralock::format::header::{FIXED_HEADER_LEN, FixedHeader};
use hydralock::format::metadata_plaintext::PaddingBucket;
use hydralock::format::policy::PolicySection;
use hydralock::format::wraps::WrapsSection;
use hydralock::ops::decrypt::{OpenKeyMaterial, decrypt};
use hydralock::ops::encrypt::{
    DEFAULT_CHUNK_SIZE, DEFAULT_EPOCH_SIZE, EncryptInput, WrapperSpec, encrypt,
};
use hydralock::wrapper::mlkem768_x25519::{
    MLKEM768_SEED_LEN, MlKem768X25519RecipientSecretKey, WRAPPER_TYPE_MLKEM768_X25519,
};
use hydralock::wrapper::passargon2id::WRAPPER_TYPE_PASS_ARGON2ID;
use hydralock::wrapper::x25519::WRAPPER_TYPE_X25519;
use rand::SeedableRng;
use rand::rngs::StdRng;
use serde_json::{Value, json};
use x25519_dalek::{PublicKey, StaticSecret};

fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("vectors")
}

fn wrapper_type_name(t: u16) -> String {
    match t {
        WRAPPER_TYPE_PASS_ARGON2ID => "PASS-ARGON2ID".to_string(),
        WRAPPER_TYPE_X25519 => "X25519".to_string(),
        WRAPPER_TYPE_MLKEM768_X25519 => "MLKEM768-X25519".to_string(),
        t => format!("UNKNOWN-0x{t:04x}"),
    }
}

fn inspect_container(container: &[u8]) -> Value {
    let fh = FixedHeader::parse(&container[..FIXED_HEADER_LEN]).unwrap();
    let policy_end = FIXED_HEADER_LEN + fh.policy_len as usize;
    let wraps_end = policy_end + fh.wraps_len as usize;

    let policy = PolicySection::parse(&container[FIXED_HEADER_LEN..policy_end]).unwrap();
    let wraps = WrapsSection::parse(&container[policy_end..wraps_end]).unwrap();

    let header_hash = hex::encode(blake3::hash(&container[..FIXED_HEADER_LEN]).as_bytes());
    let wrapper_types: Vec<String> = wraps
        .wrappers
        .iter()
        .map(|w| wrapper_type_name(w.wrapper_type))
        .collect();

    json!({
        "format_version_major": fh.format_version_major,
        "format_version_minor": fh.format_version_minor,
        "suite_id": fh.suite_id,
        "header_hash": header_hash,
        "wrapper_count": wraps.wrappers.len(),
        "wrapper_types": wrapper_types,
        "threshold": policy.threshold,
        "total_shares": policy.total_shares,
        "total_container_bytes": container.len(),
    })
}

fn write_vector(
    case_id: &str,
    container: &[u8],
    plaintext: &[u8],
    key_material: Value,
    expected: Value,
) {
    let dir = vectors_dir().join(case_id);
    fs::create_dir_all(&dir).expect("create vector dir");

    fs::write(dir.join("container.hlock"), container).expect("write container.hlock");
    fs::write(dir.join("plaintext.bin"), plaintext).expect("write plaintext.bin");
    fs::write(
        dir.join("key_material.json"),
        serde_json::to_string_pretty(&key_material).unwrap(),
    )
    .expect("write key_material.json");
    fs::write(
        dir.join("expected.json"),
        serde_json::to_string_pretty(&expected).unwrap(),
    )
    .expect("write expected.json");

    println!(
        "  generated {case_id}: {} bytes container, {} bytes plaintext",
        container.len(),
        plaintext.len()
    );
}

fn gen_diff_pass_001() {
    const CASE_ID: &str = "DIFF-PASS-001";
    let plaintext = b"hydralock differential test vector -- passphrase mode";
    let passphrase = b"hydralock-diff-pass-001";

    let wrappers = [WrapperSpec::PassArgon2id {
        passphrase: passphrase.to_vec(),
        profile: Argon2Profile::Interactive,
        wrapper_id: b"pass".to_vec(),
    }];
    let input = EncryptInput {
        plaintext,
        logical_name: Some("differential-test".to_string()),
        mime_type: None,
        created_at: None,
        chunk_size: DEFAULT_CHUNK_SIZE,
        epoch_size: DEFAULT_EPOCH_SIZE,
        padding: PaddingBucket::None,
    };

    let mut rng = StdRng::seed_from_u64(0xD1FF_0001_0000_0001);
    let container = encrypt(&input, &wrappers, &mut rng).expect("encrypt DIFF-PASS-001");

    let result = decrypt(
        &container,
        &OpenKeyMaterial::Passphrase(passphrase.to_vec()),
    )
    .expect("decrypt DIFF-PASS-001 during generation");
    assert_eq!(
        result.plaintext, plaintext,
        "decrypt roundtrip sanity check"
    );

    let inspect = inspect_container(&container);

    let key_material = json!({
        "wrapper_type": "PassArgon2id",
        "wrapper_id_label": "pass",
        "passphrase_hex": hex::encode(passphrase),
    });

    let expected = json!({
        "case_id": CASE_ID,
        "version": "1",
        "wrapper_type": "PassArgon2id",
        "plaintext_hex": hex::encode(plaintext),
        "logical_name": "differential-test",
        "inspect": inspect,
        "verify": { "result": "valid" },
    });

    write_vector(CASE_ID, &container, plaintext, key_material, expected);
}

fn gen_diff_x25519_001() {
    const CASE_ID: &str = "DIFF-X25519-001";
    let plaintext = b"hydralock differential test vector -- x25519 mode";

    let sk_bytes: [u8; 32] = [
        0xaa, 0x11, 0x22, 0x33, 0xaa, 0x11, 0x22, 0x33, 0xaa, 0x11, 0x22, 0x33, 0xaa, 0x11, 0x22,
        0x33, 0xaa, 0x11, 0x22, 0x33, 0xaa, 0x11, 0x22, 0x33, 0xaa, 0x11, 0x22, 0x33, 0xaa, 0x11,
        0x22, 0x33,
    ];
    let pk_bytes: [u8; 32] = *PublicKey::from(&StaticSecret::from(sk_bytes)).as_bytes();

    let wrappers = [WrapperSpec::X25519 {
        recipient_pk: pk_bytes,
        wrapper_id: b"x25519".to_vec(),
    }];
    let input = EncryptInput {
        plaintext,
        logical_name: Some("differential-test".to_string()),
        mime_type: None,
        created_at: None,
        chunk_size: DEFAULT_CHUNK_SIZE,
        epoch_size: DEFAULT_EPOCH_SIZE,
        padding: PaddingBucket::None,
    };

    let mut rng = StdRng::seed_from_u64(0xD1FF_0001_0000_0002);
    let container = encrypt(&input, &wrappers, &mut rng).expect("encrypt DIFF-X25519-001");

    let result = decrypt(&container, &OpenKeyMaterial::X25519SecretKey(sk_bytes))
        .expect("decrypt DIFF-X25519-001 during generation");
    assert_eq!(
        result.plaintext, plaintext,
        "decrypt roundtrip sanity check"
    );

    let inspect = inspect_container(&container);

    let key_material = json!({
        "wrapper_type": "X25519",
        "wrapper_id_label": "x25519",
        "recipient_sk_hex": hex::encode(sk_bytes),
        "recipient_pk_hex": hex::encode(pk_bytes),
    });

    let expected = json!({
        "case_id": CASE_ID,
        "version": "1",
        "wrapper_type": "X25519",
        "plaintext_hex": hex::encode(plaintext),
        "logical_name": "differential-test",
        "inspect": inspect,
        "verify": { "result": "valid" },
    });

    write_vector(CASE_ID, &container, plaintext, key_material, expected);
}

fn gen_diff_mlkem_001() {
    const CASE_ID: &str = "DIFF-MLKEM-001";
    let plaintext = b"hydralock differential test vector -- ml-kem-768+x25519 mode";

    let x25519_sk_bytes: [u8; 32] = [
        0xbb, 0x22, 0x33, 0x44, 0xbb, 0x22, 0x33, 0x44, 0xbb, 0x22, 0x33, 0x44, 0xbb, 0x22, 0x33,
        0x44, 0xbb, 0x22, 0x33, 0x44, 0xbb, 0x22, 0x33, 0x44, 0xbb, 0x22, 0x33, 0x44, 0xbb, 0x22,
        0x33, 0x44,
    ];
    let mlkem_seed: [u8; MLKEM768_SEED_LEN] = {
        let mut s = [0u8; MLKEM768_SEED_LEN];
        for (i, b) in s.iter_mut().enumerate() {
            *b = 0xcc ^ i as u8;
        }
        s
    };

    let sk = MlKem768X25519RecipientSecretKey::new(x25519_sk_bytes, mlkem_seed);
    let pk = sk.public_key();
    let pk_x25519 = pk.x25519_pk;
    let pk_mlkem_ek = pk.mlkem768_ek_bytes;

    let wrappers = [WrapperSpec::MlKem768X25519 {
        recipient_pk: Box::new(pk),
        wrapper_id: b"mlkem".to_vec(),
    }];
    let input = EncryptInput {
        plaintext,
        logical_name: Some("differential-test".to_string()),
        mime_type: None,
        created_at: None,
        chunk_size: DEFAULT_CHUNK_SIZE,
        epoch_size: DEFAULT_EPOCH_SIZE,
        padding: PaddingBucket::None,
    };

    let mut rng = StdRng::seed_from_u64(0xD1FF_0001_0000_0003);
    let container = encrypt(&input, &wrappers, &mut rng).expect("encrypt DIFF-MLKEM-001");

    let sk2 = MlKem768X25519RecipientSecretKey::new(x25519_sk_bytes, mlkem_seed);
    let result = decrypt(&container, &OpenKeyMaterial::MlKem768X25519SecretKey(sk2))
        .expect("decrypt DIFF-MLKEM-001 during generation");
    assert_eq!(
        result.plaintext, plaintext,
        "decrypt roundtrip sanity check"
    );

    let inspect = inspect_container(&container);

    let key_material = json!({
        "wrapper_type": "MlKem768X25519",
        "wrapper_id_label": "mlkem",
        "x25519_sk_hex": hex::encode(x25519_sk_bytes),
        "mlkem_dk_seed_hex": hex::encode(mlkem_seed),
        "recipient_pk_x25519_hex": hex::encode(pk_x25519),
        "recipient_pk_mlkem_ek_hex": hex::encode(pk_mlkem_ek),
    });

    let expected = json!({
        "case_id": CASE_ID,
        "version": "1",
        "wrapper_type": "MlKem768X25519",
        "plaintext_hex": hex::encode(plaintext),
        "logical_name": "differential-test",
        "inspect": inspect,
        "verify": { "result": "valid" },
    });

    write_vector(CASE_ID, &container, plaintext, key_material, expected);
}

#[test]
#[ignore]
fn gen_diff() {
    println!("\nGenerating differential test vectors...");
    gen_diff_pass_001();
    gen_diff_x25519_001();
    gen_diff_mlkem_001();
    println!("Done. 3 vectors written to vectors/DIFF-*/");
}
