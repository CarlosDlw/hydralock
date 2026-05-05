use hydralock::api::{
    DecryptOutput, EncryptOptions, KeyMaterial, RecipientSpec, decrypt, encrypt,
};
use hydralock::crypto::password::Argon2Profile;
use hydralock::wrapper::mlkem768_x25519::MlKem768X25519RecipientSecretKey;
use rand::rngs::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};

fn roundtrip(container: &[u8], key: KeyMaterial) -> DecryptOutput {
    decrypt(container, key).expect("decrypt must succeed")
}

#[test]
fn integration_small_file_passphrase_roundtrip() {
    let plaintext = b"small-file".to_vec();
    let pass = b"small-passphrase".to_vec();

    let recipients = vec![RecipientSpec::Passphrase {
        passphrase: pass.clone(),
        profile: Argon2Profile::Interactive,
        label: None,
    }];

    let container = encrypt(&plaintext, &recipients, EncryptOptions::default())
        .expect("encrypt must succeed");

    let out = roundtrip(&container, KeyMaterial::Passphrase(pass));
    assert_eq!(out.plaintext, plaintext);
}

#[test]
fn integration_medium_file_x25519_roundtrip() {
    let plaintext = vec![0x42u8; 128 * 1024];

    let mut rng = OsRng;
    let sk = StaticSecret::random_from_rng(&mut rng);
    let pk = PublicKey::from(&sk).to_bytes();

    let recipients = vec![RecipientSpec::X25519 {
        recipient_pk: pk,
        label: None,
    }];

    let container = encrypt(&plaintext, &recipients, EncryptOptions::default())
        .expect("encrypt must succeed");

    let out = roundtrip(&container, KeyMaterial::X25519SecretKey(sk.to_bytes()));
    assert_eq!(out.plaintext, plaintext);
}

#[test]
fn integration_large_file_mlkem_roundtrip() {
    let plaintext = vec![0xA5u8; 2 * 1024 * 1024];

    let mut rng = OsRng;
    let sk = MlKem768X25519RecipientSecretKey::generate_from_rng(&mut rng);
    let pk = sk.public_key();

    let recipients = vec![RecipientSpec::MlKem768X25519 {
        recipient_pk: pk,
        label: None,
    }];

    let container = encrypt(&plaintext, &recipients, EncryptOptions::default())
        .expect("encrypt must succeed");

    let out = roundtrip(&container, KeyMaterial::MlKem768X25519SecretKey(sk));
    assert_eq!(out.plaintext, plaintext);
}

#[test]
fn integration_multiple_wrappers_same_container() {
    let plaintext = b"multi-wrapper integration plaintext".to_vec();

    let pass = b"multi-wrapper-pass".to_vec();

    let mut rng = OsRng;
    let x25519_sk = StaticSecret::random_from_rng(&mut rng);
    let x25519_pk = PublicKey::from(&x25519_sk).to_bytes();

    let mlkem_sk = MlKem768X25519RecipientSecretKey::generate_from_rng(&mut rng);
    let mlkem_pk = mlkem_sk.public_key();

    let recipients = vec![
        RecipientSpec::Passphrase {
            passphrase: pass.clone(),
            profile: Argon2Profile::Interactive,
            label: Some(b"pass-a".to_vec()),
        },
        RecipientSpec::X25519 {
            recipient_pk: x25519_pk,
            label: Some(b"x25519-a".to_vec()),
        },
        RecipientSpec::MlKem768X25519 {
            recipient_pk: mlkem_pk,
            label: Some(b"mlkem-a".to_vec()),
        },
    ];

    let container = encrypt(&plaintext, &recipients, EncryptOptions::default())
        .expect("encrypt must succeed");

    let out_pass = roundtrip(&container, KeyMaterial::Passphrase(pass));
    assert_eq!(out_pass.plaintext, plaintext);

    let out_x = roundtrip(&container, KeyMaterial::X25519SecretKey(x25519_sk.to_bytes()));
    assert_eq!(out_x.plaintext, plaintext);

    let out_mlkem = roundtrip(&container, KeyMaterial::MlKem768X25519SecretKey(mlkem_sk));
    assert_eq!(out_mlkem.plaintext, plaintext);
}
