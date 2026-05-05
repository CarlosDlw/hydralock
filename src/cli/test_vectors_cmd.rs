use rand::rngs::OsRng;

use crate::crypto::password::Argon2Profile;
use crate::format::metadata_plaintext::PaddingBucket;
use crate::ops::decrypt::{OpenKeyMaterial, decrypt};
use crate::ops::encrypt::{EncryptInput, WrapperSpec, encrypt};

/// Run built-in encrypt → decrypt roundtrip test vectors.
///
/// Tests three wrapper types: passphrase, X25519, ML-KEM-768+X25519.
pub fn run() -> anyhow::Result<()> {
    let mut rng = OsRng;

    // ── Vector 1: Passphrase ──────────────────────────────────────────────
    {
        let plaintext = b"hydralock test vector 1 -- passphrase".to_vec();
        let passphrase = b"correct horse battery staple".to_vec();

        let wrappers = vec![WrapperSpec::PassArgon2id {
            passphrase: passphrase.clone(),
            profile: Argon2Profile::Interactive,
            wrapper_id: b"tv1".to_vec(),
        }];

        let input = EncryptInput {
            plaintext: &plaintext,
            logical_name: Some("test1.bin".to_string()),
            mime_type: None,
            created_at: Some(0),
            chunk_size: 65536,
            epoch_size: 256,
            padding: PaddingBucket::None,
        };

        let container = encrypt(&input, &wrappers, &mut rng)
            .map_err(|e| anyhow::anyhow!("tv1 encrypt failed: {e}"))?;

        let result = decrypt(&container, &OpenKeyMaterial::Passphrase(passphrase))
            .map_err(|e| anyhow::anyhow!("tv1 decrypt failed: {e}"))?;

        if result.plaintext != plaintext {
            anyhow::bail!("tv1 plaintext mismatch");
        }
        eprintln!("PASS tv1 — passphrase wrapper");
    }

    // ── Vector 2: X25519 ─────────────────────────────────────────────────
    {
        let plaintext = b"hydralock test vector 2 -- x25519".to_vec();
        let sk = x25519_dalek::StaticSecret::random_from_rng(rng);
        let pk: [u8; 32] = x25519_dalek::PublicKey::from(&sk).to_bytes();
        let sk_bytes: [u8; 32] = sk.to_bytes();

        let wrappers = vec![WrapperSpec::X25519 {
            recipient_pk: pk,
            wrapper_id: b"tv2".to_vec(),
        }];

        let input = EncryptInput {
            plaintext: &plaintext,
            logical_name: Some("test2.bin".to_string()),
            mime_type: None,
            created_at: Some(0),
            chunk_size: 65536,
            epoch_size: 256,
            padding: PaddingBucket::None,
        };

        let container = encrypt(&input, &wrappers, &mut rng)
            .map_err(|e| anyhow::anyhow!("tv2 encrypt failed: {e}"))?;

        let result = decrypt(&container, &OpenKeyMaterial::X25519SecretKey(sk_bytes))
            .map_err(|e| anyhow::anyhow!("tv2 decrypt failed: {e}"))?;

        if result.plaintext != plaintext {
            anyhow::bail!("tv2 plaintext mismatch");
        }
        eprintln!("PASS tv2 — X25519 wrapper");
    }

    // ── Vector 3: ML-KEM-768 + X25519 ────────────────────────────────────
    {
        use crate::wrapper::mlkem768_x25519::MlKem768X25519RecipientSecretKey;
        let plaintext = b"hydralock test vector 3 -- mlkem768-x25519".to_vec();
        let sk = MlKem768X25519RecipientSecretKey::generate_from_rng(&mut rng);
        let pk = sk.public_key();

        let wrappers = vec![WrapperSpec::MlKem768X25519 {
            recipient_pk: Box::new(pk),
            wrapper_id: b"tv3".to_vec(),
        }];

        let input = EncryptInput {
            plaintext: &plaintext,
            logical_name: Some("test3.bin".to_string()),
            mime_type: None,
            created_at: Some(0),
            chunk_size: 65536,
            epoch_size: 256,
            padding: PaddingBucket::None,
        };

        let container = encrypt(&input, &wrappers, &mut rng)
            .map_err(|e| anyhow::anyhow!("tv3 encrypt failed: {e}"))?;

        let result = decrypt(&container, &OpenKeyMaterial::MlKem768X25519SecretKey(sk))
            .map_err(|e| anyhow::anyhow!("tv3 decrypt failed: {e}"))?;

        if result.plaintext != plaintext {
            anyhow::bail!("tv3 plaintext mismatch");
        }
        eprintln!("PASS tv3 — ML-KEM-768+X25519 wrapper");
    }

    eprintln!("All test vectors passed.");
    Ok(())
}
