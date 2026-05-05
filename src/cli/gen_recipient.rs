use rand::rngs::OsRng;
use std::path::PathBuf;

use crate::cli::args::{GenRecipientArgs, KeyTypeArg};
use crate::cli::keys::{
    encode_mlkem_public, encode_mlkem_secret, encode_x25519_public, encode_x25519_secret,
};
use crate::wrapper::mlkem768_x25519::MlKem768X25519RecipientSecretKey;

pub fn run(args: GenRecipientArgs) -> anyhow::Result<()> {
    let mut rng = OsRng;

    match args.key_type {
        KeyTypeArg::X25519 => gen_x25519(&mut rng, args.output),
        KeyTypeArg::MlKem768X25519 => gen_mlkem(&mut rng, args.output),
    }
}

fn gen_x25519(rng: &mut OsRng, prefix: Option<PathBuf>) -> anyhow::Result<()> {
    let sk_bytes = x25519_dalek::StaticSecret::random_from_rng(rng);
    let pk_bytes: [u8; 32] = x25519_dalek::PublicKey::from(&sk_bytes).to_bytes();
    let sk_arr: [u8; 32] = sk_bytes.to_bytes();

    let pub_pem = encode_x25519_public(&pk_bytes);
    let sec_pem = encode_x25519_secret(&sk_arr);

    if let Some(prefix) = prefix {
        let pub_path = prefix.with_extension("pub");
        let key_path = prefix.with_extension("key");
        std::fs::write(&pub_path, &pub_pem)
            .map_err(|e| anyhow::anyhow!("failed to write public key: {e}"))?;
        std::fs::write(&key_path, &sec_pem)
            .map_err(|e| anyhow::anyhow!("failed to write secret key: {e}"))?;
        eprintln!("public key → {}", pub_path.display());
        eprintln!("secret key → {}", key_path.display());
    } else {
        print!("{pub_pem}");
        print!("{sec_pem}");
    }

    Ok(())
}

fn gen_mlkem(rng: &mut OsRng, prefix: Option<PathBuf>) -> anyhow::Result<()> {
    let sk = MlKem768X25519RecipientSecretKey::generate_from_rng(rng);
    let pk = sk.public_key();

    let pub_pem = encode_mlkem_public(&pk);
    let sec_pem = encode_mlkem_secret(&sk);

    if let Some(prefix) = prefix {
        let pub_path = prefix.with_extension("pub");
        let key_path = prefix.with_extension("key");
        std::fs::write(&pub_path, &pub_pem)
            .map_err(|e| anyhow::anyhow!("failed to write public key: {e}"))?;
        std::fs::write(&key_path, &sec_pem)
            .map_err(|e| anyhow::anyhow!("failed to write secret key: {e}"))?;
        eprintln!("public key → {}", pub_path.display());
        eprintln!("secret key → {}", key_path.display());
    } else {
        print!("{pub_pem}");
        print!("{sec_pem}");
    }

    Ok(())
}
