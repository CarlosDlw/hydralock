use std::path::{Path, PathBuf};

use crate::cli::args::DecryptArgs;
use crate::cli::keys::load_secret_key_material;
use crate::cli::passphrase::read_passphrase;
use crate::ops::decrypt::{OpenKeyMaterial, decrypt};

pub fn run(args: DecryptArgs) -> anyhow::Result<()> {
    if !args.passphrase && args.key.is_none() {
        anyhow::bail!("specify one of --passphrase or --key <FILE>");
    }
    check_output(&args.output, args.force)?;

    let container = std::fs::read(&args.input)
        .map_err(|e| anyhow::anyhow!("failed to read input '{}': {e}", args.input.display()))?;

    let key_material = if args.passphrase {
        let pass = read_passphrase("Passphrase: ")?;
        OpenKeyMaterial::Passphrase(pass)
    } else {
        let path = args.key.as_ref().unwrap();
        load_secret_key_material(path)
            .map_err(|e| anyhow::anyhow!("failed to load key '{}': {e}", path.display()))?
    };

    let result = decrypt(&container, &key_material)
        .map_err(|e| anyhow::anyhow!("decryption failed: {e}"))?;

    write_output(&args.output, &result.plaintext)?;
    eprintln!(
        "decrypted {} bytes → {}",
        result.plaintext.len(),
        args.output.display()
    );
    Ok(())
}

fn check_output(path: &Path, force: bool) -> anyhow::Result<()> {
    if path.exists() && !force {
        anyhow::bail!(
            "output file '{}' already exists — use --force to overwrite",
            path.display()
        );
    }
    Ok(())
}

fn write_output(path: &PathBuf, data: &[u8]) -> anyhow::Result<()> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, data)
        .map_err(|e| anyhow::anyhow!("failed to write temp file '{}': {e}", tmp.display()))?;
    std::fs::rename(&tmp, path).map_err(|e| anyhow::anyhow!("failed to rename temp file: {e}"))?;
    Ok(())
}
