use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use rand::rngs::OsRng;

use crate::cli::args::{Argon2ProfileArg, EncryptArgs};
use crate::cli::keys::{load_mlkem_public, load_x25519_public};
use crate::cli::passphrase::read_new_passphrase;
use crate::crypto::password::Argon2Profile;
use crate::format::metadata_plaintext::PaddingBucket;
use crate::ops::encrypt::{EncryptInput, WrapperSpec, encrypt};

pub fn run(mut args: EncryptArgs) -> anyhow::Result<()> {
    check_output(&args.output, args.force)?;

    let plaintext = std::fs::read(&args.input)
        .map_err(|e| anyhow::anyhow!("failed to read input '{}': {e}", args.input.display()))?;

    let logical_name = args.name.take().or_else(|| {
        args.input
            .file_name()
            .and_then(|n| n.to_str())
            .map(|s| s.to_string())
    });

    let created_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|d| d.as_secs() as i64);

    let wrappers = build_wrappers(&args)?;
    if wrappers.is_empty() {
        anyhow::bail!("specify at least one of --passphrase, --recipient, or --recipient-pq");
    }

    let input = EncryptInput {
        plaintext: &plaintext,
        logical_name,
        mime_type: args.mime,
        created_at,
        chunk_size: args.chunk_size,
        epoch_size: args.epoch_size,
        padding: PaddingBucket::None,
    };

    let mut rng = OsRng;
    let container = encrypt(&input, &wrappers, &mut rng)
        .map_err(|e| anyhow::anyhow!("encryption failed: {e}"))?;

    write_output(&args.output, &container)?;
    eprintln!(
        "encrypted {} bytes → {} ({} bytes)",
        plaintext.len(),
        args.output.display(),
        container.len()
    );
    Ok(())
}

fn build_wrappers(args: &EncryptArgs) -> anyhow::Result<Vec<WrapperSpec>> {
    let mut wrappers = Vec::new();
    let mut idx = 0u32;

    if args.passphrase {
        let passphrase = read_new_passphrase()?;
        let profile = match args.argon2_profile {
            Argon2ProfileArg::Interactive => Argon2Profile::Interactive,
            Argon2ProfileArg::Balanced => Argon2Profile::Balanced,
            Argon2ProfileArg::Paranoid => Argon2Profile::Paranoid,
        };
        wrappers.push(WrapperSpec::PassArgon2id {
            passphrase,
            profile,
            wrapper_id: format!("pass{idx}").into_bytes(),
        });
        idx += 1;
    }

    if let Some(ref path) = args.recipient {
        let pk = load_x25519_public(path).map_err(|e| {
            anyhow::anyhow!("failed to load recipient key '{}': {e}", path.display())
        })?;
        wrappers.push(WrapperSpec::X25519 {
            recipient_pk: pk,
            wrapper_id: format!("rcpt{idx}").into_bytes(),
        });
        idx += 1;
    }

    if let Some(ref path) = args.recipient_pq {
        let pk = load_mlkem_public(path).map_err(|e| {
            anyhow::anyhow!("failed to load PQ recipient key '{}': {e}", path.display())
        })?;
        wrappers.push(WrapperSpec::MlKem768X25519 {
            recipient_pk: Box::new(pk),
            wrapper_id: format!("rcpt{idx}").into_bytes(),
        });
        let _ = idx;
    }

    Ok(wrappers)
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
    // Write to a temp file, then rename for atomicity.
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, data)
        .map_err(|e| anyhow::anyhow!("failed to write temp file '{}': {e}", tmp.display()))?;
    std::fs::rename(&tmp, path).map_err(|e| anyhow::anyhow!("failed to rename temp file: {e}"))?;
    Ok(())
}
