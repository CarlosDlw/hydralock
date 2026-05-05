use crate::cli::args::VerifyArgs;
use crate::cli::keys::load_secret_key_material;
use crate::cli::passphrase::read_passphrase;
use crate::format::footer::FooterSection;
use crate::format::header::{FIXED_HEADER_LEN, FixedHeader};
use crate::ops::decrypt::{OpenKeyMaterial, decrypt, scan_payload_end};

pub fn run(args: VerifyArgs) -> anyhow::Result<()> {
    let data = std::fs::read(&args.input)
        .map_err(|e| anyhow::anyhow!("failed to read '{}': {e}", args.input.display()))?;

    // Structural check first (no FMK required).
    if data.len() < FIXED_HEADER_LEN {
        anyhow::bail!("file too short to be a valid HydraLock container");
    }

    let fh = FixedHeader::parse(&data[..FIXED_HEADER_LEN])
        .map_err(|e| anyhow::anyhow!("invalid header: {e}"))?;

    let policy_start = FIXED_HEADER_LEN;
    let policy_end = policy_start + fh.policy_len as usize;
    let wraps_start = policy_end;
    let wraps_end = wraps_start + fh.wraps_len as usize;
    let metadata_start = wraps_end;
    let metadata_end = metadata_start + fh.metadata_len as usize;
    let payload_start = fh.payload_offset as usize;

    if data.len() < metadata_end {
        anyhow::bail!("container truncated before metadata section");
    }
    if data.len() < payload_start {
        anyhow::bail!("container truncated before payload section");
    }

    let payload_end = scan_payload_end(&data, payload_start)
        .map_err(|e| anyhow::anyhow!("payload scan error: {e}"))?;

    if data.len() < payload_end {
        anyhow::bail!("container truncated (payload end past EOF)");
    }

    let footer_bytes = &data[payload_end..];
    let _footer = FooterSection::parse(footer_bytes)
        .map_err(|e| anyhow::anyhow!("footer parse error: {e}"))?;

    eprintln!("structure OK — container length {} bytes", data.len());

    // Footer auth tag verification requires the FMK.
    let needs_key = args.passphrase || args.key.is_some();
    if !needs_key {
        eprintln!("note: use --passphrase or --key to also verify the footer auth tag");
        return Ok(());
    }

    let key_material = if args.passphrase {
        let pass = read_passphrase("Passphrase: ")?;
        OpenKeyMaterial::Passphrase(pass)
    } else {
        let path = args.key.as_ref().unwrap();
        load_secret_key_material(path)
            .map_err(|e| anyhow::anyhow!("failed to load key '{}': {e}", path.display()))?
    };

    // Decrypt the container (which also verifies the footer auth tag internally).
    decrypt(&data, &key_material).map_err(|e| anyhow::anyhow!("verification failed: {e}"))?;

    eprintln!("footer auth tag OK");
    Ok(())
}
