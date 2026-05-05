use crate::cli::args::InspectArgs;
use crate::format::header::{FIXED_HEADER_LEN, FixedHeader};
use crate::format::policy::PolicySection;
use crate::format::wraps::WrapsSection;
use crate::wrapper::mlkem768_x25519::WRAPPER_TYPE_MLKEM768_X25519;
use crate::wrapper::passargon2id::WRAPPER_TYPE_PASS_ARGON2ID;
use crate::wrapper::threshold::WRAPPER_TYPE_THRESHOLD;
use crate::wrapper::x25519::WRAPPER_TYPE_X25519;

pub fn run(args: InspectArgs) -> anyhow::Result<()> {
    let data = std::fs::read(&args.input)
        .map_err(|e| anyhow::anyhow!("failed to read '{}': {e}", args.input.display()))?;

    if data.len() < FIXED_HEADER_LEN {
        anyhow::bail!("file too short to be a valid HydraLock container");
    }

    let fh = FixedHeader::parse(&data[..FIXED_HEADER_LEN])
        .map_err(|e| anyhow::anyhow!("invalid header: {e}"))?;

    let policy_start = FIXED_HEADER_LEN;
    let policy_end = policy_start + fh.policy_len as usize;
    let wraps_start = policy_end;
    let wraps_end = wraps_start + fh.wraps_len as usize;

    if data.len() < wraps_end {
        anyhow::bail!("container truncated before wraps section");
    }

    let policy = PolicySection::parse(&data[policy_start..policy_end])
        .map_err(|e| anyhow::anyhow!("policy parse error: {e:?}"))?;
    let wraps = WrapsSection::parse(&data[wraps_start..wraps_end])
        .map_err(|e| anyhow::anyhow!("wraps parse error: {e}"))?;

    let header_hash: [u8; 32] = *blake3::hash(&data[..FIXED_HEADER_LEN]).as_bytes();

    println!("HydraLock Container");
    println!(
        "  format version : {}.{}",
        fh.format_version_major, fh.format_version_minor
    );
    println!("  suite id       : 0x{:04x}", fh.suite_id);
    println!("  flags          : 0x{:08x}", fh.flags);
    println!("  header len     : {} bytes", fh.header_len);
    println!("  policy len     : {} bytes", fh.policy_len);
    println!("  wraps len      : {} bytes", fh.wraps_len);
    println!("  metadata len   : {} bytes", fh.metadata_len);
    println!("  payload offset : {} bytes", fh.payload_offset);
    println!("  container size : {} bytes", data.len());
    println!("  header hash    : {}", hex::encode(header_hash));
    println!();
    println!("Policy");
    println!(
        "  threshold      : {}/{}",
        policy.threshold, policy.total_shares
    );
    println!("  wrapper count  : {}", policy.wrapper_count);
    println!();
    println!("Wrappers ({}):", wraps.wrappers.len());
    for (i, entry) in wraps.wrappers.iter().enumerate() {
        let type_name = match entry.wrapper_type {
            WRAPPER_TYPE_PASS_ARGON2ID => "PASS-ARGON2ID",
            WRAPPER_TYPE_X25519 => "X25519",
            WRAPPER_TYPE_MLKEM768_X25519 => "MLKEM768-X25519",
            WRAPPER_TYPE_THRESHOLD => "THRESHOLD",
            t => {
                println!("  [{i}] unknown type 0x{t:04x}");
                return Ok(());
            }
        };
        // wrapper_id convention: file_uuid(16) || user_label
        let label = if entry.wrapper_id.len() > 16 {
            String::from_utf8_lossy(&entry.wrapper_id[16..]).to_string()
        } else {
            String::new()
        };
        println!(
            "  [{i}] type={type_name} stanza_len={} label={label:?}",
            entry.stanza.len()
        );
    }

    Ok(())
}
