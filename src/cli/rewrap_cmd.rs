use rand::rngs::OsRng;

use crate::cli::args::RewrapArgs;
use crate::cli::keys::{load_mlkem_public, load_secret_key_material, load_x25519_public};
use crate::cli::passphrase::read_new_passphrase;
use crate::crypto::aad::WrapperAadInput;
use crate::crypto::password::{Argon2Params, Argon2Profile};
use crate::crypto::secret::fmk_expose;
use crate::format::header::{FIXED_HEADER_LEN, FixedHeader};
use crate::format::policy::PolicySection;
use crate::format::wraps::{WrapperEntry, WrapsSection};
use crate::ops::decrypt::{OpenKeyMaterial, extract_file_uuid, try_unwrap_fmk};
use crate::ops::rewrap::{compute_rewrap_header_hash, rewrap_container};
use crate::wrapper::mlkem768_x25519::{
    MLKEM768_X25519_STANZA_LEN, MlKem768X25519Stanza, WRAPPER_TYPE_MLKEM768_X25519,
};
use crate::wrapper::passargon2id::{
    PASS_ARGON2ID_STANZA_LEN, PassArgon2idStanza, WRAPPER_TYPE_PASS_ARGON2ID,
};
use crate::wrapper::x25519::{WRAPPER_TYPE_X25519, X25519_STANZA_LEN, X25519Stanza};

pub fn run(args: RewrapArgs) -> anyhow::Result<()> {
    if !args.old_passphrase && args.old_key.is_none() {
        anyhow::bail!("specify one of --old-passphrase or --old-key <FILE>");
    }
    if !args.add_passphrase && args.add_recipient.is_none() && args.add_recipient_pq.is_none() {
        anyhow::bail!(
            "specify at least one of --add-passphrase, --add-recipient, or --add-recipient-pq"
        );
    }
    if args.output.exists() && !args.force {
        anyhow::bail!(
            "output file '{}' already exists — use --force to overwrite",
            args.output.display()
        );
    }

    let container = std::fs::read(&args.input)
        .map_err(|e| anyhow::anyhow!("failed to read '{}': {e}", args.input.display()))?;

    if container.len() < FIXED_HEADER_LEN {
        anyhow::bail!("file too short to be a valid HydraLock container");
    }

    let fh = FixedHeader::parse(&container[..FIXED_HEADER_LEN])
        .map_err(|e| anyhow::anyhow!("invalid header: {e}"))?;

    let header_hash: [u8; 32] = *blake3::hash(&container[..FIXED_HEADER_LEN]).as_bytes();
    let suite_id = fh.suite_id;

    let wraps_start = FIXED_HEADER_LEN + fh.policy_len as usize;
    let wraps_end = wraps_start + fh.wraps_len as usize;
    if container.len() < wraps_end {
        anyhow::bail!("container truncated in wraps section");
    }

    let wraps = WrapsSection::parse(&container[wraps_start..wraps_end])
        .map_err(|e| anyhow::anyhow!("wraps parse error: {e}"))?;

    let file_uuid = extract_file_uuid(&wraps.wrappers)
        .map_err(|e| anyhow::anyhow!("cannot extract file_uuid: {e}"))?;

    let old_key = if args.old_passphrase {
        let pass = crate::cli::passphrase::read_passphrase("Old passphrase: ")?;
        OpenKeyMaterial::Passphrase(pass)
    } else {
        let path = args.old_key.as_ref().unwrap();
        load_secret_key_material(path)
            .map_err(|e| anyhow::anyhow!("failed to load old key '{}': {e}", path.display()))?
    };

    let fmk = try_unwrap_fmk(
        &wraps.wrappers,
        &old_key,
        suite_id,
        &header_hash,
        &file_uuid,
    )
    .map_err(|e| anyhow::anyhow!("FMK recovery failed: {e}"))?;

    // Build entry size list for computing the new header hash.
    let mut new_entry_sizes: Vec<(usize, usize)> = Vec::new();
    let mut entry_idx = 0u32;

    if args.add_passphrase {
        let label = format!("pass{entry_idx}");
        new_entry_sizes.push((16 + label.len(), PASS_ARGON2ID_STANZA_LEN));
        entry_idx += 1;
    }
    if let Some(ref path) = args.add_recipient {
        let _ = load_x25519_public(path)
            .map_err(|e| anyhow::anyhow!("failed to load recipient key: {e}"))?;
        let label = format!("rcpt{entry_idx}");
        new_entry_sizes.push((16 + label.len(), X25519_STANZA_LEN));
        entry_idx += 1;
    }
    if let Some(ref path) = args.add_recipient_pq {
        let _ = load_mlkem_public(path)
            .map_err(|e| anyhow::anyhow!("failed to load PQ recipient key: {e}"))?;
        let label = format!("rcpt{entry_idx}");
        new_entry_sizes.push((16 + label.len(), MLKEM768_X25519_STANZA_LEN));
        let _ = entry_idx;
    }

    let new_policy = PolicySection {
        policy_version: 1,
        threshold: 1,
        total_shares: 1,
        wrapper_count: new_entry_sizes.len() as u16,
    };

    let new_header_hash = compute_rewrap_header_hash(&fh, &new_policy, &new_entry_sizes)
        .map_err(|e| anyhow::anyhow!("header hash computation failed: {e:?}"))?;

    // Now build the actual new WrapperEntry list.
    let fmk_bytes = *fmk_expose(&fmk);
    let fmk_as_key = crate::crypto::secret::SecretKey32::from_bytes(fmk_bytes);

    let mut new_wrappers: Vec<WrapperEntry> = Vec::new();
    let mut rng = OsRng;
    let mut entry_idx = 0u32;

    if args.add_passphrase {
        let label = format!("pass{entry_idx}");
        let wire_id = [file_uuid.as_slice(), label.as_bytes()].concat();
        let passphrase = read_new_passphrase()?;
        let profile = Argon2Profile::Balanced;
        let (m, t, p) = match profile {
            Argon2Profile::Interactive => (65536, 3, 1),
            Argon2Profile::Balanced => (262144, 3, 1),
            Argon2Profile::Paranoid => (1048576, 3, 1),
        };
        let params = Argon2Params {
            version: 19,
            memory_kib: m,
            time_cost: t,
            parallelism: p,
            salt: [0u8; 32],
        };
        let aad = WrapperAadInput {
            suite_id,
            wrapper_index: entry_idx as u16,
            file_uuid,
            header_hash: new_header_hash,
        }
        .encode();
        let stanza =
            PassArgon2idStanza::seal_with_rng(&fmk_as_key, params, &passphrase, &aad, &mut rng)
                .map_err(|e| anyhow::anyhow!("passphrase seal failed: {e:?}"))?;
        new_wrappers.push(WrapperEntry {
            wrapper_type: WRAPPER_TYPE_PASS_ARGON2ID,
            wrapper_flags: 0,
            wrapper_id: wire_id,
            stanza: stanza.encode().to_vec(),
        });
        entry_idx += 1;
    }

    if let Some(ref path) = args.add_recipient {
        let label = format!("rcpt{entry_idx}");
        let wire_id = [file_uuid.as_slice(), label.as_bytes()].concat();
        let pk = load_x25519_public(path).unwrap();
        let aad = WrapperAadInput {
            suite_id,
            wrapper_index: entry_idx as u16,
            file_uuid,
            header_hash: new_header_hash,
        }
        .encode();
        let stanza = X25519Stanza::seal_with_rng(&fmk_as_key, &pk, &aad, &mut rng)
            .map_err(|e| anyhow::anyhow!("X25519 seal failed: {e:?}"))?;
        new_wrappers.push(WrapperEntry {
            wrapper_type: WRAPPER_TYPE_X25519,
            wrapper_flags: 0,
            wrapper_id: wire_id,
            stanza: stanza.encode().to_vec(),
        });
        entry_idx += 1;
    }

    if let Some(ref path) = args.add_recipient_pq {
        let label = format!("rcpt{entry_idx}");
        let wire_id = [file_uuid.as_slice(), label.as_bytes()].concat();
        let pk = load_mlkem_public(path).unwrap();
        let aad = WrapperAadInput {
            suite_id,
            wrapper_index: entry_idx as u16,
            file_uuid,
            header_hash: new_header_hash,
        }
        .encode();
        let stanza = MlKem768X25519Stanza::seal_with_rng(&fmk_as_key, &pk, &aad, &mut rng)
            .map_err(|e| anyhow::anyhow!("ML-KEM seal failed: {e:?}"))?;
        new_wrappers.push(WrapperEntry {
            wrapper_type: WRAPPER_TYPE_MLKEM768_X25519,
            wrapper_flags: 0,
            wrapper_id: wire_id,
            stanza: stanza.encode().to_vec(),
        });
        let _ = entry_idx;
    }

    let new_container = rewrap_container(&container, &fmk, &file_uuid, new_policy, new_wrappers)
        .map_err(|e| anyhow::anyhow!("rewrap failed: {e:?}"))?;

    let tmp = args.output.with_extension("tmp");
    std::fs::write(&tmp, &new_container)
        .map_err(|e| anyhow::anyhow!("failed to write temp file: {e}"))?;
    std::fs::rename(&tmp, &args.output)
        .map_err(|e| anyhow::anyhow!("failed to rename temp file: {e}"))?;

    eprintln!(
        "rewrapped container → {} ({} bytes)",
        args.output.display(),
        new_container.len()
    );
    Ok(())
}
