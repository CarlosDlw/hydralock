//! Container rewrap — replace the wrapped secrets section (and policy section)
//! without re-encrypting the payload.
//!
//! # What changes
//!
//! | Section          | Action                              |
//! |------------------|-------------------------------------|
//! | Fixed header     | Recomputed (new wraps_len / offset) |
//! | Policy section   | Replaced (new threshold / n)        |
//! | Wraps section    | Replaced (new sealed stanzas)       |
//! | Metadata section | Preserved verbatim (opaque bytes)   |
//! | Payload section  | Preserved verbatim (ciphertexts)    |
//! | Footer auth_tag  | Recomputed over new pre-footer data |
//! | manifest_root    | Preserved verbatim (unchanged)      |
//!
//! # Circular-dependency break for wrapper AAD
//!
//! Each wrapper stanza is sealed with an `AAD` that includes the 32-byte
//! `header_hash = BLAKE3(fixed_header_bytes)`. Because the fixed header
//! contains `wraps_len`, which depends on the final stanza sizes, the hash
//! is not yet known when you start sealing stanzas.
//!
//! The solution is a two-step API:
//!
//! 1. Call [`compute_rewrap_header_hash`] with the sizes of the new entries
//!    (`(wrapper_id_len, stanza_len)` per entry) to obtain `header_hash`.
//! 2. Seal each new wrapper stanza passing that `header_hash` in the
//!    `WrapperAadInput`.
//! 3. Call [`rewrap_container`] with the sealed `WrapperEntry` list.
//!
//! Stanza sizes are deterministic per wrapper type:
//!
//! | Wrapper type            | `stanza_len` (bytes) |
//! |-------------------------|----------------------|
//! | `PASS-ARGON2ID`         | 110                  |
//! | `X25519`                | 94                   |
//! | `MLKEM768-X25519`       | 1182                 |
//! | `THRESHOLD` share       | 65                   |

use crate::crypto::kdf::{derive_root_key, derive_subkeys};
use crate::crypto::metadata::{decrypt_metadata, encrypt_metadata};
use crate::crypto::secret::{Fmk, SecretKey32};
use crate::crypto::verify::{build_footer, verify_container_no_decrypt};
use crate::format::footer::{FooterSection, FooterSectionError};
use crate::format::header::{FIXED_HEADER_LEN, FixedHeader, FixedHeaderError};
use crate::format::payload::PAYLOAD_HEADER_LEN;
use crate::format::policy::{POLICY_SECTION_LEN, PolicySection, PolicySectionError};
use crate::format::wraps::{
    WRAPPER_ENTRY_HEADER_LEN, WRAPS_HEADER_LEN, WrapperEntry, WrapsSection, WrapsSectionError,
};

// ── Error type ───────────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum RewrapError {
    /// Container is shorter than the minimum valid length.
    ContainerTooShort,
    /// Fixed header parsing failed.
    HeaderParseFailed(FixedHeaderError),
    /// Policy section encoding failed.
    PolicyEncodeFailed(PolicySectionError),
    /// New wraps section encoding failed.
    WrapsEncodeFailed(WrapsSectionError),
    /// Footer section parsing failed.
    FooterParseFailed(FooterSectionError),
    /// The payload was truncated before a final chunk was found.
    PayloadTruncated,
    /// Scanned the entire payload without encountering a final chunk.
    PayloadNoFinalChunk,
    /// Arithmetic overflow during layout computation.
    LayoutOverflow,
    /// New wrapper count is below `total_shares` in the new policy.
    PolicyMismatch {
        wrapper_count: usize,
        total_shares: u8,
    },
    /// A header field value exceeds its wire representation range.
    HeaderFieldOverflow,
    /// The manifest_root in the original footer has an unexpected size.
    InvalidManifestRootSize { actual: usize },
    /// The original container's footer auth_tag is invalid (container tampered or wrong FMK).
    InvalidOriginalContainer,
    /// Metadata decryption or re-encryption failed during rewrap (wrong FMK or corrupt bytes).
    MetadataReencryptFailed,
}

impl core::fmt::Display for RewrapError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for RewrapError {}

impl From<FixedHeaderError> for RewrapError {
    fn from(e: FixedHeaderError) -> Self {
        RewrapError::HeaderParseFailed(e)
    }
}

impl From<FooterSectionError> for RewrapError {
    fn from(e: FooterSectionError) -> Self {
        RewrapError::FooterParseFailed(e)
    }
}

// ── Public helpers ────────────────────────────────────────────────────────────

/// Compute the expected byte length of a wraps section given a list of
/// `(wrapper_id_len, stanza_len)` pairs for the entries.
///
/// Layout: `4 + Σ(8 + wrapper_id_len + stanza_len)`.
pub fn compute_wraps_section_len(entry_sizes: &[(usize, usize)]) -> usize {
    WRAPS_HEADER_LEN
        + entry_sizes
            .iter()
            .map(|(id_len, stanza_len)| WRAPPER_ENTRY_HEADER_LEN + id_len + stanza_len)
            .sum::<usize>()
}

/// Compute the BLAKE3 hash of the new fixed header.
///
/// The returned 32-byte hash is the value that must be placed in the
/// `header_hash` field of each `WrapperAadInput` when sealing the new
/// recipient stanzas. Call this **before** sealing any stanza.
///
/// Parameters:
///   - `original`: parsed fixed header of the container to rewrap.
///   - `new_policy`: new policy section to be written.
///   - `new_entry_sizes`: `(wrapper_id_len, stanza_len)` pairs, one per
///     new entry in the order they will appear in the wraps section.
pub fn compute_rewrap_header_hash(
    original: &FixedHeader,
    new_policy: &PolicySection,
    new_entry_sizes: &[(usize, usize)],
) -> Result<[u8; 32], RewrapError> {
    let new_fh = build_new_fixed_header(original, new_policy, new_entry_sizes)?;
    Ok(*blake3::hash(&new_fh.encode()).as_bytes())
}

// ── Core operation ────────────────────────────────────────────────────────────

/// Rewrap an existing container with a new set of recipients.
///
/// The payload ciphertexts and manifest root are preserved verbatim. Only
/// the header, policy, and wraps sections are replaced, and the footer
/// `auth_tag` is recomputed.
///
/// **Pre-condition**: each `WrapperEntry.stanza` in `new_wrappers` must have
/// been sealed with `WrapperAadInput { header_hash: compute_rewrap_header_hash(...) }`.
/// This is not verified here; incorrect AAD will make the container
/// unreadable by the intended recipients.
///
/// Parameters:
///   - `container`: original container bytes.
///   - `fmk`: File Master Key, recovered from one of the original stanzas.
///   - `file_uuid`: 16-byte UUID from the container's encrypted metadata.
///   - `new_policy`: new access policy (threshold / total_shares).
///   - `new_wrappers`: new sealed recipient stanza entries.
pub fn rewrap_container(
    container: &[u8],
    fmk: &Fmk,
    file_uuid: &[u8; 16],
    new_policy: PolicySection,
    new_wrappers: Vec<WrapperEntry>,
) -> Result<Vec<u8>, RewrapError> {
    // ── 1. Parse the original fixed header ────────────────────────────────
    if container.len() < FIXED_HEADER_LEN {
        return Err(RewrapError::ContainerTooShort);
    }
    let orig_fh = FixedHeader::parse(&container[..FIXED_HEADER_LEN])?;

    // ── 2. Validate new policy against wrapper count ──────────────────────
    if new_wrappers.len() < new_policy.total_shares as usize {
        return Err(RewrapError::PolicyMismatch {
            wrapper_count: new_wrappers.len(),
            total_shares: new_policy.total_shares,
        });
    }

    // ── 3. Locate metadata bytes and compute old header hash ─────────────
    let wraps_start = FIXED_HEADER_LEN + orig_fh.policy_len as usize;
    let wraps_end = wraps_start + orig_fh.wraps_len as usize;
    let metadata_start = wraps_end;
    let metadata_end = metadata_start + orig_fh.metadata_len as usize;
    let payload_offset = orig_fh.payload_offset as usize;

    if container.len() < payload_offset {
        return Err(RewrapError::ContainerTooShort);
    }

    let old_metadata_bytes = &container[metadata_start..metadata_end];
    let old_header_hash: [u8; 32] = *blake3::hash(&container[..FIXED_HEADER_LEN]).as_bytes();

    // ── 4. Scan the payload to find the footer start ──────────────────────
    let footer_start = scan_payload_end(container, payload_offset)?;

    if container.len() < footer_start {
        return Err(RewrapError::ContainerTooShort);
    }

    let old_payload_bytes = &container[payload_offset..footer_start];
    let old_footer_bytes = &container[footer_start..];

    // ── 5. Parse old footer — extract manifest_root (preserved unchanged) ─
    let old_footer = FooterSection::parse(old_footer_bytes)?;
    let manifest_root: [u8; 32] = old_footer
        .manifest_root
        .as_slice()
        .try_into()
        .map_err(|_| RewrapError::InvalidManifestRootSize {
            actual: old_footer.manifest_root.len(),
        })?;

    // ── 5.5 Verify original container integrity before rewriting ─────────
    // Ensures we are not rewrapping a tampered container. Requires deriving
    // k_manifest from the provided FMK.
    let root_key = derive_root_key(fmk, file_uuid);
    let subkeys = derive_subkeys(&root_key);
    {
        let orig_k_manifest = SecretKey32::from_bytes(*subkeys.k_manifest.expose());
        let orig_pre_footer = &container[..footer_start];
        verify_container_no_decrypt(&orig_k_manifest, orig_pre_footer, old_footer_bytes)
            .map_err(|_| RewrapError::InvalidOriginalContainer)?;
    }

    // ── 6. Build the new wraps section ────────────────────────────────────
    let new_entry_sizes: Vec<(usize, usize)> = new_wrappers
        .iter()
        .map(|e| (e.wrapper_id.len(), e.stanza.len()))
        .collect();

    let new_wraps_section = WrapsSection {
        wraps_version: 1,
        wrappers: new_wrappers,
    };
    let new_wraps_bytes = new_wraps_section
        .encode()
        .map_err(RewrapError::WrapsEncodeFailed)?;

    // ── 7. Build the new fixed header ─────────────────────────────────────
    let new_fh = build_new_fixed_header(&orig_fh, &new_policy, &new_entry_sizes)?;

    // ── 8. Encode new policy ──────────────────────────────────────────────
    let new_policy_bytes = new_policy
        .encode()
        .map_err(RewrapError::PolicyEncodeFailed)?;

    // ── 8.5 Re-encrypt metadata with the new header_hash ─────────────────
    // The metadata bytes in the container are raw crypto bytes: nonce(12) || AEAD_ct.
    // Metadata AAD binds to header_hash; after rewrap the fixed header changes,
    // so the ciphertext must be re-sealed under the new header hash.
    let new_header_hash: [u8; 32] = *blake3::hash(&new_fh.encode()).as_bytes();
    let k_control = SecretKey32::from_bytes(*subkeys.k_control.expose());
    let meta_plain = decrypt_metadata(
        &k_control,
        old_metadata_bytes,
        file_uuid,
        orig_fh.suite_id,
        &old_header_hash,
    )
    .map_err(|_| RewrapError::MetadataReencryptFailed)?;
    let new_metadata_bytes = encrypt_metadata(
        &k_control,
        &meta_plain,
        file_uuid,
        orig_fh.suite_id,
        &new_header_hash,
    )
    .map_err(|_| RewrapError::MetadataReencryptFailed)?;

    // ── 9. Assemble pre-footer bytes ──────────────────────────────────────
    let pre_footer_capacity = FIXED_HEADER_LEN
        + new_policy_bytes.len()
        + new_wraps_bytes.len()
        + new_metadata_bytes.len()
        + old_payload_bytes.len();

    let mut pre_footer: Vec<u8> = Vec::with_capacity(pre_footer_capacity);
    pre_footer.extend_from_slice(&new_fh.encode());
    pre_footer.extend_from_slice(&new_policy_bytes);
    pre_footer.extend_from_slice(&new_wraps_bytes);
    pre_footer.extend_from_slice(&new_metadata_bytes);
    pre_footer.extend_from_slice(old_payload_bytes);

    // ── 10. Derive k_manifest and recompute footer auth_tag ───────────────
    let new_footer_bytes = build_footer(&subkeys.k_manifest, manifest_root, &pre_footer);

    // ── 11. Assemble the new container ────────────────────────────────────
    let mut result = pre_footer;
    result.extend_from_slice(&new_footer_bytes);
    Ok(result)
}

// ── Private helpers ───────────────────────────────────────────────────────────

/// Scan the payload section starting at `payload_offset` and return the byte
/// offset in `container` immediately following the last chunk (= footer start).
///
/// Does not decrypt or store chunk data; only inspects the structural headers.
fn scan_payload_end(container: &[u8], payload_offset: usize) -> Result<usize, RewrapError> {
    let payload_bytes = container
        .get(payload_offset..)
        .ok_or(RewrapError::ContainerTooShort)?;

    if payload_bytes.len() < PAYLOAD_HEADER_LEN {
        return Err(RewrapError::PayloadTruncated);
    }

    // Payload section header: version(2) + flags(2) + chunk_size(4) + tag_size(4) + reserved(4)
    let tag_size = u32::from_be_bytes([
        payload_bytes[8],
        payload_bytes[9],
        payload_bytes[10],
        payload_bytes[11],
    ]) as usize;

    let mut offset = PAYLOAD_HEADER_LEN; // scan cursor within payload_bytes

    loop {
        // Each chunk entry header: ciphertext_len(4) + flags(2) + reserved(2) = 8 bytes.
        if offset + 8 > payload_bytes.len() {
            return Err(RewrapError::PayloadTruncated);
        }

        let ciphertext_len = u32::from_be_bytes([
            payload_bytes[offset],
            payload_bytes[offset + 1],
            payload_bytes[offset + 2],
            payload_bytes[offset + 3],
        ]) as usize;

        let chunk_flags =
            u16::from_be_bytes([payload_bytes[offset + 4], payload_bytes[offset + 5]]);

        let is_final = chunk_flags & 0x0001 != 0;

        offset = offset
            .checked_add(8)
            .and_then(|o| o.checked_add(ciphertext_len))
            .and_then(|o| o.checked_add(tag_size))
            .ok_or(RewrapError::LayoutOverflow)?;

        if is_final {
            break;
        }

        if offset >= payload_bytes.len() {
            return Err(RewrapError::PayloadNoFinalChunk);
        }
    }

    payload_offset
        .checked_add(offset)
        .ok_or(RewrapError::LayoutOverflow)
}

/// Build a new `FixedHeader` from `original`, updating only the fields that
/// depend on the new wraps section size.
fn build_new_fixed_header(
    original: &FixedHeader,
    _new_policy: &PolicySection,
    new_entry_sizes: &[(usize, usize)],
) -> Result<FixedHeader, RewrapError> {
    let new_wraps_len = compute_wraps_section_len(new_entry_sizes);
    let new_wraps_len_u32 =
        u32::try_from(new_wraps_len).map_err(|_| RewrapError::HeaderFieldOverflow)?;

    let new_payload_offset = (FIXED_HEADER_LEN as u64)
        .checked_add(POLICY_SECTION_LEN as u64)
        .and_then(|o| o.checked_add(new_wraps_len as u64))
        .and_then(|o| o.checked_add(original.metadata_len as u64))
        .ok_or(RewrapError::LayoutOverflow)?;

    Ok(FixedHeader {
        format_version_major: original.format_version_major,
        format_version_minor: original.format_version_minor,
        suite_id: original.suite_id,
        flags: original.flags,
        header_len: original.header_len,
        policy_len: POLICY_SECTION_LEN as u32,
        wraps_len: new_wraps_len_u32,
        metadata_len: original.metadata_len,
        payload_offset: new_payload_offset,
    })
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::kdf::{derive_root_key, derive_subkeys};
    use crate::crypto::metadata::encrypt_metadata;
    use crate::crypto::secret::fmk_from_bytes;
    use crate::crypto::verify::{build_footer, verify_container_no_decrypt};
    use crate::format::metadata_plaintext::{MetadataPlaintext, PaddingBucket};
    use crate::format::payload::CHUNK_FLAG_FINAL;

    fn test_fmk() -> Fmk {
        fmk_from_bytes([0x55u8; 32])
    }

    fn test_file_uuid() -> [u8; 16] {
        [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10,
        ]
    }

    fn dummy_wrapper_entry(id: &[u8], stanza_len: usize) -> WrapperEntry {
        WrapperEntry {
            wrapper_type: 0x0002,
            wrapper_flags: 0,
            wrapper_id: id.to_vec(),
            stanza: vec![0xAA; stanza_len],
        }
    }

    /// Build a minimal but structurally valid synthetic container with real encrypted metadata.
    ///
    /// The metadata section is raw crypto bytes (nonce || AEAD_ct), matching the format
    /// written by `ops::encrypt::encrypt`.
    fn build_test_container(fmk: &Fmk, file_uuid: &[u8; 16]) -> Vec<u8> {
        let policy = PolicySection {
            policy_version: 1,
            threshold: 1,
            total_shares: 1,
            wrapper_count: 1,
        };
        let policy_bytes = policy.encode().unwrap();

        let initial_wrapper = dummy_wrapper_entry(b"alice", 94);
        let wraps = WrapsSection {
            wraps_version: 1,
            wrappers: vec![initial_wrapper],
        };
        let wraps_bytes = wraps.encode().unwrap();

        // Minimal payload: 16-byte header + 1 final chunk.
        let chunk_ct = vec![0xCC; 48];
        let tag = vec![0xDD; 16];
        let mut payload = Vec::new();
        payload.extend_from_slice(&1u16.to_be_bytes());
        payload.extend_from_slice(&0u16.to_be_bytes());
        payload.extend_from_slice(&64u32.to_be_bytes());
        payload.extend_from_slice(&16u32.to_be_bytes());
        payload.extend_from_slice(&[0u8; 4]);
        payload.extend_from_slice(&(48u32).to_be_bytes());
        payload.extend_from_slice(&CHUNK_FLAG_FINAL.to_be_bytes());
        payload.extend_from_slice(&[0u8; 2]);
        payload.extend_from_slice(&chunk_ct);
        payload.extend_from_slice(&tag);

        let manifest_root = [0xEEu8; 32];
        let meta_plain = MetadataPlaintext {
            plaintext_size: 0,
            logical_name: None,
            mime_type: None,
            created_at: None,
            chunk_size: 64,
            epoch_size: 256,
            manifest_root,
            payload_mode: 0,
            padding_bucket: PaddingBucket::None,
        };

        let root_key = derive_root_key(fmk, file_uuid);
        let subkeys = derive_subkeys(&root_key);
        let k_control = SecretKey32::from_bytes(*subkeys.k_control.expose());

        // Pass 1: encrypt with dummy header_hash to learn metadata_len.
        // The metadata section in the container is raw crypto bytes (nonce || AEAD_ct).
        let dummy_hash = [0u8; 32];
        let dummy_ct =
            encrypt_metadata(&k_control, &meta_plain, file_uuid, 0x0001, &dummy_hash).unwrap();
        let metadata_len = dummy_ct.len() as u32;

        // Build the fixed header with the real metadata_len.
        let policy_len = policy_bytes.len() as u32;
        let wraps_len = wraps_bytes.len() as u32;
        let payload_offset =
            FIXED_HEADER_LEN as u64 + policy_len as u64 + wraps_len as u64 + metadata_len as u64;
        let fh = FixedHeader {
            format_version_major: 1,
            format_version_minor: 0,
            suite_id: 0x0001,
            flags: 0,
            header_len: FIXED_HEADER_LEN as u32,
            policy_len,
            wraps_len,
            metadata_len,
            payload_offset,
        };

        // Pass 2: encrypt metadata with real header_hash.
        let real_header_hash: [u8; 32] = *blake3::hash(&fh.encode()).as_bytes();
        let metadata_bytes = encrypt_metadata(
            &k_control,
            &meta_plain,
            file_uuid,
            0x0001,
            &real_header_hash,
        )
        .unwrap();

        // Assemble pre-footer.
        let mut pre_footer = Vec::new();
        pre_footer.extend_from_slice(&fh.encode());
        pre_footer.extend_from_slice(&policy_bytes);
        pre_footer.extend_from_slice(&wraps_bytes);
        pre_footer.extend_from_slice(&metadata_bytes);
        pre_footer.extend_from_slice(&payload);

        let footer = build_footer(&subkeys.k_manifest, manifest_root, &pre_footer);
        pre_footer.extend_from_slice(&footer);
        pre_footer
    }

    // ── compute_wraps_section_len ─────────────────────────────────────────

    #[test]
    fn wraps_section_len_empty() {
        assert_eq!(compute_wraps_section_len(&[]), WRAPS_HEADER_LEN);
    }

    #[test]
    fn wraps_section_len_single_entry() {
        // 4 header + 8 entry_header + 5 id + 94 stanza = 111
        let sizes = vec![(5, 94)];
        assert_eq!(compute_wraps_section_len(&sizes), 4 + 8 + 5 + 94);
    }

    #[test]
    fn wraps_section_len_matches_encoded() {
        let entries = vec![
            dummy_wrapper_entry(b"alice", 94),
            dummy_wrapper_entry(b"bob", 110),
        ];
        let wraps = WrapsSection {
            wraps_version: 1,
            wrappers: entries.clone(),
        };
        let encoded = wraps.encode().unwrap();
        let sizes: Vec<(usize, usize)> = entries
            .iter()
            .map(|e| (e.wrapper_id.len(), e.stanza.len()))
            .collect();
        assert_eq!(compute_wraps_section_len(&sizes), encoded.len());
    }

    // ── compute_rewrap_header_hash ────────────────────────────────────────

    #[test]
    fn rewrap_header_hash_is_deterministic() {
        let container = build_test_container(&test_fmk(), &test_file_uuid());
        let orig_fh = FixedHeader::parse(&container[..FIXED_HEADER_LEN]).unwrap();
        let new_policy = PolicySection {
            policy_version: 1,
            threshold: 1,
            total_shares: 1,
            wrapper_count: 1,
        };
        let sizes = vec![(5usize, 94usize)];
        let h1 = compute_rewrap_header_hash(&orig_fh, &new_policy, &sizes).unwrap();
        let h2 = compute_rewrap_header_hash(&orig_fh, &new_policy, &sizes).unwrap();
        assert_eq!(h1, h2);
    }

    #[test]
    fn rewrap_header_hash_changes_with_different_stanza_sizes() {
        let container = build_test_container(&test_fmk(), &test_file_uuid());
        let orig_fh = FixedHeader::parse(&container[..FIXED_HEADER_LEN]).unwrap();
        let new_policy = PolicySection {
            policy_version: 1,
            threshold: 1,
            total_shares: 1,
            wrapper_count: 1,
        };
        let h1 = compute_rewrap_header_hash(&orig_fh, &new_policy, &[(5, 94)]).unwrap();
        let h2 = compute_rewrap_header_hash(&orig_fh, &new_policy, &[(5, 110)]).unwrap();
        assert_ne!(h1, h2);
    }

    // ── rewrap_container — structural correctness ─────────────────────────

    #[test]
    fn rewrap_produces_valid_fixed_header() {
        let fmk = test_fmk();
        let uuid = test_file_uuid();
        let container = build_test_container(&fmk, &uuid);

        let new_policy = PolicySection {
            policy_version: 1,
            threshold: 1,
            total_shares: 1,
            wrapper_count: 1,
        };
        let new_wrappers = vec![dummy_wrapper_entry(b"bob", 94)];

        let result = rewrap_container(&container, &fmk, &uuid, new_policy, new_wrappers).unwrap();

        let new_fh = FixedHeader::parse(&result[..FIXED_HEADER_LEN]).unwrap();
        assert_eq!(new_fh.format_version_major, 1);
        assert_eq!(new_fh.suite_id, 0x0001);
        assert_eq!(new_fh.policy_len, POLICY_SECTION_LEN as u32);
    }

    #[test]
    fn rewrap_footer_auth_tag_passes_verification() {
        let fmk = test_fmk();
        let uuid = test_file_uuid();
        let container = build_test_container(&fmk, &uuid);

        let new_policy = PolicySection {
            policy_version: 1,
            threshold: 1,
            total_shares: 1,
            wrapper_count: 1,
        };
        let new_wrappers = vec![dummy_wrapper_entry(b"carol", 94)];
        let result = rewrap_container(&container, &fmk, &uuid, new_policy, new_wrappers).unwrap();

        // Derive k_manifest and verify the new footer.
        let root_key = derive_root_key(&fmk, &uuid);
        let subkeys = derive_subkeys(&root_key);

        // Find footer start in the result container.
        let new_fh = FixedHeader::parse(&result[..FIXED_HEADER_LEN]).unwrap();
        let footer_start = scan_payload_end(&result, new_fh.payload_offset as usize).unwrap();

        let pre_footer = &result[..footer_start];
        let footer_bytes = &result[footer_start..];

        verify_container_no_decrypt(&subkeys.k_manifest, pre_footer, footer_bytes)
            .expect("footer auth_tag must be valid after rewrap");
    }

    #[test]
    fn rewrap_preserves_payload_bytes() {
        let fmk = test_fmk();
        let uuid = test_file_uuid();
        let container = build_test_container(&fmk, &uuid);

        let orig_fh = FixedHeader::parse(&container[..FIXED_HEADER_LEN]).unwrap();
        let orig_payload_end =
            scan_payload_end(&container, orig_fh.payload_offset as usize).unwrap();
        let orig_payload = &container[orig_fh.payload_offset as usize..orig_payload_end];

        let new_policy = PolicySection {
            policy_version: 1,
            threshold: 1,
            total_shares: 1,
            wrapper_count: 1,
        };
        let new_wrappers = vec![dummy_wrapper_entry(b"dave", 110)];
        let result = rewrap_container(&container, &fmk, &uuid, new_policy, new_wrappers).unwrap();

        let new_fh = FixedHeader::parse(&result[..FIXED_HEADER_LEN]).unwrap();
        let new_payload_end = scan_payload_end(&result, new_fh.payload_offset as usize).unwrap();
        let new_payload = &result[new_fh.payload_offset as usize..new_payload_end];

        assert_eq!(
            orig_payload, new_payload,
            "payload bytes must be identical after rewrap"
        );
    }

    #[test]
    fn rewrap_preserves_metadata_content() {
        // After rewrap the raw metadata bytes change (ciphertext re-keyed to new header_hash),
        // but the decrypted content must remain identical.
        use crate::crypto::kdf::{derive_root_key, derive_subkeys};
        use crate::crypto::metadata::decrypt_metadata;

        let fmk = test_fmk();
        let uuid = test_file_uuid();
        let container = build_test_container(&fmk, &uuid);

        let new_policy = PolicySection {
            policy_version: 1,
            threshold: 1,
            total_shares: 1,
            wrapper_count: 1,
        };
        let new_wrappers = vec![dummy_wrapper_entry(b"eve", 94)];
        let result = rewrap_container(&container, &fmk, &uuid, new_policy, new_wrappers).unwrap();

        // Verify raw bytes differ (re-encrypted under new header_hash).
        let orig_fh = FixedHeader::parse(&container[..FIXED_HEADER_LEN]).unwrap();
        let orig_meta_start =
            FIXED_HEADER_LEN + orig_fh.policy_len as usize + orig_fh.wraps_len as usize;
        let orig_meta =
            &container[orig_meta_start..orig_meta_start + orig_fh.metadata_len as usize];

        let new_fh = FixedHeader::parse(&result[..FIXED_HEADER_LEN]).unwrap();
        let new_meta_start =
            FIXED_HEADER_LEN + new_fh.policy_len as usize + new_fh.wraps_len as usize;
        let new_meta = &result[new_meta_start..new_meta_start + new_fh.metadata_len as usize];

        assert_ne!(
            orig_meta, new_meta,
            "metadata bytes must differ after rewrap (re-encrypted)"
        );
        assert_eq!(
            orig_fh.metadata_len, new_fh.metadata_len,
            "metadata_len must stay the same"
        );

        // Verify decrypted content is the same.
        let root_key = derive_root_key(&fmk, &uuid);
        let subkeys = derive_subkeys(&root_key);
        let k_control = SecretKey32::from_bytes(*subkeys.k_control.expose());

        let orig_hash: [u8; 32] = *blake3::hash(&container[..FIXED_HEADER_LEN]).as_bytes();
        let orig_plain =
            decrypt_metadata(&k_control, orig_meta, &uuid, 0x0001, &orig_hash).unwrap();

        let new_hash: [u8; 32] = *blake3::hash(&result[..FIXED_HEADER_LEN]).as_bytes();
        let new_plain = decrypt_metadata(&k_control, new_meta, &uuid, 0x0001, &new_hash).unwrap();

        assert_eq!(orig_plain.plaintext_size, new_plain.plaintext_size);
        assert_eq!(orig_plain.logical_name, new_plain.logical_name);
        assert_eq!(orig_plain.chunk_size, new_plain.chunk_size);
    }

    #[test]
    fn rewrap_manifest_root_preserved() {
        let fmk = test_fmk();
        let uuid = test_file_uuid();
        let container = build_test_container(&fmk, &uuid);

        let new_policy = PolicySection {
            policy_version: 1,
            threshold: 1,
            total_shares: 1,
            wrapper_count: 1,
        };
        let new_wrappers = vec![dummy_wrapper_entry(b"frank", 94)];
        let result = rewrap_container(&container, &fmk, &uuid, new_policy, new_wrappers).unwrap();

        // Extract manifest_root from both containers' footers.
        let orig_fh = FixedHeader::parse(&container[..FIXED_HEADER_LEN]).unwrap();
        let orig_footer_start =
            scan_payload_end(&container, orig_fh.payload_offset as usize).unwrap();
        let orig_footer = FooterSection::parse(&container[orig_footer_start..]).unwrap();

        let new_fh = FixedHeader::parse(&result[..FIXED_HEADER_LEN]).unwrap();
        let new_footer_start = scan_payload_end(&result, new_fh.payload_offset as usize).unwrap();
        let new_footer = FooterSection::parse(&result[new_footer_start..]).unwrap();

        assert_eq!(
            orig_footer.manifest_root, new_footer.manifest_root,
            "manifest_root must be preserved after rewrap"
        );
    }

    #[test]
    fn rewrap_updates_wraps_section() {
        let fmk = test_fmk();
        let uuid = test_file_uuid();
        let container = build_test_container(&fmk, &uuid);

        let new_policy = PolicySection {
            policy_version: 1,
            threshold: 1,
            total_shares: 1,
            wrapper_count: 1,
        };
        let new_wrappers = vec![dummy_wrapper_entry(b"grace", 94)];
        let result = rewrap_container(&container, &fmk, &uuid, new_policy, new_wrappers).unwrap();

        let new_fh = FixedHeader::parse(&result[..FIXED_HEADER_LEN]).unwrap();
        let wraps_start = FIXED_HEADER_LEN + new_fh.policy_len as usize;
        let wraps_end = wraps_start + new_fh.wraps_len as usize;
        let wraps = WrapsSection::parse(&result[wraps_start..wraps_end]).unwrap();

        assert_eq!(wraps.wrappers.len(), 1);
        assert_eq!(wraps.wrappers[0].wrapper_id, b"grace");
    }

    #[test]
    fn rewrap_add_second_recipient() {
        let fmk = test_fmk();
        let uuid = test_file_uuid();
        let container = build_test_container(&fmk, &uuid);

        let new_policy = PolicySection {
            policy_version: 1,
            threshold: 1,
            total_shares: 1,
            wrapper_count: 2,
        };
        let new_wrappers = vec![
            dummy_wrapper_entry(b"alice", 94),
            dummy_wrapper_entry(b"bob", 94),
        ];
        let result = rewrap_container(&container, &fmk, &uuid, new_policy, new_wrappers).unwrap();

        let new_fh = FixedHeader::parse(&result[..FIXED_HEADER_LEN]).unwrap();
        let wraps_start = FIXED_HEADER_LEN + new_fh.policy_len as usize;
        let wraps_end = wraps_start + new_fh.wraps_len as usize;
        let wraps = WrapsSection::parse(&result[wraps_start..wraps_end]).unwrap();

        assert_eq!(wraps.wrappers.len(), 2);
    }

    #[test]
    fn rewrap_with_threshold_policy() {
        let fmk = test_fmk();
        let uuid = test_file_uuid();
        let container = build_test_container(&fmk, &uuid);

        let new_policy = PolicySection {
            policy_version: 1,
            threshold: 2,
            total_shares: 3,
            wrapper_count: 3,
        };
        let new_wrappers = vec![
            dummy_wrapper_entry(b"share-1", 65),
            dummy_wrapper_entry(b"share-2", 65),
            dummy_wrapper_entry(b"share-3", 65),
        ];
        let result = rewrap_container(&container, &fmk, &uuid, new_policy, new_wrappers).unwrap();

        let new_fh = FixedHeader::parse(&result[..FIXED_HEADER_LEN]).unwrap();
        let policy_bytes = &result[FIXED_HEADER_LEN..FIXED_HEADER_LEN + new_fh.policy_len as usize];
        let policy = PolicySection::parse(policy_bytes).unwrap();

        assert_eq!(policy.threshold, 2);
        assert_eq!(policy.total_shares, 3);
        assert_eq!(policy.wrapper_count, 3);
    }

    #[test]
    fn rewrap_policy_mismatch_returns_error() {
        let fmk = test_fmk();
        let uuid = test_file_uuid();
        let container = build_test_container(&fmk, &uuid);

        let new_policy = PolicySection {
            policy_version: 1,
            threshold: 2,
            total_shares: 3,
            wrapper_count: 3,
        };
        // Only 2 wrappers but policy requires 3 (total_shares = 3).
        let new_wrappers = vec![
            dummy_wrapper_entry(b"s1", 65),
            dummy_wrapper_entry(b"s2", 65),
        ];
        let err = rewrap_container(&container, &fmk, &uuid, new_policy, new_wrappers).unwrap_err();
        assert!(matches!(
            err,
            RewrapError::PolicyMismatch {
                wrapper_count: 2,
                total_shares: 3
            }
        ));
    }

    #[test]
    fn rewrap_container_too_short_returns_error() {
        let fmk = test_fmk();
        let uuid = test_file_uuid();
        let new_policy = PolicySection {
            policy_version: 1,
            threshold: 1,
            total_shares: 1,
            wrapper_count: 1,
        };
        let err = rewrap_container(&[0u8; 10], &fmk, &uuid, new_policy, vec![]).unwrap_err();
        assert!(matches!(err, RewrapError::ContainerTooShort));
    }

    #[test]
    fn rewrap_different_fmk_produces_invalid_footer() {
        let fmk = test_fmk();
        let wrong_fmk = fmk_from_bytes([0x99u8; 32]);
        let uuid = test_file_uuid();
        let container = build_test_container(&fmk, &uuid);

        let new_policy = PolicySection {
            policy_version: 1,
            threshold: 1,
            total_shares: 1,
            wrapper_count: 1,
        };
        let new_wrappers = vec![dummy_wrapper_entry(b"x", 94)];

        // Since §18: rewrap now verifies the original footer auth_tag before rewriting.
        // Passing a wrong FMK causes the original verification to fail immediately.
        let err =
            rewrap_container(&container, &wrong_fmk, &uuid, new_policy, new_wrappers).unwrap_err();

        assert!(
            matches!(err, RewrapError::InvalidOriginalContainer),
            "expected InvalidOriginalContainer, got {err:?}"
        );
    }

    // ── scan_payload_end ──────────────────────────────────────────────────

    #[test]
    fn scan_payload_end_finds_footer_start() {
        let fmk = test_fmk();
        let uuid = test_file_uuid();
        let container = build_test_container(&fmk, &uuid);

        let orig_fh = FixedHeader::parse(&container[..FIXED_HEADER_LEN]).unwrap();
        let footer_start = scan_payload_end(&container, orig_fh.payload_offset as usize).unwrap();

        // Footer must be parseable at this offset.
        let footer_bytes = &container[footer_start..];
        FooterSection::parse(footer_bytes).expect("footer must parse at scan_payload_end result");
    }
}
