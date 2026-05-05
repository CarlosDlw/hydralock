//! Footer authentication and full container verification.
//!
//! The footer auth_tag is a 32-byte BLAKE3 keyed MAC that authenticates all
//! container bytes preceding the footer section. This closes the integrity
//! chain:
//!
//!   chunk[i] → authenticated by XChaCha20-Poly1305 AEAD (per-chunk key)
//!   manifest_root → BLAKE3_keyed(k_manifest, chunk_hash[0] || ... || chunk_hash[n])
//!   footer auth_tag → BLAKE3_keyed(k_manifest, pre_footer_bytes)
//!
//! The `k_manifest` key binds both the manifest root and the footer auth_tag
//! to the specific file's KDF tree. An attacker who does not know the FMK
//! cannot forge either.
//!
//! Verify modes:
//!   - `verify_container`: full verify — checks footer auth_tag and manifest
//!     root against the provided encrypted chunks.
//!   - `verify_container_no_decrypt`: structural integrity only — checks the
//!     footer auth_tag without requiring access to decrypted plaintext.

use subtle::ConstantTimeEq;

use crate::crypto::manifest::{ManifestError, verify_manifest_root};
use crate::crypto::secret::SecretKey32;
use crate::format::footer::{FooterSection, FooterSectionError};

/// Errors during container verification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VerifyError {
    /// Footer could not be parsed.
    FooterParseFailed(FooterSectionError),
    /// The footer auth_tag does not match the computed MAC.
    FooterAuthTagMismatch,
    /// The manifest root stored in the footer does not match the computed root.
    ManifestRootMismatch,
    /// A manifest error (empty chunk list).
    ManifestError(ManifestError),
    /// The manifest_root field in the footer has an unexpected size (not 32 bytes).
    InvalidManifestRootSize { actual: usize },
    /// The auth_tag field in the footer has an unexpected size (not 32 bytes).
    InvalidAuthTagSize { actual: usize },
}

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for VerifyError {}

impl From<FooterSectionError> for VerifyError {
    fn from(e: FooterSectionError) -> Self {
        VerifyError::FooterParseFailed(e)
    }
}

impl From<ManifestError> for VerifyError {
    fn from(e: ManifestError) -> Self {
        VerifyError::ManifestError(e)
    }
}

// ── Footer auth_tag ──────────────────────────────────────────────────────────

/// Compute the 32-byte footer auth_tag.
///
/// Algorithm:
///   auth_tag = BLAKE3_keyed(k_manifest, pre_footer_bytes)
///
/// `pre_footer_bytes` must be every container byte that precedes the footer
/// section (i.e., header + policy + wraps + metadata + payload).
pub fn compute_footer_auth_tag(k_manifest: &SecretKey32, pre_footer_bytes: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_keyed(k_manifest.expose());
    hasher.update(pre_footer_bytes);
    *hasher.finalize().as_bytes()
}

/// Verify a footer auth_tag in constant time.
///
/// Returns `true` when `expected_tag` matches the computed MAC, `false`
/// otherwise. The comparison is constant-time regardless of the mismatch
/// position to prevent timing oracles.
pub fn verify_footer_auth_tag(
    k_manifest: &SecretKey32,
    pre_footer_bytes: &[u8],
    expected_tag: &[u8; 32],
) -> bool {
    let computed = compute_footer_auth_tag(k_manifest, pre_footer_bytes);
    computed.ct_eq(expected_tag).unwrap_u8() == 1
}

// ── Full container verify ────────────────────────────────────────────────────

/// Verify a container without decrypting the payload.
///
/// Checks:
///   1. Footer parses successfully.
///   2. `footer.auth_tag` is a valid BLAKE3 keyed MAC over `pre_footer_bytes`.
///   3. `footer.manifest_root` is exactly 32 bytes.
///
/// Does NOT verify the manifest root against the actual chunk ciphertexts —
/// use `verify_container` for that.
///
/// This is the cheapest structural integrity check. It requires only
/// `k_manifest`, not the FMK or any payload key.
pub fn verify_container_no_decrypt(
    k_manifest: &SecretKey32,
    pre_footer_bytes: &[u8],
    footer_bytes: &[u8],
) -> Result<(), VerifyError> {
    let footer = FooterSection::parse(footer_bytes)?;

    if footer.auth_tag.len() != 32 {
        return Err(VerifyError::InvalidAuthTagSize {
            actual: footer.auth_tag.len(),
        });
    }

    if footer.manifest_root.len() != 32 {
        return Err(VerifyError::InvalidManifestRootSize {
            actual: footer.manifest_root.len(),
        });
    }

    let expected: [u8; 32] = footer.auth_tag.try_into().unwrap();
    if !verify_footer_auth_tag(k_manifest, pre_footer_bytes, &expected) {
        return Err(VerifyError::FooterAuthTagMismatch);
    }

    Ok(())
}

/// Verify a container fully: footer auth_tag + manifest root.
///
/// Checks:
///   1. Footer parses successfully.
///   2. `footer.auth_tag` is a valid BLAKE3 keyed MAC over `pre_footer_bytes`.
///   3. `footer.manifest_root` matches the recomputed root from `chunk_ciphertexts`.
///
/// `chunk_ciphertexts` must be the full list of encrypted chunks (including
/// their AEAD tags) in the order they appear in the payload section.
pub fn verify_container(
    k_manifest: &SecretKey32,
    pre_footer_bytes: &[u8],
    footer_bytes: &[u8],
    chunk_ciphertexts: &[impl AsRef<[u8]>],
) -> Result<(), VerifyError> {
    let footer = FooterSection::parse(footer_bytes)?;

    if footer.auth_tag.len() != 32 {
        return Err(VerifyError::InvalidAuthTagSize {
            actual: footer.auth_tag.len(),
        });
    }

    if footer.manifest_root.len() != 32 {
        return Err(VerifyError::InvalidManifestRootSize {
            actual: footer.manifest_root.len(),
        });
    }

    // Verify footer auth_tag.
    let expected_tag: [u8; 32] = footer.auth_tag.try_into().unwrap();
    if !verify_footer_auth_tag(k_manifest, pre_footer_bytes, &expected_tag) {
        return Err(VerifyError::FooterAuthTagMismatch);
    }

    // Verify manifest root.
    let expected_root: [u8; 32] = footer.manifest_root.try_into().unwrap();
    let ok = verify_manifest_root(k_manifest, chunk_ciphertexts, &expected_root)?;
    if !ok {
        return Err(VerifyError::ManifestRootMismatch);
    }

    Ok(())
}

// ── Helpers for building a valid footer ─────────────────────────────────────

/// Build and encode a valid FooterSection with computed auth_tag.
///
/// `manifest_root` is typically produced by `ManifestBuilder::finalize()`.
/// `pre_footer_bytes` is the concatenation of all container bytes before the footer.
pub fn build_footer(
    k_manifest: &SecretKey32,
    manifest_root: [u8; 32],
    pre_footer_bytes: &[u8],
) -> Vec<u8> {
    let auth_tag = compute_footer_auth_tag(k_manifest, pre_footer_bytes);

    let footer = FooterSection {
        footer_version: 1,
        flags: 0,
        manifest_root: manifest_root.to_vec(),
        auth_tag: auth_tag.to_vec(),
    };

    footer.encode().expect("footer fields are valid")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::manifest::ManifestBuilder;
    use crate::format::payload_writer::PayloadWriter;

    fn test_k_manifest() -> SecretKey32 {
        SecretKey32::from_bytes([0xEEu8; 32])
    }

    fn test_pre_footer() -> Vec<u8> {
        b"fake_header|fake_policy|fake_wraps|fake_metadata|fake_payload".to_vec()
    }

    // ── compute / verify footer auth_tag ──────────────────────────────────

    #[test]
    fn auth_tag_is_deterministic() {
        let k = test_k_manifest();
        let data = test_pre_footer();
        let t1 = compute_footer_auth_tag(&k, &data);
        let t2 = compute_footer_auth_tag(&k, &data);
        assert_eq!(t1, t2);
        assert_eq!(t1.len(), 32);
    }

    #[test]
    fn auth_tag_changes_with_data() {
        let k = test_k_manifest();
        let data = test_pre_footer();
        let mut modified = data.clone();
        modified[0] ^= 0x01;

        let t1 = compute_footer_auth_tag(&k, &data);
        let t2 = compute_footer_auth_tag(&k, &modified);
        assert_ne!(t1, t2);
    }

    #[test]
    fn auth_tag_changes_with_key() {
        let k1 = test_k_manifest();
        let k2 = SecretKey32::from_bytes([0xFFu8; 32]);
        let data = test_pre_footer();

        let t1 = compute_footer_auth_tag(&k1, &data);
        let t2 = compute_footer_auth_tag(&k2, &data);
        assert_ne!(t1, t2);
    }

    #[test]
    fn verify_footer_auth_tag_passes() {
        let k = test_k_manifest();
        let data = test_pre_footer();
        let tag = compute_footer_auth_tag(&k, &data);
        assert!(verify_footer_auth_tag(&k, &data, &tag));
    }

    #[test]
    fn verify_footer_auth_tag_fails_wrong_data() {
        let k = test_k_manifest();
        let data = test_pre_footer();
        let tag = compute_footer_auth_tag(&k, &data);
        let mut wrong = data.clone();
        wrong.push(0x00);
        assert!(!verify_footer_auth_tag(&k, &wrong, &tag));
    }

    #[test]
    fn verify_footer_auth_tag_fails_wrong_key() {
        let k = test_k_manifest();
        let k_wrong = SecretKey32::from_bytes([0x00u8; 32]);
        let data = test_pre_footer();
        let tag = compute_footer_auth_tag(&k, &data);
        assert!(!verify_footer_auth_tag(&k_wrong, &data, &tag));
    }

    // ── build_footer helper ───────────────────────────────────────────────

    #[test]
    fn build_footer_produces_parseable_bytes() {
        let k = test_k_manifest();
        let root = [0xABu8; 32];
        let pre_footer = test_pre_footer();

        let footer_bytes = build_footer(&k, root, &pre_footer);
        let parsed = FooterSection::parse(&footer_bytes).expect("footer must parse");

        assert_eq!(parsed.footer_version, 1);
        assert_eq!(parsed.manifest_root, root.to_vec());
        assert_eq!(parsed.auth_tag.len(), 32);
    }

    // ── verify_container_no_decrypt ───────────────────────────────────────

    #[test]
    fn no_decrypt_verify_passes() {
        let k = test_k_manifest();
        let pre_footer = test_pre_footer();
        let root = [0xCDu8; 32];

        let footer_bytes = build_footer(&k, root, &pre_footer);
        verify_container_no_decrypt(&k, &pre_footer, &footer_bytes).expect("verify must pass");
    }

    #[test]
    fn no_decrypt_verify_fails_tampered_pre_footer() {
        let k = test_k_manifest();
        let pre_footer = test_pre_footer();
        let root = [0xCDu8; 32];

        let footer_bytes = build_footer(&k, root, &pre_footer);

        let mut tampered = pre_footer.clone();
        tampered[0] ^= 0x01;

        let err = verify_container_no_decrypt(&k, &tampered, &footer_bytes);
        assert!(matches!(err, Err(VerifyError::FooterAuthTagMismatch)));
    }

    #[test]
    fn no_decrypt_verify_fails_tampered_footer() {
        let k = test_k_manifest();
        let pre_footer = test_pre_footer();
        let root = [0xCDu8; 32];

        let mut footer_bytes = build_footer(&k, root, &pre_footer);
        // Flip a bit in the auth_tag area (last 32 bytes).
        let last = footer_bytes.len() - 1;
        footer_bytes[last] ^= 0x01;

        let err = verify_container_no_decrypt(&k, &pre_footer, &footer_bytes);
        assert!(matches!(err, Err(VerifyError::FooterAuthTagMismatch)));
    }

    #[test]
    fn no_decrypt_verify_fails_wrong_key() {
        let k = test_k_manifest();
        let k_wrong = SecretKey32::from_bytes([0x01u8; 32]);
        let pre_footer = test_pre_footer();
        let root = [0xCDu8; 32];

        let footer_bytes = build_footer(&k, root, &pre_footer);

        let err = verify_container_no_decrypt(&k_wrong, &pre_footer, &footer_bytes);
        assert!(matches!(err, Err(VerifyError::FooterAuthTagMismatch)));
    }

    // ── verify_container (full) ───────────────────────────────────────────

    fn make_chunks_and_manifest_root(k_manifest: &SecretKey32) -> (Vec<Vec<u8>>, [u8; 32]) {
        let k_payload_master = SecretKey32::from_bytes([0x77u8; 32]);
        let plaintext: Vec<u8> = (0u8..=255u8).cycle().take(300).collect();

        let mut writer = PayloadWriter::new(
            k_payload_master,
            [0x88u8; 16],
            0x01,
            64,
            100,
            plaintext.len() as u64,
        )
        .unwrap();
        writer.write(&plaintext).unwrap();
        let chunks = writer.finalize().unwrap();

        let mut builder = ManifestBuilder::new(k_manifest.clone());
        let ciphertexts: Vec<Vec<u8>> = chunks
            .iter()
            .map(|c| {
                builder.add_chunk(&c.ciphertext_with_tag);
                c.ciphertext_with_tag.clone()
            })
            .collect();
        let root = builder.finalize().unwrap();

        (ciphertexts, root)
    }

    #[test]
    fn full_verify_passes() {
        let k = test_k_manifest();
        let (chunks, root) = make_chunks_and_manifest_root(&k);
        let pre_footer = test_pre_footer();

        let footer_bytes = build_footer(&k, root, &pre_footer);

        verify_container(&k, &pre_footer, &footer_bytes, &chunks).expect("full verify must pass");
    }

    #[test]
    fn full_verify_fails_tampered_chunk() {
        let k = test_k_manifest();
        let (mut chunks, root) = make_chunks_and_manifest_root(&k);
        let pre_footer = test_pre_footer();

        let footer_bytes = build_footer(&k, root, &pre_footer);

        // Tamper with one chunk ciphertext.
        if let Some(first) = chunks.first_mut() {
            first[0] ^= 0x01;
        }

        let err = verify_container(&k, &pre_footer, &footer_bytes, &chunks);
        assert!(matches!(err, Err(VerifyError::ManifestRootMismatch)));
    }

    #[test]
    fn full_verify_fails_tampered_pre_footer() {
        let k = test_k_manifest();
        let (chunks, root) = make_chunks_and_manifest_root(&k);
        let pre_footer = test_pre_footer();

        let footer_bytes = build_footer(&k, root, &pre_footer);

        let mut tampered_pre = pre_footer.clone();
        tampered_pre[0] ^= 0x01;

        let err = verify_container(&k, &tampered_pre, &footer_bytes, &chunks);
        assert!(matches!(err, Err(VerifyError::FooterAuthTagMismatch)));
    }

    #[test]
    fn full_verify_fails_mismatched_manifest_root() {
        let k = test_k_manifest();
        let (chunks, _root) = make_chunks_and_manifest_root(&k);
        let pre_footer = test_pre_footer();

        // Build footer with a wrong manifest root.
        let wrong_root = [0xFFu8; 32];
        let footer_bytes = build_footer(&k, wrong_root, &pre_footer);

        let err = verify_container(&k, &pre_footer, &footer_bytes, &chunks);
        assert!(matches!(err, Err(VerifyError::ManifestRootMismatch)));
    }

    #[test]
    fn full_verify_fails_wrong_key() {
        let k = test_k_manifest();
        let k_wrong = SecretKey32::from_bytes([0x01u8; 32]);
        let (chunks, root) = make_chunks_and_manifest_root(&k);
        let pre_footer = test_pre_footer();

        let footer_bytes = build_footer(&k, root, &pre_footer);

        let err = verify_container(&k_wrong, &pre_footer, &footer_bytes, &chunks);
        assert!(matches!(err, Err(VerifyError::FooterAuthTagMismatch)));
    }
}
