use hkdf::Hkdf;
use sha2::Sha512;

use crate::crypto::secret::{fmk_expose, Fmk, SecretKey32, SecretNonce24, SubkeySet};

// ── KDF labels ──────────────────────────────────────────────────────────────
//
// All labels are ASCII, null-free, and uniquely namespaced under the
// "hydralock:v1:" prefix. Changing any label is a breaking protocol change.

const LABEL_ROOT: &[u8] = b"hydralock:v1:root";
const LABEL_CONTROL: &[u8] = b"hydralock:v1:control";
const LABEL_MANIFEST: &[u8] = b"hydralock:v1:manifest";
const LABEL_PAYLOAD_MASTER: &[u8] = b"hydralock:v1:payload-master";
const LABEL_PADDING: &[u8] = b"hydralock:v1:padding";
const LABEL_REWRAP: &[u8] = b"hydralock:v1:rewrap";
const LABEL_CHUNK_KEY: &[u8] = b"hydralock:v1:chunk-key";
const LABEL_CHUNK_NONCE: &[u8] = b"hydralock:v1:chunk-nonce";

// ── Root key derivation ──────────────────────────────────────────────────────

/// Derive the file root key from the File Master Key and the file UUID.
///
/// Algorithm: HKDF-SHA-512(ikm=FMK, salt=file_uuid, info="hydralock:v1:root")
/// Output: 32 bytes.
///
/// The file UUID acts as the HKDF salt, providing per-file randomness without
/// requiring the FMK itself to be file-specific.
pub fn derive_root_key(fmk: &Fmk, file_uuid: &[u8; 16]) -> SecretKey32 {
    let hk = Hkdf::<Sha512>::new(Some(file_uuid.as_slice()), fmk_expose(fmk));
    let mut okm = [0u8; 32];
    hk.expand(LABEL_ROOT, &mut okm)
        .expect("32 bytes is a valid HKDF-SHA-512 output length");
    SecretKey32::from_bytes(okm)
}

// ── Subkey derivation ────────────────────────────────────────────────────────

/// Derive all five root subkeys from `root_key`.
///
/// Each subkey is derived independently via BLAKE3 in keyed-hash mode:
///   `subkey = BLAKE3_keyed(key=root_key, data=label)`
///
/// No two labels are the same, guaranteeing domain separation.
pub fn derive_subkeys(root_key: &SecretKey32) -> SubkeySet {
    SubkeySet {
        k_control: blake3_derive_label(root_key.expose(), LABEL_CONTROL),
        k_manifest: blake3_derive_label(root_key.expose(), LABEL_MANIFEST),
        k_payload_master: blake3_derive_label(root_key.expose(), LABEL_PAYLOAD_MASTER),
        k_padding: blake3_derive_label(root_key.expose(), LABEL_PADDING),
        k_rewrap: blake3_derive_label(root_key.expose(), LABEL_REWRAP),
    }
}

// ── Epoch-level derivation ───────────────────────────────────────────────────

/// Derive the key for epoch `epoch_index` from `k_payload_master`.
///
/// Algorithm: BLAKE3_keyed(key=k_payload_master, data=LABEL_CHUNK_KEY || u32_be(epoch_index))
///
/// Note: Both epoch-key and chunk-key derivation intentionally use `LABEL_CHUNK_KEY`.
/// Domain separation between the two levels is provided by the distinct input keys:
/// `k_payload_master` (KDF root) vs `k_epoch_i` (derived per-epoch). These can never
/// collide, so reusing the same label is safe and this choice is normative for v1.
pub fn derive_epoch_key(k_payload_master: &SecretKey32, epoch_index: u32) -> SecretKey32 {
    blake3_derive_indexed(k_payload_master.expose(), LABEL_CHUNK_KEY, epoch_index)
}

// ── Chunk-level derivation ───────────────────────────────────────────────────

/// Derive the encryption key for chunk `chunk_index` within an epoch.
///
/// Algorithm: BLAKE3_keyed(key=k_epoch, data=LABEL_CHUNK_KEY || u32_be(chunk_index))
pub fn derive_chunk_key(k_epoch: &SecretKey32, chunk_index: u32) -> SecretKey32 {
    blake3_derive_indexed(k_epoch.expose(), LABEL_CHUNK_KEY, chunk_index)
}

/// Derive the 24-byte nonce for chunk `chunk_index` within an epoch.
///
/// Algorithm: BLAKE3_keyed_xof(key=k_epoch, data=LABEL_CHUNK_NONCE || u32_be(chunk_index))
/// Output: 24 bytes via XOF mode (fills the nonce buffer deterministically).
pub fn derive_chunk_nonce(k_epoch: &SecretKey32, chunk_index: u32) -> SecretNonce24 {
    let mut h = blake3::Hasher::new_keyed(k_epoch.expose());
    h.update(LABEL_CHUNK_NONCE);
    h.update(&chunk_index.to_be_bytes());
    let mut out = [0u8; 24];
    h.finalize_xof().fill(&mut out);
    SecretNonce24::from_bytes(out)
}

// ── BLAKE3 primitives ────────────────────────────────────────────────────────

/// BLAKE3 keyed hash with a label only (no index).
///
/// `BLAKE3_keyed(key=key_32, data=label)`
fn blake3_derive_label(key: &[u8; 32], label: &[u8]) -> SecretKey32 {
    let mut h = blake3::Hasher::new_keyed(key);
    h.update(label);
    SecretKey32::from_bytes(*h.finalize().as_bytes())
}

/// BLAKE3 keyed hash with a label and a u32 big-endian index.
///
/// `BLAKE3_keyed(key=key_32, data=label || u32_be(index))`
fn blake3_derive_indexed(key: &[u8; 32], label: &[u8], index: u32) -> SecretKey32 {
    let mut h = blake3::Hasher::new_keyed(key);
    h.update(label);
    h.update(&index.to_be_bytes());
    SecretKey32::from_bytes(*h.finalize().as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::secret::fmk_from_bytes;

    fn test_fmk() -> Fmk {
        fmk_from_bytes([0x42u8; 32])
    }

    fn test_uuid() -> [u8; 16] {
        [0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01, 0x02, 0x03,
         0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B]
    }

    #[test]
    fn root_key_is_deterministic() {
        let fmk = test_fmk();
        let uuid = test_uuid();
        let k1 = derive_root_key(&fmk, &uuid);
        let k2 = derive_root_key(&fmk, &uuid);
        assert_eq!(k1.expose(), k2.expose());
    }

    #[test]
    fn root_key_differs_by_uuid() {
        let fmk = test_fmk();
        let uuid1 = [0x01u8; 16];
        let uuid2 = [0x02u8; 16];
        let k1 = derive_root_key(&fmk, &uuid1);
        let k2 = derive_root_key(&fmk, &uuid2);
        assert_ne!(k1.expose(), k2.expose());
    }

    #[test]
    fn subkeys_are_distinct() {
        let fmk = test_fmk();
        let uuid = test_uuid();
        let root = derive_root_key(&fmk, &uuid);
        let subs = derive_subkeys(&root);

        let all = [
            root.expose(),
            subs.k_control.expose(),
            subs.k_manifest.expose(),
            subs.k_payload_master.expose(),
            subs.k_padding.expose(),
            subs.k_rewrap.expose(),
        ];

        for i in 0..all.len() {
            for j in (i + 1)..all.len() {
                assert_ne!(all[i], all[j], "keys at index {i} and {j} must differ");
            }
        }
    }

    #[test]
    fn epoch_keys_are_distinct() {
        let fmk = test_fmk();
        let uuid = test_uuid();
        let root = derive_root_key(&fmk, &uuid);
        let subs = derive_subkeys(&root);
        let k0 = derive_epoch_key(&subs.k_payload_master, 0);
        let k1 = derive_epoch_key(&subs.k_payload_master, 1);
        assert_ne!(k0.expose(), k1.expose());
    }

    #[test]
    fn epoch_key_differs_from_payload_master() {
        let fmk = test_fmk();
        let uuid = test_uuid();
        let root = derive_root_key(&fmk, &uuid);
        let subs = derive_subkeys(&root);
        let k_epoch = derive_epoch_key(&subs.k_payload_master, 0);
        assert_ne!(k_epoch.expose(), subs.k_payload_master.expose());
    }

    #[test]
    fn chunk_keys_are_distinct() {
        let fmk = test_fmk();
        let uuid = test_uuid();
        let root = derive_root_key(&fmk, &uuid);
        let subs = derive_subkeys(&root);
        let k_epoch = derive_epoch_key(&subs.k_payload_master, 0);
        let kc0 = derive_chunk_key(&k_epoch, 0);
        let kc1 = derive_chunk_key(&k_epoch, 1);
        assert_ne!(kc0.expose(), kc1.expose());
    }

    #[test]
    fn chunk_key_differs_from_chunk_nonce() {
        let fmk = test_fmk();
        let uuid = test_uuid();
        let root = derive_root_key(&fmk, &uuid);
        let subs = derive_subkeys(&root);
        let k_epoch = derive_epoch_key(&subs.k_payload_master, 0);
        let kc = derive_chunk_key(&k_epoch, 0);
        let nc = derive_chunk_nonce(&k_epoch, 0);
        // Compare the first 24 bytes of the key with the nonce
        assert_ne!(&kc.expose()[..24], nc.expose());
    }

    #[test]
    fn nonces_are_distinct_across_chunks() {
        let fmk = test_fmk();
        let uuid = test_uuid();
        let root = derive_root_key(&fmk, &uuid);
        let subs = derive_subkeys(&root);
        let k_epoch = derive_epoch_key(&subs.k_payload_master, 0);
        let n0 = derive_chunk_nonce(&k_epoch, 0);
        let n1 = derive_chunk_nonce(&k_epoch, 1);
        assert_ne!(n0.expose(), n1.expose());
    }

    #[test]
    fn nonces_are_distinct_across_epochs() {
        let fmk = test_fmk();
        let uuid = test_uuid();
        let root = derive_root_key(&fmk, &uuid);
        let subs = derive_subkeys(&root);
        let k_epoch0 = derive_epoch_key(&subs.k_payload_master, 0);
        let k_epoch1 = derive_epoch_key(&subs.k_payload_master, 1);
        let n0 = derive_chunk_nonce(&k_epoch0, 0);
        let n1 = derive_chunk_nonce(&k_epoch1, 0);
        assert_ne!(n0.expose(), n1.expose());
    }
}
