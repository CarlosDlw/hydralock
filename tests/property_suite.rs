use hydralock::crypto::kdf::{
    derive_chunk_key, derive_chunk_nonce, derive_epoch_key, derive_root_key, derive_subkeys,
};
use hydralock::crypto::secret::{SecretKey32, fmk_from_bytes};
use hydralock::format::header::{FIXED_HEADER_LEN, FixedHeader};
use hydralock::format::policy::PolicySection;
use hydralock::format::wraps::{WrapperEntry, WrapsSection};
use hydralock::wrapper::threshold::{open as threshold_open, seal as threshold_seal};
use proptest::prelude::*;
use rand::{SeedableRng, rngs::StdRng};

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    #[test]
    fn prop_parser_fixed_header_roundtrip(
        major in any::<u16>(),
        minor in any::<u16>(),
        suite_id in any::<u16>(),
        flags in any::<u32>(),
        header_extra in 0u32..256,
        policy_len in 0u32..65536,
        wraps_len in 0u32..65536,
        metadata_len in 0u32..65536,
    ) {
        let header_len = (FIXED_HEADER_LEN as u32) + header_extra;
        let payload_offset =
            (header_len as u64) + (policy_len as u64) + (wraps_len as u64) + (metadata_len as u64);

        let header = FixedHeader {
            format_version_major: major,
            format_version_minor: minor,
            suite_id,
            flags,
            header_len,
            policy_len,
            wraps_len,
            metadata_len,
            payload_offset,
        };

        let encoded = header.encode();
        let decoded = FixedHeader::parse(&encoded).expect("valid encoded header must parse");
        prop_assert_eq!(decoded, header);
    }

    #[test]
    fn prop_canonical_policy_parse_encode(
        threshold in 1u8..8,
        total_shares in 1u8..8,
        wrapper_count in 1u16..16,
    ) {
        prop_assume!(threshold <= total_shares);
        prop_assume!(wrapper_count >= total_shares as u16);

        let policy = PolicySection {
            policy_version: 1,
            threshold,
            total_shares,
            wrapper_count,
        };

        let bytes1 = policy.encode().expect("valid policy must encode");
        let parsed = PolicySection::parse(&bytes1).expect("encoded policy must parse");
        let bytes2 = parsed.encode().expect("parsed policy must encode");
        prop_assert_eq!(bytes1, bytes2);
    }

    #[test]
    fn prop_canonical_wraps_parse_encode(
        wrapper_count in 1usize..5,
        type_seed in any::<u16>(),
        flags_seed in any::<u16>(),
        stanza_lens in prop::collection::vec(0usize..64, 1..5),
        id_suffixes in prop::collection::vec(any::<u8>(), 8..32),
    ) {
        let mut wrappers = Vec::new();
        for idx in 0..wrapper_count {
            let id = {
                let mut v = vec![idx as u8 + 1];
                v.extend(id_suffixes.iter().copied());
                v
            };

            let stanza_len = stanza_lens[idx % stanza_lens.len()];
            let stanza = vec![idx as u8; stanza_len];

            wrappers.push(WrapperEntry {
                wrapper_type: type_seed.wrapping_add(idx as u16),
                wrapper_flags: flags_seed.wrapping_add(idx as u16),
                wrapper_id: id,
                stanza,
            });
        }

        let wraps = WrapsSection {
            wraps_version: 1,
            wrappers,
        };

        let bytes1 = wraps.encode().expect("valid wraps must encode");
        let parsed = WrapsSection::parse(&bytes1).expect("encoded wraps must parse");
        let bytes2 = parsed.encode().expect("parsed wraps must encode");
        prop_assert_eq!(bytes1, bytes2);
    }

    #[test]
    fn prop_kdf_determinism_and_domain_separation(
        fmk_bytes in any::<[u8; 32]>(),
        file_uuid in any::<[u8; 16]>(),
        epoch_index in any::<u32>(),
        chunk_index in any::<u32>(),
    ) {
        let fmk = fmk_from_bytes(fmk_bytes);
        let root_a = derive_root_key(&fmk, &file_uuid);
        let root_b = derive_root_key(&fmk, &file_uuid);
        prop_assert_eq!(root_a.expose(), root_b.expose());

        let subkeys = derive_subkeys(&root_a);
        prop_assert_ne!(subkeys.k_control.expose(), subkeys.k_manifest.expose());
        prop_assert_ne!(subkeys.k_control.expose(), subkeys.k_payload_master.expose());
        prop_assert_ne!(subkeys.k_manifest.expose(), subkeys.k_payload_master.expose());

        let k_epoch_a = derive_epoch_key(&subkeys.k_payload_master, epoch_index);
        let k_epoch_b = derive_epoch_key(&subkeys.k_payload_master, epoch_index);
        prop_assert_eq!(k_epoch_a.expose(), k_epoch_b.expose());

        let chunk_key_a = derive_chunk_key(&k_epoch_a, chunk_index);
        let chunk_key_b = derive_chunk_key(&k_epoch_a, chunk_index);
        prop_assert_eq!(chunk_key_a.expose(), chunk_key_b.expose());

        let nonce_a = derive_chunk_nonce(&k_epoch_a, chunk_index);
        let nonce_b = derive_chunk_nonce(&k_epoch_a, chunk_index);
        prop_assert_eq!(nonce_a.expose(), nonce_b.expose());
    }

    #[test]
    fn prop_threshold_seal_open_roundtrip(
        secret in any::<[u8; 32]>(),
        share_root in any::<[u8; 32]>(),
        t in 1u8..5,
        n in 1u8..7,
        aad in prop::collection::vec(any::<u8>(), 0..64),
        seed in any::<u64>(),
    ) {
        prop_assume!(t <= n);

        let secret_key = SecretKey32::from_bytes(secret);
        let root_key = SecretKey32::from_bytes(share_root);

        let mut rng = StdRng::seed_from_u64(seed);
        let stanzas = threshold_seal(&secret_key, t, n, &root_key, &aad, &mut rng)
            .expect("threshold seal must succeed");

        let subset: Vec<_> = stanzas.iter().take(t as usize).cloned().collect();
        let recovered = threshold_open(&subset, &root_key, &aad)
            .expect("threshold open must succeed with t shares");

        prop_assert_eq!(recovered.expose(), secret_key.expose());
    }
}
