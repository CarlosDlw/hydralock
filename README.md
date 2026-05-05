# HydraLock

File encryption container with hybrid post-quantum key encapsulation and rewrap support.

---

## Table of Contents

1. [Threat Model](#1-threat-model)
2. [Design Overview](#2-design-overview)
3. [Cryptographic Design](#3-cryptographic-design)
   - 3.1 [Primitives](#31-primitives)
   - 3.2 [Key Hierarchy](#32-key-hierarchy)
   - 3.3 [Encryption Flow](#33-encryption-flow)
   - 3.4 [Hybrid KEM (ML-KEM-768 + X25519)](#34-hybrid-kem-ml-kem-768--x25519)
   - 3.5 [Rewrap Mechanism](#35-rewrap-mechanism)
4. [Container Format](#4-container-format)
   - 4.1 [Fixed Header](#41-fixed-header)
   - 4.2 [Policy Section](#42-policy-section)
   - 4.3 [Wraps Section](#43-wraps-section)
   - 4.4 [Metadata Section](#44-metadata-section)
   - 4.5 [Payload Section](#45-payload-section)
   - 4.6 [Footer Section](#46-footer-section)
5. [CLI Usage](#5-cli-usage)
      - 5.1 [Rust Library API](#51-rust-library-api)
6. [Build](#6-build)
7. [Performance Characteristics](#7-performance-characteristics)
8. [Security Considerations](#8-security-considerations)
9. [Limitations](#9-limitations)
10. [Interoperability](#10-interoperability)
11. [Testing](#11-testing)
12. [Roadmap](#12-roadmap)
13. [License](#13-license)
14. [References](#14-references)

---

## 1. Threat Model

### Protected against

| Scenario | Covered |
|---|---|
| Offline read of encrypted file on disk | Yes |
| Offline brute-force of passphrase | Yes — Argon2id with configurable cost |
| Harvest-now-decrypt-later (future quantum adversary) | Yes — ML-KEM-768 in every hybrid KEM |
| Payload tampering (bit-flip, truncation, reorder) | Yes — per-chunk AEAD + BLAKE3 manifest |
| Metadata tampering (logical name, MIME, timestamps) | Yes — AES-256-GCM-SIV with keyed AAD |
| Footer / container-level tampering | Yes — BLAKE3 keyed MAC over the entire pre-footer |
| Recipient list replacement without knowledge of FMK | Yes — wrapper stanzas include header_hash in AAD |

### Out of scope

- **Runtime compromise** (malicious process, keylogger, memory scraping) — key material is zeroized on drop, but a compromised runtime cannot be defended against.
- **Side-channel attacks at hardware level** — no constant-time guarantees beyond what the underlying Rust crates provide.
- **Deniability** — containers do not provide plausible deniability.
- **Streaming decryption** — the current implementation decrypts the entire container into memory before returning plaintext.
- **Multi-party threshold** — the policy section supports threshold encoding, but the Shamir share wrapper (`THRESHOLD`, type `0x0004`) is implemented at the primitive level and not yet exposed in the CLI.

---

## 2. Design Overview

A HydraLock container is a single binary file composed of six consecutive sections:

```
[ Fixed Header | Policy | Wraps | Metadata | Payload | Footer ]
```

- **Fixed Header** — 70-byte magic, version, suite ID, and section offsets.
- **Policy** — threshold and total-shares parameters for the access policy.
- **Wraps** — one or more key-encapsulation stanzas, each sealing a copy of the File Master Key (FMK). Any single stanza is sufficient to recover the FMK (threshold = 1 in the default policy).
- **Metadata** — CBOR-encoded plaintext metadata (logical name, MIME type, timestamps, chunk parameters) encrypted with AES-256-GCM-SIV under a key derived from the FMK.
- **Payload** — plaintext split into fixed-size chunks, each independently encrypted with XChaCha20-Poly1305. A per-epoch key ratchet limits key reuse.
- **Footer** — BLAKE3 manifest root (a keyed Merkle root over all ciphertext chunks) and a BLAKE3-keyed MAC over the entire pre-footer content.

Re-wrapping replaces only the Wraps, Policy, and Header sections, then recomputes the footer MAC. The payload ciphertexts and manifest root are preserved verbatim, making rewrap cost proportional to the number of recipients, not the payload size.

---

## 3. Cryptographic Design

### 3.1 Primitives

| Primitive | Role | Crate |
|---|---|---|
| XChaCha20-Poly1305 | Payload chunk AEAD | `chacha20poly1305 v0.10` |
| AES-256-GCM-SIV | Metadata AEAD (nonce-misuse resistant) | `aes-gcm-siv v0.11` |
| BLAKE3 (keyed) | Manifest, footer MAC, subkey derivation | `blake3 v1` |
| HKDF-SHA-512 | Root key derivation from FMK + file UUID | `hkdf v0.12` / `sha2 v0.10` |
| Argon2id | Passphrase-based key derivation | `argon2 v0.5` |
| X25519 | Classical asymmetric KEM | `x25519-dalek v2` |
| ML-KEM-768 | Post-quantum KEM (FIPS 203) | `ml-kem v0.3` |

All key material (FMK, root key, subkeys, secret scalars, ML-KEM seeds) is stored in types that implement `Zeroize + ZeroizeOnDrop`, ensuring secrets are cleared from memory when dropped.

### 3.2 Key Hierarchy

```
passphrase / X25519 SK / ML-KEM SK
         │
         ▼
   FMK (32 bytes, random)          ← sealed in one or more Wraps stanzas
         │
         ▼  HKDF-SHA-512(ikm=FMK, salt=file_uuid, info="hydralock:v1:root")
   Root Key (32 bytes)
         │
         ├─ BLAKE3_keyed("hydralock:v1:control")      → k_control       (metadata AEAD key)
         ├─ BLAKE3_keyed("hydralock:v1:manifest")     → k_manifest      (manifest + footer MAC key)
         ├─ BLAKE3_keyed("hydralock:v1:payload-master") → k_payload_master (epoch key derivation root)
         ├─ BLAKE3_keyed("hydralock:v1:padding")      → k_padding       (reserved)
         └─ BLAKE3_keyed("hydralock:v1:rewrap")       → k_rewrap        (reserved)

k_payload_master
         │
         ▼  BLAKE3_keyed("hydralock:v1:epoch" || u32_be(epoch_index))
   k_epoch[i]
         │
         ├─ BLAKE3_keyed("hydralock:v1:chunk-key"   || u32_be(chunk_index)) → chunk key   (32B)
         └─ BLAKE3_keyed("hydralock:v1:chunk-nonce" || u32_be(chunk_index)) → chunk nonce (24B XChaCha)
```

The `file_uuid` (16-byte random value, stored as the first 16 bytes of every `wrapper_id`) acts as the HKDF salt, providing per-file key isolation even if the same FMK were somehow reused.

### 3.3 Encryption Flow

1. **Generate secrets** — random FMK (32 bytes) and file UUID (16 bytes) from OS CSPRNG.
2. **Derive key tree** — HKDF-SHA-512 → root key → BLAKE3 subkeys.
3. **Compute header hash** — encode the fixed header (with correct section lengths) and hash it with BLAKE3. This binds wrapper and metadata AADs to the specific container layout.
4. **Encrypt payload** — split plaintext into `chunk_size`-byte blocks (default 64 KiB). For every `epoch_size` chunks (default 256), derive a new epoch key. Encrypt each chunk with XChaCha20-Poly1305 under its unique `(k_epoch, nonce)` pair. AAD per chunk: `magic || version || suite_id || file_uuid || epoch_index || chunk_index || plaintext_chunk_len || is_final_flag`. The payload AAD intentionally excludes `header_hash` so rewrap can preserve payload ciphertexts verbatim.
5. **Build manifest** — compute `manifest_root = BLAKE3_keyed(k_manifest, ct[0] || ct[1] || ... || ct[n])` using an incremental keyed hasher over all chunk ciphertexts (including Poly1305 tags).
6. **Encrypt metadata** — serialize metadata as CBOR, then encrypt with AES-256-GCM-SIV under `k_control`. Store the result as `nonce (12B) || ciphertext+tag`. AAD: `magic || version || suite_id || section_type=0x04 || file_uuid || header_hash`.
7. **Seal FMK into wrappers** — for each recipient, seal the FMK using the appropriate KEM (see §3.4). Each stanza AAD includes: `suite_id || wrapper_index || file_uuid || header_hash`.
8. **Assemble container** — concatenate all sections, then compute the footer auth tag: `BLAKE3_keyed(k_manifest, pre_footer_bytes)`.

### 3.4 Hybrid KEM (ML-KEM-768 + X25519)

The hybrid KEM combines a classical and a post-quantum shared secret, so security holds as long as **either** scheme is unbroken.

**Key encapsulation (seal):**

```
1. Sample ephemeral X25519 key pair: (eph_sk, eph_pk)
2. ss_x25519   = X25519(eph_sk, recipient_x25519_pk)           // 32 bytes
3. (ct_mlkem, ss_mlkem) = ML-KEM-768.Encaps(recipient_mlkem_ek) // ct=1088B, ss=32B
4. KEK = HKDF-SHA-512(
       ikm  = ss_x25519 (32B) || ss_mlkem (32B),
       salt = eph_x25519_pk (32B) || recipient_x25519_pk (32B),
       info = "hydralock:v1:mlkem768-x25519-kek"
   )                                                            // KEK = 32 bytes
5. Seal FMK with KEK using XChaCha20-Poly1305 + stanza AAD
```

**Key decapsulation (open):**

```
1. ss_x25519   = X25519(recipient_x25519_sk, eph_pk)
2. ss_mlkem    = ML-KEM-768.Decaps(recipient_dk, ct_mlkem)
3. Re-derive KEK (same HKDF call)
4. Open FMK ciphertext
```

**Stanza layout** (1182 bytes total):

| Offset | Size | Field |
|---|---|---|
| 0 | 2 | version (u16, = 0x0001) |
| 2 | 32 | `eph_x25519_pk` |
| 34 | 1088 | `ct_mlkem` (ML-KEM-768 ciphertext) |
| 1122 | 32 | `enc_fmk` (FMK ciphertext, 16B + 16B tag) |
| 1150 | 32 | XChaCha20-Poly1305 nonce |

**Recipient key files** (PEM-like encoding):
- Public: `x25519_pk (32B) || mlkem768_ek (1184B)` = 1216 bytes
- Secret: `x25519_sk (32B) || mlkem768_seed (64B)` = 96 bytes

### 3.5 Rewrap Mechanism

Rewrap replaces the Wraps section (and recomputes the Policy and Fixed Header) without touching the payload or manifest.

**Cost**: O(number of new recipients) — independent of payload size.

**Security invariant**: The new wrapper stanzas and metadata are authenticated with the correct `header_hash` for the rewrapped container (computed before sealing via `compute_rewrap_header_hash`), and the footer MAC is recomputed over the new pre-footer bytes. The FMK and file UUID are not changed, meaning the payload key tree is identical and the payload ciphertexts remain valid without re-encryption.

---

## 4. Container Format

All multi-byte integers are **big-endian**. The container is fail-closed: any parser error during a required field returns an error and no partial data is returned.

### 4.1 Fixed Header

**Size**: 70 bytes (constant)

| Offset | Size | Type | Field | Description |
|---|---|---|---|---|
| 0 | 4 | `[u8;4]` | `magic` | `HLK1` (0x484C4B31) |
| 4 | 2 | `u16` | `format_version_major` | Currently `1` |
| 6 | 2 | `u16` | `format_version_minor` | Currently `0` |
| 8 | 2 | `u16` | `suite_id` | `0x0001` for suite v1 |
| 10 | 4 | `u32` | `flags` | Reserved, must be 0 |
| 14 | 4 | `u32` | `header_len` | Always 70 in v1 |
| 18 | 4 | `u32` | `policy_len` | Size of Policy section |
| 22 | 4 | `u32` | `wraps_len` | Size of Wraps section |
| 26 | 4 | `u32` | `metadata_len` | Size of encrypted metadata bytes (`nonce || ciphertext+tag`) |
| 30 | 8 | `u64` | `payload_offset` | Byte offset of Payload section from file start |
| 38 | 32 | `[u8;32]` | `reserved` | Must be all-zero |

`payload_offset` must equal `header_len + policy_len + wraps_len + metadata_len` exactly; parsers reject any mismatch.

### 4.2 Policy Section

**Size**: 8 bytes (constant)

| Offset | Size | Type | Field | Description |
|---|---|---|---|---|
| 0 | 2 | `u16` | `policy_version` | `1` |
| 2 | 1 | `u8` | `threshold` | Minimum shares required (currently always 1) |
| 3 | 1 | `u8` | `total_shares` | Total shares (currently always 1) |
| 4 | 2 | `u16` | `wrapper_count` | Number of entries in the Wraps section |
| 6 | 2 | `u16` | `reserved` | Must be 0 |

### 4.3 Wraps Section

**Header**: 4 bytes

| Offset | Size | Field | Description |
|---|---|---|---|
| 0 | 2 | `wraps_version` | `1` |
| 2 | 2 | `reserved` | Must be 0 |

**Per-entry header**: 8 bytes, followed by variable-length `wrapper_id` and `stanza`

| Offset | Size | Field | Description |
|---|---|---|---|
| 0 | 2 | `wrapper_type` | See table below |
| 2 | 2 | `wrapper_flags` | Reserved, 0 |
| 4 | 2 | `wrapper_id_len` | Length of `wrapper_id` in bytes |
| 6 | 2 | `stanza_len` | Length of `stanza` in bytes |
| 8 | `wrapper_id_len` | `wrapper_id` | `file_uuid (16B) \|\| user_label` |
| 8+id | `stanza_len` | `stanza` | KEM-specific sealed secret |

**Wrapper types and stanza sizes:**

| `wrapper_type` | Name | `stanza_len` |
|---|---|---|
| `0x0001` | `PASS-ARGON2ID` | 110 bytes |
| `0x0002` | `X25519` | 94 bytes |
| `0x0003` | `MLKEM768-X25519` | 1182 bytes |
| `0x0004` | `THRESHOLD` | 65 bytes per share |

The first 16 bytes of every `wrapper_id` are the `file_uuid`. This allows decryption to recover the file UUID from the plaintext container without requiring a separate field, and without breaking the binary format.

### 4.4 Metadata Section

Encrypted CBOR blob under AES-256-GCM-SIV. There is no standalone metadata header in the v1 wire format.

**Wire layout**: `nonce (12B) || ciphertext+tag`

**Plaintext CBOR fields** (all optional except version):

| Field | Type | Description |
|---|---|---|
| `version` | `u16` | Metadata schema version |
| `logical_name` | `text` | Original filename |
| `mime_type` | `text` | MIME type |
| `created_at` | `i64` | Unix timestamp (seconds) |
| `plaintext_size` | `u64` | Original plaintext size in bytes |
| `chunk_size` | `u32` | Payload chunk size in bytes |
| `epoch_size` | `u32` | Chunks per epoch |
| `manifest_root` | `bstr (32B)` | BLAKE3 manifest root |

### 4.5 Payload Section

**Header**: 16 bytes

| Offset | Size | Field | Description |
|---|---|---|---|
| 0 | 2 | `payload_version` | `1` |
| 2 | 2 | `flags` | Reserved, 0 |
| 4 | 4 | `chunk_size` | Plaintext bytes per chunk |
| 8 | 4 | `tag_size` | AEAD tag size (16 for Poly1305) |
| 12 | 4 | `chunk_count` | Number of chunk entries |

**Per-chunk entry**: 8-byte header + ciphertext + tag

| Offset | Size | Field | Description |
|---|---|---|---|
| 0 | 4 | `ciphertext_len` | Ciphertext bytes (excl. tag) |
| 4 | 2 | `flags` | Bit 0 = `FINAL` |
| 6 | 2 | `reserved` | 0 |
| 8 | `ciphertext_len` | ciphertext | Encrypted chunk bytes |
| 8+ct | 16 | tag | Poly1305 authentication tag |

The last chunk in the container must have `FINAL` set. Parsers reject a container with no final chunk.

### 4.6 Footer Section

**Header**: 12 bytes

| Offset | Size | Field | Description |
|---|---|---|---|
| 0 | 2 | `footer_version` | `1` |
| 2 | 2 | `reserved` | 0 |
| 4 | 4 | `manifest_root_len` | 32 |
| 8 | 4 | `auth_tag_len` | 32 |

Followed by:

- `manifest_root` (32 bytes) — `BLAKE3_keyed(k_manifest, ct[0] \|\| ... \|\| ct[n])`
- `auth_tag` (32 bytes) — `BLAKE3_keyed(k_manifest, all_bytes_before_footer)`

---

## 5. CLI Usage

### Generate a recipient keypair

```sh
# X25519 (classical)
hydralock gen-recipient -o alice

# ML-KEM-768+X25519 (hybrid post-quantum)
hydralock gen-recipient -t mlkem768-x25519 -o alice
```

Produces `alice.pub` and `alice.key`.

### Encrypt

```sh
# Passphrase (interactive)
hydralock encrypt -i plaintext.bin -o out.hlk -p

# X25519 recipient
hydralock encrypt -i plaintext.bin -o out.hlk -r alice.pub

# ML-KEM-768+X25519 recipient
hydralock encrypt -i plaintext.bin -o out.hlk -R alice.pub

# Multiple recipients (any one key can decrypt)
hydralock encrypt -i plaintext.bin -o out.hlk -p -r alice.pub

# Passphrase profile selection (default: balanced)
hydralock encrypt -i plaintext.bin -o out.hlk -p -P interactive
```

### Decrypt

```sh
hydralock decrypt -i out.hlk -o plaintext.bin -p
hydralock decrypt -i out.hlk -o plaintext.bin -k alice.key
```

### Inspect (no key required)

```sh
hydralock inspect -i out.hlk
```

Prints header fields, policy, and wrapper types without decrypting.

### Verify

```sh
# Structural check only
hydralock verify -i out.hlk

# Full integrity check (requires key)
hydralock verify -i out.hlk -p
hydralock verify -i out.hlk -k alice.key
```

### Rewrap

```sh
# Recover FMK via passphrase, add X25519 recipient
hydralock rewrap -i out.hlk -o rewrapped.hlk -p -r bob.pub

# Recover via key, replace with new passphrase
hydralock rewrap -i out.hlk -o rewrapped.hlk -k alice.key -P
```

### Built-in test vectors

```sh
hydralock test-vectors
```

### Short flags reference

| Flag | `encrypt` | `decrypt` | `verify` | `rewrap` |
|---|---|---|---|---|
| `-i` | input | input | input | input |
| `-o` | output | output | — | output |
| `-p` | --passphrase | --passphrase | --passphrase | --old-passphrase |
| `-k` | — | --key | --key | --old-key |
| `-r` | --recipient | — | — | --add-recipient |
| `-R` | --recipient-pq | — | — | --add-recipient-pq |
| `-P` | --argon2-profile | — | — | --add-passphrase |
| `-f` | --force | --force | — | --force |
| `-n` | --name | — | — | — |
| `-m` | --mime | — | — | — |

### 5.1 Rust Library API

HydraLock exposes a stable facade under `hydralock::api` for application
integration, while preserving low-level operations under
`hydralock::api::low_level` for advanced use cases.

High-level surface:

- `hydralock::api::encrypt(plaintext, recipients, options)`
- `hydralock::api::decrypt(container, key_material)`
- `hydralock::api::rewrap_container(container, current_key, recipients, policy)`

Minimal example:

```rust
use hydralock::api::{
      EncryptOptions, KeyMaterial, RecipientSpec,
      decrypt, encrypt,
};
use hydralock::crypto::password::Argon2Profile;

let plaintext = b"hello hydralock";
let recipients = vec![RecipientSpec::Passphrase {
      passphrase: b"correct horse battery staple".to_vec(),
      profile: Argon2Profile::Balanced,
      label: None,
}];

let container = encrypt(plaintext, &recipients, EncryptOptions::default())?;
let out = decrypt(
      &container,
      KeyMaterial::Passphrase(b"correct horse battery staple".to_vec()),
)?;
assert_eq!(out.plaintext, plaintext);
```

API invariants:

- High-level API requires at least one recipient.
- Default labels are deterministic (`pass{idx}` / `rcpt{idx}`).
- Rewrap does not re-encrypt payload bytes; only wraps/policy/header/footer are rewritten.
- `hydralock::api::low_level` is intentionally small to reduce accidental public API freeze.

---

## 6. Build

**Requirements:**

- Rust stable ≥ 1.85 (edition 2024)
- No C dependencies — pure Rust crate graph

```sh
git clone <repo>
cd hydralock
cargo build --release
```

The resulting binary is at `target/release/hydralock`.

**Run tests:**

```sh
cargo test
```

---

## 7. Performance Characteristics

All numbers are approximate and depend on hardware.

| Operation | Notes |
|---|---|
| Payload encryption | Bound by XChaCha20-Poly1305 throughput (~1–3 GB/s on modern x86_64) |
| Payload decryption | Same as encryption |
| BLAKE3 manifest | Negligible — ~5 GB/s keyed hashing |
| Argon2id (interactive) | 64 MiB, t=3 — ~0.1–0.5s |
| Argon2id (balanced, default) | 256 MiB, t=3 — ~0.5–2s |
| Argon2id (paranoid) | 1024 MiB, t=3 — ~2–8s |
| ML-KEM-768 encapsulation | ~100–200 µs |
| X25519 ECDH | ~50 µs |
| Rewrap (any payload size) | Argon2 cost + KEM cost only — payload not touched |

**Chunk size impact:** Larger chunks increase throughput (fewer AEAD calls, better cache utilization) but increase the granularity of error detection. The default 64 KiB is a practical balance. Smaller chunks (~4 KiB) are preferable if streaming-like access is needed.

---

## 8. Security Considerations

### Nonce reuse

XChaCha20-Poly1305 uses 192-bit nonces derived deterministically from `(k_epoch, chunk_index)`. Because `k_epoch` is derived from a random FMK and file UUID, and each chunk has a unique index, nonce collision probability across two distinct encryptions is negligible. Two encryptions of the same plaintext produce different ciphertexts because the FMK and file UUID are freshly sampled each time.

### Wrapper AAD binding

Each KEM stanza AAD includes `header_hash = BLAKE3(fixed_header_bytes)`. This cryptographically binds each stanza to the specific container layout (section sizes, payload offset). An attacker cannot transplant a stanza from one container into another without invalidating the AAD.

### Memory zeroization

All key material (`Fmk`, `SecretKey32`, X25519 static secrets, ML-KEM decapsulation keys, passphrases) is held in types that implement `Zeroize + ZeroizeOnDrop`. Keys are cleared when dropped. This does not protect against a compromised runtime or memory dump taken while keys are in use.

### Manifest authentication

The `manifest_root` is a BLAKE3 keyed hash over all chunk ciphertexts (including tags), committed to inside the encrypted metadata section and independently verified via the footer auth tag. An attacker who can modify the payload but not derive `k_manifest` cannot produce a valid manifest root.

### Downgrade attacks

The `suite_id` and `format_version_major` fields are covered by the fixed header hash, which is included in all wrapper stanza AADs. A downgrade that changes the suite ID would invalidate every stanza.

### Side-channel considerations

No explicit constant-time guarantees are made beyond what the underlying crates provide. ML-KEM operations via `ml-kem` use the reference implementation, which is designed to be constant-time. X25519 uses `x25519-dalek`, which is constant-time. Argon2id execution time is inherently variable.

---

## 9. Limitations

- **In-memory decryption only** — the entire plaintext is assembled in memory before being returned. Large files (> available RAM) are not supported.
- **No deniability** — a container is unambiguously a HydraLock container (magic bytes `HLK1`).
- **No streaming encryption** — the format requires knowing the total plaintext size before writing the fixed header (needed for `payload_offset`). Streaming support would require a two-pass or chunked-header design.
- **Threshold wrappers not in CLI** — the Shamir GF(256) + `THRESHOLD` stanza primitives are fully implemented and tested, but not yet exposed through the CLI.
- **No key revocation** — there is no mechanism to invalidate a specific recipient's access short of rewrapping to a new recipient set.
- **Single suite** — only `suite_id = 0x0001` is defined. Adding new cipher suites is a breaking format change.

---

## 10. Interoperability

The container format is versioned via `format_version_major` / `format_version_minor` and `suite_id`. Version `1.0`, suite `0x0001` is the only currently defined combination.

All integers are big-endian. The format is fully self-describing — a parser needs no external configuration to locate sections, given a valid fixed header.

Alternative implementations are possible in any language. The cryptographic operations are all specified in terms of standard primitives (FIPS 203 for ML-KEM-768, RFC 7748 for X25519, RFC 9106 for Argon2, BLAKE3 spec).

---

## 11. Testing

### Unit tests

```sh
cargo test
```

Current automated coverage includes unit, integration, and property tests:

- Format parsing (header, policy, wraps, payload, footer)
- AAD domain separation
- KDF determinism and domain separation
- Argon2 profile parameters
- Per-chunk payload encryption/decryption
- BLAKE3 manifest building and verification
- Footer auth tag computation and verification
- X25519 stanza seal/open roundtrip
- ML-KEM-768+X25519 stanza seal/open roundtrip
- Passphrase stanza seal/open roundtrip
- Shamir GF(256) share split/recombine
- Full rewrap roundtrip (header, wraps, footer recomputed)
- End-to-end API integration (small, medium, and large file roundtrip)
- Multi-wrapper same-container decryptability (passphrase, X25519, ML-KEM)
- Property tests (parser roundtrip, canonicalization, KDF invariants, threshold roundtrip)

### Differential test vectors

Three deterministic binary vectors are committed under `vectors/` — one per wrapper type:

- `DIFF-PASS-001` — passphrase/Argon2id wrapper
- `DIFF-X25519-001` — X25519 wrapper
- `DIFF-MLKEM-001` — ML-KEM-768+X25519 hybrid wrapper

Each vector ships with `container.hlock`, `plaintext.bin`, `key_material.json`, and `expected.json`.
Vectors are regenerated via:

```sh
cargo test gen_diff -- --ignored --nocapture
```

The Rust differential harness validates all three vectors:

```sh
cargo test differential
```

### Python second implementation

An independent Python implementation lives under `impl/python/` and cross-validates the format
and cryptographic protocol against the differential vectors without using any Rust code.

**Dependencies**: `blake3`, `argon2-cffi`, `kyber-py`, `cryptography`, `pycryptodome`, `cbor2`.

```sh
cd impl/python
python3 -m pytest tests/test_differential_vectors.py -v
```

All three differential vectors pass 3/3.

### Integration test vectors

```sh
hydralock test-vectors
```

Runs three encrypt → decrypt roundtrips covering all three wrapper types (passphrase, X25519, ML-KEM-768+X25519) and verifies plaintext equality end-to-end.

### Fuzzing

HydraLock ships a dedicated `cargo-fuzz` harness under `fuzz/` with these targets:

- `fixed_header_parser`
- `container_parser`
- `metadata_decoder`
- `payload_decoder`

Initial regression corpus is versioned under `fuzz/corpus/<target>/` and seeded from official vectors.

Requirements:

- `cargo-fuzz`
- Rust nightly toolchain (ASan-based libFuzzer runs)

```sh
cargo install cargo-fuzz
rustup toolchain install nightly
```

Run a quick smoke campaign for all targets:

```sh
cargo +nightly fuzz run fixed_header_parser fuzz/corpus/fixed_header_parser -- -max_total_time=10
cargo +nightly fuzz run container_parser fuzz/corpus/container_parser -- -max_total_time=10
cargo +nightly fuzz run metadata_decoder fuzz/corpus/metadata_decoder -- -max_total_time=10
cargo +nightly fuzz run payload_decoder fuzz/corpus/payload_decoder -- -max_total_time=10
```

---

## 12. Roadmap

- **Streaming encryption** — split header emission from payload writing, allowing encryption of files larger than RAM.
- **Threshold CLI** — expose the Shamir `THRESHOLD` wrapper via `encrypt` and `decrypt` subcommands.
- **ML-KEM-1024** — add a `suite_id = 0x0002` with ML-KEM-1024 for higher post-quantum security margins.
- **Compression** — optional plaintext compression before encryption (e.g., zstd).
- **Hardware acceleration** — AES-NI / VAES for metadata encryption on x86_64.
- **Key derivation from hardware tokens** — FIDO2 / PIV integration for enterprise use cases.

---

## 13. License

MIT

---

## 14. References

- [FIPS 203 — Module-Lattice-Based Key-Encapsulation Mechanism Standard (ML-KEM)](https://csrc.nist.gov/pubs/fips/203/final) — NIST, 2024
- [RFC 7748 — Elliptic Curves for Diffie-Hellman Key Agreement (X25519)](https://www.rfc-editor.org/rfc/rfc7748)
- [RFC 9106 — Argon2 Memory-Hard Function](https://www.rfc-editor.org/rfc/rfc9106)
- [RFC 8439 — ChaCha20 and Poly1305 for IETF Protocols](https://www.rfc-editor.org/rfc/rfc8439)
- [BLAKE3 Specification](https://github.com/BLAKE3-team/BLAKE3-specs/blob/master/blake3.pdf)
- [AES-GCM-SIV — RFC 8452](https://www.rfc-editor.org/rfc/rfc8452)
- [HKDF — RFC 5869](https://www.rfc-editor.org/rfc/rfc5869)
- [Hybrid Post-Quantum KEM Combiners — Giacon, Heuer, Poettering (2018)](https://eprint.iacr.org/2018/024.pdf)
