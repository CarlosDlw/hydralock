# HydraLock Container Format v1 (Draft)

Status: Initial normative specification draft.

## 1. Scope

This document defines the `HydraLock Container Format v1` binary format for file encryption.

v1 goals:

- language-independent specification;
- canonical serialization and strict parsing;
- interoperability baseline across implementations;
- initial container support with a normative fixed header.

## 2. Normative terminology

The words `MUST`, `MUST NOT`, `SHOULD`, `SHOULD NOT`, and `MAY` are normative.

Main terms:

- Container: full `.hlock` file.
- Fixed Header: fixed binary header at the beginning of the container.
- Section: logical block after the fixed header.
- Suite: versioned cryptographic set identified by `suite_id`.

## 3. Identity and versioning

- Format name: `HydraLock Container Format v1`.
- Magic bytes: `HLK1`.
- Recommended extension: `.hlock`.
- Format versioning: `format_version_major` and `format_version_minor`.

Compatibility:

- `v1` implementations MUST reject `format_version_major != 1`.
- `v1` implementations MAY accept a higher `format_version_minor` only if extension rules allow it without violating security constraints.

## 4. Serialization conventions

General encoding rules:

- All integers are unsigned and big-endian.
- The fixed header has a fixed size and MUST have exact length.
- `reserved` fields MUST be zero in v1.
- Unknown fields in critical context MUST cause an error.
- Parsers MUST operate in strict mode, without recovery heuristics.

## 5. Normative parsing order

The parser MUST follow this order:

1. Read magic bytes.
2. Validate magic bytes.
3. Read fixed-header fields.
4. Validate reserved bytes.
5. Validate supported major version.
6. Only then process subsequent sections.

If any validation fails, the parser MUST abort with an error.

## 6. Fixed Header (normative)

### 6.1 Layout

The fixed header is 70 bytes.

```text
Offset  Size  Field
0       4     magic = "HLK1"
4       2     format_version_major (u16)
6       2     format_version_minor (u16)
8       2     suite_id (u16)
10      4     flags (u32)
14      4     header_len (u32)
18      4     policy_len (u32)
22      4     wraps_len (u32)
26      4     metadata_len (u32)
30      8     payload_offset (u64)
38      32    reserved (bytes)
```

### 6.2 Mandatory rules

- The fixed header MUST have exact length 70 bytes.
- `magic` MUST be exactly `HLK1`.
- `reserved` MUST contain only zero bytes.
- `header_len` SHOULD be 70 in v1.

### 6.3 Mandatory parser errors

Implementations MUST reject:

- length different from 70 bytes;
- invalid magic;
- any non-zero byte in `reserved`.

## 7. Fixed Header (Rust reference mapping)

Current reference implementation:

- file: `src/format/header.rs`
- constants:
  - `MAGIC = b"HLK1"`
  - `FIXED_HEADER_LEN = 70`
  - `RESERVED_LEN = 32`
- errors:
  - `InvalidLength`
  - `InvalidMagic`
  - `NonZeroReserved`

This mapping exists to aid conformance, but the specification is implementation-independent.

## 8. Initial security rules

- Parser MUST fail closed.
- Parser MUST NOT attempt to repair an invalid container.
- Implementations MUST avoid platform-dependent behavior for binary fields.

## 9. Policy Section (normative, initial)

### 9.1 Layout

Initial v1 policy section layout is 8 bytes.

```text
Offset  Size  Field
0       2     policy_version (u16)
2       1     threshold (u8)
3       1     total_shares (u8)
4       2     wrapper_count (u16)
6       2     reserved (bytes)
```

### 9.2 Mandatory rules

- Policy section MUST have exact length 8 bytes.
- `policy_version` MUST be `1` in v1.
- `total_shares` MUST be greater than zero.
- `threshold` MUST be in range `1..=total_shares`.
- `wrapper_count` MUST be greater than or equal to `total_shares`.
- `reserved` MUST contain only zero bytes.

### 9.3 Mandatory parser errors

Implementations MUST reject:

- invalid policy section length;
- unsupported `policy_version`;
- `total_shares == 0`;
- invalid threshold range;
- `wrapper_count < total_shares`;
- any non-zero byte in policy reserved bytes.

### 9.4 Rust reference mapping

Current reference implementation:

- file: `src/format/policy.rs`
- constants:
  - `POLICY_SECTION_LEN = 8`
- errors:
  - `InvalidLength`
  - `UnsupportedPolicyVersion`
  - `InvalidTotalShares`
  - `InvalidThreshold`
  - `InvalidWrapperCount`
  - `NonZeroReserved`

## 10. Wraps Section (normative, initial)

### 10.1 Layout

The wraps section starts with a fixed 4-byte header and is followed by
`wrapper_count` variable-size entries.

Wraps section header:

```text
Offset  Size  Field
0       2     wraps_version (u16)
2       2     wrapper_count (u16)
```

Wrapper entry header:

```text
Offset  Size  Field
0       2     wrapper_type (u16)
2       2     wrapper_flags (u16)
4       2     wrapper_id_len (u16)
6       2     stanza_len (u16)
8       N     wrapper_id bytes
8+N     M     stanza bytes
```

### 10.2 Mandatory rules

- `wraps_version` MUST be `1` in v1.
- `wrapper_id_len` MUST be greater than zero.
- `wrapper_id` values MUST be unique within the section.
- Parser MUST consume the section exactly, with no trailing bytes.

### 10.3 Mandatory parser errors

Implementations MUST reject:

- unsupported `wraps_version`;
- truncated entry header;
- truncated `wrapper_id` or truncated `stanza`;
- empty `wrapper_id`;
- duplicate `wrapper_id`;
- section with trailing bytes after declared entries.

### 10.4 Rust reference mapping

Current reference implementation:

- file: `src/format/wraps.rs`
- constants:
  - `WRAPS_HEADER_LEN = 4`
  - `WRAPPER_ENTRY_HEADER_LEN = 8`
- errors:
  - `InvalidLength`
  - `UnsupportedWrapsVersion`
  - `TruncatedEntryHeader`
  - `TruncatedField`
  - `InvalidWrapperCount`
  - `EmptyWrapperId`
  - `DuplicateWrapperId`
  - `LengthOverflow`

  ## 11. Metadata Section (normative, initial)

  ### 11.1 Layout

  The metadata section has an 8-byte fixed header followed by encrypted metadata
  ciphertext.

  Metadata section header:

  ```text
  Offset  Size  Field
  0       2     metadata_version (u16)
  2       2     reserved (bytes)
  4       4     ciphertext_len (u32)
  8       N     ciphertext bytes
  ```

  ### 11.2 Mandatory rules

  - `metadata_version` MUST be `1` in v1.
  - `reserved` MUST contain only zero bytes.
  - `ciphertext_len` MUST be greater than zero.
  - Parser MUST consume the section exactly, with no trailing bytes.

  ### 11.3 Mandatory parser errors

  Implementations MUST reject:

  - unsupported `metadata_version`;
  - non-zero `reserved` bytes;
  - `ciphertext_len == 0`;
  - truncated ciphertext bytes;
  - section with trailing bytes after declared `ciphertext_len`.

  ### 11.4 Rust reference mapping

  Current reference implementation:

  - file: `src/format/metadata.rs`
  - constants:
    - `METADATA_HEADER_LEN = 8`
  - errors:
    - `InvalidLength`
    - `UnsupportedMetadataVersion`
    - `NonZeroReserved`
    - `EmptyCiphertext`
    - `TruncatedCiphertext`
    - `InvalidCiphertextLength`
    - `LengthOverflow`

  ## 12. Footer Section (normative, initial)

  ### 12.1 Layout

  The footer section has a 12-byte fixed header followed by two variable-size
  fields.

  Footer section header:

  ```text
  Offset  Size  Field
  0       2     footer_version (u16)
  2       2     flags (u16)
  4       2     manifest_root_len (u16)
  6       2     auth_tag_len (u16)
  8       4     reserved (bytes)
  12      N     manifest_root bytes
  12+N    M     auth_tag bytes
  ```

  ### 12.2 Mandatory rules

  - `footer_version` MUST be `1` in v1.
  - `reserved` MUST contain only zero bytes.
  - `manifest_root_len` MUST be greater than zero.
  - `auth_tag_len` MUST be greater than zero.
  - Parser MUST consume the section exactly, with no trailing bytes.

  ### 12.3 Mandatory parser errors

  Implementations MUST reject:

  - unsupported `footer_version`;
  - non-zero `reserved` bytes;
  - `manifest_root_len == 0`;
  - `auth_tag_len == 0`;
  - truncated `manifest_root` or truncated `auth_tag` bytes;
  - section with trailing bytes after declared lengths.

  ### 12.4 Rust reference mapping

  Current reference implementation:

  - file: `src/format/footer.rs`
  - constants:
    - `FOOTER_HEADER_LEN = 12`
  - errors:
    - `InvalidLength`
    - `UnsupportedFooterVersion`
    - `NonZeroReserved`
    - `EmptyManifestRoot`
    - `EmptyAuthTag`
    - `TruncatedField`
    - `InvalidFooterLength`
    - `LengthOverflow`

  ## 13. Payload Section (normative, initial)

  ### 13.1 Layout

  The payload section carries one or more authenticated-encrypted chunks.
  It begins with a 16-byte fixed header followed by a sequence of chunk entries.
  The section is fully self-describing: every chunk entry declares its own
  ciphertext length inline.

  Payload section header:

  ```text
  Offset  Size  Field
  0       2     payload_version (u16)
  2       2     flags (u16)
  4       4     chunk_size (u32)   nominal ciphertext bytes per non-final chunk
  8       4     tag_size (u32)     auth tag bytes per chunk (fixed for the suite)
  12      4     reserved (bytes)
  ```

  Each chunk entry has an 8-byte header followed by the declared ciphertext and
  tag bytes:

  ```text
  Offset  Size  Field
  0       4     ciphertext_len (u32)   actual ciphertext bytes in this chunk
  4       2     flags (u16)            bit 0: FINAL (0x0001)
  6       2     reserved (bytes)       must be zero
  8       N     ciphertext bytes       N = ciphertext_len
  8+N     M     tag bytes              M = tag_size from section header
  ```

  The `FINAL` flag (bit 0 of chunk `flags`) marks the last logical chunk.

  ### 13.2 Mandatory rules

  - `payload_version` MUST be `1` in v1.
  - `reserved` bytes in the section header MUST contain only zero bytes.
  - `reserved` bytes in each chunk entry MUST contain only zero bytes.
  - `chunk_size` MUST be greater than zero.
  - `tag_size` MUST be greater than zero.
  - `ciphertext_len` of each chunk MUST be greater than zero.
  - All non-final chunks MUST have `ciphertext_len == chunk_size`.
  - Exactly one chunk MUST have the `FINAL` flag set.
  - The `FINAL` chunk MUST be the last chunk in sequence.
  - Parser MUST consume the section exactly, with no trailing bytes.

  ### 13.3 Mandatory parser errors

  Implementations MUST reject:

  - unsupported `payload_version`;
  - non-zero `reserved` bytes (section header or chunk entry);
  - `chunk_size == 0`;
  - `tag_size == 0`;
  - `ciphertext_len == 0` in any chunk entry;
  - non-final chunk with `ciphertext_len != chunk_size`;
  - truncated chunk entry header;
  - truncated ciphertext bytes;
  - truncated tag bytes;
  - no chunk marked as `FINAL`;
  - `FINAL` chunk that is not the last chunk in the sequence;
  - trailing bytes after all declared chunk entries.

  ### 13.4 Rust reference mapping

  Current reference implementation:

  - file: `src/format/payload.rs`
  - constants:
    - `PAYLOAD_HEADER_LEN = 16`
    - `CHUNK_ENTRY_HEADER_LEN = 8`
    - `CHUNK_FLAG_FINAL = 0x0001`
  - errors:
    - `InvalidLength`
    - `UnsupportedPayloadVersion`
    - `NonZeroReserved`
    - `ZeroChunkSize`
    - `ZeroTagSize`
    - `TruncatedChunkHeader`
    - `TruncatedCiphertext`
    - `TruncatedTag`
    - `ZeroCiphertextLen`
    - `ChunkSizeViolation`
    - `NoFinalChunk`
    - `FinalNotLast`
    - `TrailingBytes`
    - `LengthOverflow`

  ## 14. Open items to finalize v1

This draft does not yet finalize:

- final extensibility rules;
- complete normative algorithms for encrypt/decrypt/verify/rewrap;
- final full suite and wrapper definitions.

## 15. Normative `wrapper_id` convention

The `wrapper_id` field in the wraps section encodes both the container's file UUID
and an optional opaque recipient label using the following layout:

```text
wrapper_id = file_uuid (16 bytes) || recipient_label (0..N bytes)
```

- `file_uuid`: MUST be exactly the 16-byte UUID also stored inside the encrypted
  metadata. This prefix is available in plaintext and is the only mechanism to
  bootstrap the File Master Key derivation without first decrypting the metadata.
- `recipient_label`: an optional, opaque byte sequence assigned by the sealer.
  Its content is not interpreted by the format.

Normative rules:

- All `wrapper_id` values in a single container MUST share the same `file_uuid`
  prefix (the first 16 bytes). An implementation MUST reject or ignore wrappers
  whose `file_uuid` prefix does not match the `file_uuid` from the first wrapper.
- `wrapper_id` MUST be at least 16 bytes (enforced by the requirement that
  `wrapper_id_len > 0` combined with the minimum 16-byte prefix).
- Implementations that discover `wrapper_id` values shorter than 16 bytes MUST
  treat the container as invalid and abort.

Rust reference:
- `ops::decrypt::extract_file_uuid` extracts `wrapper_id[0..16]` from the first wrapper.
- `ops::encrypt::WrapperSpec::wire_id` constructs `file_uuid || label`.

## 16. Immediate next steps

1. Define header-to-section offset invariants across all sections.
2. Extend vectors specification with payload corruption cases.
3. Define metadata canonical plaintext layout and AAD binding.
4. Specify KDF tree (BLAKE3 derive_key) and AAD construction per section.