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

## 9. Open items to finalize v1

This draft does not yet finalize:

- byte-level definition of policy section;
- byte-level definition of wrapped secrets section;
- byte-level definition of metadata section;
- byte-level definition of payload and footer;
- final extensibility rules;
- complete normative algorithms for encrypt/decrypt/verify/rewrap;
- final full suite and wrapper definitions.

## 10. Immediate next steps

1. Freeze policy-section fields and validations.
2. Freeze wraps-section fields and validations.
3. Define header-to-section offset invariants.
4. Publish `spec/hydralock-v1-vectors.md` with initial fixed-header vectors.