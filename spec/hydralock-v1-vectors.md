# HydraLock V1 Test Vectors (Draft)

Status: Initial draft.

## 1. Goal

This document defines the format and the minimum test-vector cases used to validate HydraLock v1 implementation conformance.

Initial scope of this draft:

- fixed-header vectors;
- policy-section vectors;
- wraps-section vectors;
- acceptance and rejection cases;
- distribution pattern for implementations in different languages.

## 2. Distribution layout

Each test case should be distributed in its own directory under `vectors/`.

Recommended structure:

```text
vectors/
  case-id/
    input.hlock
    expected.json
    notes.txt
```

Rules:

- `input.hlock`: input bytes for the case.
- `expected.json`: expected result for the tested operation.
- `notes.txt`: optional human-readable notes.

## 3. expected.json schema

Required fields:

- `case_id`: unique case identifier.
- `version`: vector schema version.
- `operation`: target operation (`parse_fixed_header`, `verify`, `decrypt`, etc).
- `expect`: `accept` or `reject`.

Recommended fields for fixed header:

- `parsed.magic`
- `parsed.format_version_major`
- `parsed.format_version_minor`
- `parsed.suite_id`
- `parsed.flags`
- `parsed.header_len`
- `parsed.policy_len`
- `parsed.wraps_len`
- `parsed.metadata_len`
- `parsed.payload_offset`

Expected error fields:

- `error.code`
- `error.contains`

## 4. Initial minimum set (fixed header)

### 4.1 Case FH-ACCEPT-001

Description:

- valid fixed header with magic `HLK1`, zeroed reserved field, and exact length.

Operation:

- `parse_fixed_header`

Expected result:

- `accept`

### 4.2 Case FH-REJECT-001

Description:

- fixed header with invalid magic.

Operation:

- `parse_fixed_header`

Expected result:

- `reject`
- `error.code = InvalidMagic`

### 4.3 Case FH-REJECT-002

Description:

- fixed header with non-zero reserved byte.

Operation:

- `parse_fixed_header`

Expected result:

- `reject`
- `error.code = NonZeroReserved`

### 4.4 Case FH-REJECT-003

Description:

- fixed header shorter than 70 bytes.

Operation:

- `parse_fixed_header`

Expected result:

- `reject`
- `error.code = InvalidLength`

## 5. Initial minimum set (policy section)

### 5.1 Case POLICY-ACCEPT-001

Description:

- valid policy section with version 1, valid threshold range, and zero reserved bytes.

Operation:

- `parse_policy_section`

Expected result:

- `accept`

### 5.2 Case POLICY-REJECT-001

Description:

- policy section shorter than 8 bytes.

Operation:

- `parse_policy_section`

Expected result:

- `reject`
- `error.code = InvalidLength`

## 6. Initial minimum set (wraps section)

### 6.1 Case WRAPS-ACCEPT-001

Description:

- valid wraps section with one wrapper entry.

Operation:

- `parse_wraps_section`

Expected result:

- `accept`

### 6.2 Case WRAPS-REJECT-001

Description:

- wraps section with unsupported wraps version.

Operation:

- `parse_wraps_section`

Expected result:

- `reject`
- `error.code = UnsupportedWrapsVersion`

### 6.3 Case WRAPS-REJECT-002

Description:

- wraps section with trailing bytes after declared entries.

Operation:

- `parse_wraps_section`

Expected result:

- `reject`
- `error.code = InvalidWrapperCount`

### 6.4 Case WRAPS-REJECT-003

Description:

- wraps section with truncated stanza payload.

Operation:

- `parse_wraps_section`

Expected result:

- `reject`
- `error.code = TruncatedStanza`

### 6.5 Case WRAPS-REJECT-004

Description:

- wraps section with duplicate wrapper identifiers.

Operation:

- `parse_wraps_section`

Expected result:

- `reject`
- `error.code = DuplicateWrapperId`

## 7. Case naming

Pattern:

- `<AREA>-<EXPECT>-<NNN>`

Examples:

- `FH-ACCEPT-001`
- `FH-REJECT-001`
- `WRAP-ACCEPT-003`
- `PAYLOAD-REJECT-010`

## 8. Conformance rules

For fixed header, an implementation is conformant when it:

- accepts all `FH-ACCEPT-*` cases;
- rejects all `FH-REJECT-*` cases;
- returns an error consistent with the expected category.

For policy section, an implementation is conformant when it:

- accepts all `POLICY-ACCEPT-*` cases;
- rejects all `POLICY-REJECT-*` cases;
- returns an error consistent with the expected category.

For wraps section, an implementation is conformant when it:

- accepts all `WRAPS-ACCEPT-*` cases;
- rejects all `WRAPS-REJECT-*` cases;
- returns an error consistent with the expected category.

## 9. Open items

This draft still needs:

- encrypted metadata vectors;
- payload/manifest/footer vectors;
- corruption and downgrade vectors;
- password mode and asymmetric wrapper vectors;
- `2-of-3` threshold vectors;
- final fixture set for cross-language differential testing.