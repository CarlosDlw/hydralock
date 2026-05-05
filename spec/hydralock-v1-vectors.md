# HydraLock V1 Test Vectors

Status: FROZEN — v1.0.0 (2026-05-05)

## 1. Goal

This document defines the format and the minimum test-vector cases used to validate HydraLock v1 implementation conformance.

Initial scope of this draft:

- fixed-header vectors;
- policy-section vectors;
- wraps-section vectors;
- metadata corruption vectors;
- footer-section vectors;
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

## 7. Initial minimum set (metadata corruption)

Metadata is not a standalone self-describing section in the v1 wire format. The
container stores raw metadata bytes as `nonce (12B) || ciphertext+tag`, and
validation happens as part of full container decrypt/verify.

### 7.1 Case META-CORRUPT-001

Description:

- one bit flipped inside the encrypted metadata bytes of an otherwise valid container.

Operation:

- `decrypt`

Expected result:

- `reject`
- `error.code = VerifyFailed` or `MetadataDecrypt`

## 8. Initial minimum set (footer section)

### 8.1 Case FOOTER-ACCEPT-001

Description:

- valid footer section with version 1, zeroed reserved bytes, non-empty manifest_root and auth_tag.

Operation:

- `parse_footer_section`

Expected result:

- `accept`

### 8.2 Case FOOTER-REJECT-001

Description:

- footer section with unsupported footer version.

Operation:

- `parse_footer_section`

Expected result:

- `reject`
- `error.code = UnsupportedFooterVersion`

### 8.3 Case FOOTER-REJECT-002

Description:

- footer section with non-zero reserved bytes.

Operation:

- `parse_footer_section`

Expected result:

- `reject`
- `error.code = NonZeroReserved`

### 8.4 Case FOOTER-REJECT-003

Description:

- footer section with truncated auth_tag bytes.

Operation:

- `parse_footer_section`

Expected result:

- `reject`
- `error.code = TruncatedAuthTag`

### 8.5 Case FOOTER-REJECT-004

Description:

- footer section with empty manifest_root declaration.

Operation:

- `parse_footer_section`

Expected result:

- `reject`
- `error.code = EmptyManifestRoot`

### 8.6 Case FOOTER-REJECT-005

Description:

- footer section with trailing bytes after declared lengths.

Operation:

- `parse_footer_section`

Expected result:

- `reject`
- `error.code = InvalidFooterLength`

## 9. Payload section minimum set

### 9.1 Case PAYLOAD-ACCEPT-001

Description:

- minimal valid payload section: one final chunk, chunk_size=4, tag_size=4.

Operation:

- `parse_payload_section`

Expected result:

- `accept`
- `parsed.payload_version = 1`
- `parsed.flags = 0`
- `parsed.chunk_size = 4`
- `parsed.tag_size = 4`
- `parsed.chunk_count = 1`

### 9.2 Case PAYLOAD-REJECT-001

Description:

- payload_version = 2, which is unsupported.

Operation:

- `parse_payload_section`

Expected result:

- `reject`
- `error.code = UnsupportedPayloadVersion`

### 9.3 Case PAYLOAD-REJECT-002

Description:

- section header reserved bytes are non-zero.

Operation:

- `parse_payload_section`

Expected result:

- `reject`
- `error.code = NonZeroReserved`

### 9.4 Case PAYLOAD-REJECT-003

Description:

- chunk_size field is zero.

Operation:

- `parse_payload_section`

Expected result:

- `reject`
- `error.code = ZeroChunkSize`

### 9.5 Case PAYLOAD-REJECT-004

Description:

- chunk entry declares ciphertext_len=8 but only 2 bytes of ciphertext are present.

Operation:

- `parse_payload_section`

Expected result:

- `reject`
- `error.code = TruncatedCiphertext`

### 9.6 Case PAYLOAD-REJECT-005

Description:

- single chunk with FINAL flag not set; no chunk is ever marked as final.

Operation:

- `parse_payload_section`

Expected result:

- `reject`
- `error.code = NoFinalChunk`

## 10. Case naming

Pattern:

- `<AREA>-<EXPECT>-<NNN>`

Examples:

- `FH-ACCEPT-001`
- `FH-REJECT-001`
- `WRAP-ACCEPT-003`
- `PAYLOAD-REJECT-010`

## 10. Conformance rules

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

For metadata corruption handling, an implementation is conformant when it:

- rejects all `META-CORRUPT-*` cases;
- returns an error consistent with the expected category.

For footer section, an implementation is conformant when it:

- accepts all `FOOTER-ACCEPT-*` cases;
- rejects all `FOOTER-REJECT-*` cases;
- returns an error consistent with the expected category.

For payload section, an implementation is conformant when it:

- accepts all `PAYLOAD-ACCEPT-*` cases;
- rejects all `PAYLOAD-REJECT-*` cases;
- returns an error consistent with the expected category.

## 11. Completeness

All vectors listed in §3.2 (acceptance) and §3.3 (rejection) are implemented
and generated by `tests/gen_vectors.rs`. The fixture set is final.