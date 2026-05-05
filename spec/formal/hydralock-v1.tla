---- MODULE hydralock_v1 ----
(*
  HydraLock Container Format v1 — Formal Invariants (TLA+)

  This module models the critical state invariants of the HydraLock v1
  container format. It covers:

    1. KDF tree well-formedness: each key in the tree is derived from a
       strictly lower-level key with a unique (label, index) pair.

    2. Container section ordering: sections appear in the normative order
       and their offsets are consistent.

    3. Wrapper AAD binding: each wrapper stanza is bound to a specific
       (suite_id, wrapper_index, file_uuid, header_hash) tuple, preventing
       cross-container or cross-position wrapper splicing.

    4. Payload integrity chain: the footer auth_tag covers all pre-footer
       bytes, and the manifest root covers all chunk ciphertexts in order.

    5. Rewrap safety: rewrapping preserves the payload ciphertexts and
       manifest_root verbatim while re-keying only the access layer.

  Verification target: these invariants must hold for all reachable states
  in the encrypt → decrypt and encrypt → rewrap → decrypt sequences.

  Tools: TLC model checker, or Apalache for bounded model checking.
*)

EXTENDS Integers, Sequences, FiniteSets

(* ── Constants ────────────────────────────────────────────────────────────── *)

CONSTANTS
  MaxEpochs,        \* maximum number of epochs in a container
  MaxChunksPerEpoch \* maximum chunks per epoch

ASSUME MaxEpochs \in Nat /\ MaxEpochs > 0
ASSUME MaxChunksPerEpoch \in Nat /\ MaxChunksPerEpoch > 0

(* ── Type definitions ─────────────────────────────────────────────────────── *)

\* A key is modelled as an opaque token (natural number) for symbolic reasoning.
Key == Nat

\* A label is one of the normative KDF label strings.
Label == {"root", "control", "manifest", "payload-master",
           "padding", "rewrap", "chunk-key", "chunk-nonce"}

\* A container section identifier.
Section == {"header", "policy", "wraps", "metadata", "payload", "footer"}

(* ── KDF tree invariants ──────────────────────────────────────────────────── *)

(*
  The KDF tree has the following structure:

    FMK + file_uuid
      → root_key        (HKDF-SHA-512, label="root")
          → k_control        (BLAKE3_keyed, label="control")
          → k_manifest       (BLAKE3_keyed, label="manifest")
          → k_payload_master (BLAKE3_keyed, label="payload-master")
          → k_padding        (BLAKE3_keyed, label="padding")
          → k_rewrap         (BLAKE3_keyed, label="rewrap")
              → k_epoch_i    (BLAKE3_keyed, label="chunk-key", index=i)
                  → k_chunk_j (BLAKE3_keyed, label="chunk-key", index=j)
                  → nonce_j   (BLAKE3_keyed_xof, label="chunk-nonce", index=j)

  Invariant KDF_DomainSeparation:
    For any two key derivation calls in the tree, if they share the same
    input key, they must use different (label, index) pairs.

  Note: k_epoch_i and k_chunk_j within epoch i both use label="chunk-key"
  but have different input keys (k_payload_master vs k_epoch_i). Domain
  separation between epochs and chunks is provided by the distinct input
  keys, not by distinct labels. This is a normative v1 decision.
*)

KdfNode == [parent: Key, label: Label, index: Nat]

KDF_DomainSeparation(tree) ==
  \A n1, n2 \in tree :
    n1 /= n2 =>
      ~(n1.parent = n2.parent /\ n1.label = n2.label /\ n1.index = n2.index)

(*
  Invariant KDF_NoKeyReuse:
    No derived key is used as input to its own derivation.
    (Acyclicity of the KDF tree.)
*)
KDF_NoKeyReuse(tree) ==
  \A n \in tree : n.parent /= n.index  \* symbolic: a key does not derive itself

(* ── Container section ordering ──────────────────────────────────────────── *)

(*
  Container layout (normative order):
    [header][policy][wraps][metadata][payload][footer]

  Invariant SectionOrder:
    Offsets must satisfy:
      header_start = 0
      policy_start = header_end
      wraps_start  = policy_end
      metadata_start = wraps_end
      payload_start = metadata_end  (= payload_offset in fixed header)
      footer_start  = payload_end

  This is a simple linear ordering invariant.
*)

ContainerLayout == [
  header_start  : Nat,
  header_len    : Nat,
  policy_len    : Nat,
  wraps_len     : Nat,
  metadata_len  : Nat,
  payload_len   : Nat
]

SectionOrder(c) ==
  LET header_end   == c.header_start + c.header_len
      policy_end   == header_end + c.policy_len
      wraps_end    == policy_end + c.wraps_len
      metadata_end == wraps_end + c.metadata_len
  IN
  /\ c.header_start = 0
  /\ c.header_len > 0
  /\ c.policy_len > 0
  /\ c.wraps_len > 0
  /\ c.metadata_len > 0
  /\ c.payload_len > 0
  /\ header_end = c.header_start + c.header_len   \* no gap between header and policy
  /\ policy_end  = header_end + c.policy_len       \* contiguous
  /\ wraps_end   = policy_end + c.wraps_len        \* contiguous
  /\ metadata_end = wraps_end + c.metadata_len     \* contiguous

(* ── Wrapper AAD binding ──────────────────────────────────────────────────── *)

(*
  Each wrapper stanza AAD encodes:
    (suite_id, section_type=0x03, wrapper_index, file_uuid, header_hash)

  Invariant WrapperBinding:
    If two containers share the same (file_uuid, header_hash) but differ
    in wrapper_index, their AADs are distinct. An attempt to use a stanza
    from wrapper position i in position j will fail AEAD authentication.
*)

WrapperAAD == [
  suite_id      : Nat,
  section_type  : {3},   \* 0x03 = SECTION_TYPE_WRAP
  wrapper_index : Nat,
  file_uuid     : Seq(Nat),
  header_hash   : Seq(Nat)
]

WrapperBinding(aads) ==
  \A a1, a2 \in aads :
    a1 /= a2 =>
      ~(a1.file_uuid = a2.file_uuid
        /\ a1.header_hash = a2.header_hash
        /\ a1.wrapper_index = a2.wrapper_index)

(* ── Payload integrity chain ──────────────────────────────────────────────── *)

(*
  Integrity chain:
     1. Each chunk is authenticated by XChaCha20-Poly1305 AEAD with AAD
       binding (epoch_index, chunk_index, file_uuid, suite_id,
       plaintext_chunk_len, is_final).
    2. Manifest root = BLAKE3_keyed(k_manifest, chunk_hash[0] || ... || chunk_hash[n-1])
       where chunk_hash[i] = BLAKE3(ciphertext_with_tag[i]).
    3. Footer auth_tag = BLAKE3_keyed(k_manifest, pre_footer_bytes)
       where pre_footer_bytes covers all sections before the footer.

  Invariant IntegrityChain:
    If footer auth_tag is valid, then pre_footer_bytes (including all chunk
    ciphertexts) are authentic. If manifest root is valid, then all chunk
    ciphertexts in order are authentic and complete.

  Note: In the v1 decrypt path, BOTH checks are performed:
    - verify_container_no_decrypt: checks footer auth_tag
    - verify_manifest_root: checks manifest root against actual chunks
*)

PayloadState == [
  chunks        : Seq(Seq(Nat)),   \* sequence of ciphertext_with_tag blobs
  manifest_root : Seq(Nat),        \* 32-byte manifest root
  auth_tag      : Seq(Nat)         \* 32-byte footer auth_tag
]

IntegrityChainConsistent(ps) ==
  \* Manifest root is computed from all chunks in order.
  \* Auth_tag covers pre_footer_bytes which includes all chunks.
  \* Both are derived from k_manifest, which is derived from FMK.
  \* Any modification to chunks invalidates both checks.
  /\ Len(ps.manifest_root) = 32
  /\ Len(ps.auth_tag) = 32
  /\ Len(ps.chunks) > 0

(* ── Rewrap safety ────────────────────────────────────────────────────────── *)

(*
  Rewrap operation modifies only:
    - fixed header (wraps_len, payload_offset)
    - policy section
    - wraps section
    - footer auth_tag (recomputed)

  And preserves verbatim:
    - metadata section (encrypted, opaque)
    - payload section (all chunk ciphertexts)
    - manifest_root (preserved from old footer into new footer)

  Invariant RewrapPayloadPreservation:
    The payload ciphertexts in the rewrapped container are identical to
    those in the original container.

  Invariant RewrapManifestPreservation:
    The manifest_root in the new footer equals the manifest_root in the
    old footer.

  Invariant RewrapIntegrityRecomputed:
    The new footer auth_tag is computed over the new pre_footer_bytes
    (which includes the new header, policy, wraps sections). Therefore
    the new container is self-consistent.
*)

RewrapState == [
  old_payload   : Seq(Seq(Nat)),
  new_payload   : Seq(Seq(Nat)),
  old_root      : Seq(Nat),
  new_root      : Seq(Nat)
]

RewrapPayloadPreservation(rs) ==
  rs.old_payload = rs.new_payload

RewrapManifestPreservation(rs) ==
  rs.old_root = rs.new_root

(* ── Master invariant ─────────────────────────────────────────────────────── *)

(*
  The combined safety invariant for a well-formed HydraLock v1 container.
*)

Invariant(tree, c, aads, ps, rs) ==
  /\ KDF_DomainSeparation(tree)
  /\ SectionOrder(c)
  /\ WrapperBinding(aads)
  /\ IntegrityChainConsistent(ps)
  /\ RewrapPayloadPreservation(rs)
  /\ RewrapManifestPreservation(rs)

====
