import blake3


def verify_footer_auth_tag(k_manifest: bytes, pre_footer_bytes: bytes, expected_tag: bytes) -> bool:
    computed = blake3.blake3(pre_footer_bytes, key=k_manifest).digest()
    return computed == expected_tag
