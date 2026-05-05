import struct

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.hashes import SHA512
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV

STANZA_LEN = 94
STANZA_VERSION = 1


def unwrap(stanza: bytes, recipient_sk: bytes, aad: bytes) -> bytes:
    if len(stanza) != STANZA_LEN:
        raise ValueError(f"X25519 stanza must be {STANZA_LEN} bytes, got {len(stanza)}")

    version = struct.unpack_from(">H", stanza, 0)[0]
    if version != STANZA_VERSION:
        raise ValueError(f"unsupported stanza version: {version}")

    eph_pk_bytes = stanza[2:34]
    wrap_nonce = stanza[34:46]
    wrapped_key_body = stanza[46:94]  # 48 bytes: ct(32) + tag(16)

    sk = X25519PrivateKey.from_private_bytes(recipient_sk)
    eph_pk = X25519PublicKey.from_public_bytes(eph_pk_bytes)
    recipient_pk_bytes = sk.public_key().public_bytes_raw()
    shared = sk.exchange(eph_pk)

    salt = eph_pk_bytes + recipient_pk_bytes
    hkdf = HKDF(algorithm=SHA512(), length=32, salt=salt, info=b"hydralock:v1:x25519-kek")
    kek = hkdf.derive(shared)

    cipher = AESGCMSIV(kek)
    return cipher.decrypt(wrap_nonce, wrapped_key_body, aad)
