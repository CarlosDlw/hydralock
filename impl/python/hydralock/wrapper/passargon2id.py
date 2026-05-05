import struct

from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV

STANZA_LEN = 110
STANZA_VERSION = 1
ARGON2ID_VERSION = 19


def unwrap(stanza: bytes, passphrase: bytes, aad: bytes) -> bytes:
    if len(stanza) != STANZA_LEN:
        raise ValueError(f"PASS-ARGON2ID stanza must be {STANZA_LEN} bytes, got {len(stanza)}")

    version = struct.unpack_from(">H", stanza, 0)[0]
    if version != STANZA_VERSION:
        raise ValueError(f"unsupported stanza version: {version}")

    argon2_ver = struct.unpack_from(">I", stanza, 2)[0]
    if argon2_ver != ARGON2ID_VERSION:
        raise ValueError(f"unsupported argon2 version: {argon2_ver}")

    mem_kib = struct.unpack_from(">I", stanza, 6)[0]
    time_cost = struct.unpack_from(">I", stanza, 10)[0]
    parallelism = struct.unpack_from(">I", stanza, 14)[0]
    salt = stanza[18:50]
    wrap_nonce = stanza[50:62]
    wrapped_key_body = stanza[62:110]  # 48 bytes: ct(32) + tag(16)

    kek = hash_secret_raw(
        passphrase,
        salt,
        time_cost=time_cost,
        memory_cost=mem_kib,
        parallelism=parallelism,
        hash_len=32,
        type=Type.ID,
        version=argon2_ver,
    )

    cipher = AESGCMSIV(kek)
    return cipher.decrypt(wrap_nonce, wrapped_key_body, aad)
