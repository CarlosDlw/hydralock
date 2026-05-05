import struct

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.hashes import SHA512
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV
from kyber_py.ml_kem import ML_KEM_768

STANZA_LEN = 1182
STANZA_VERSION = 1
MLKEM768_CT_LEN = 1088


def unwrap(stanza: bytes, x25519_sk: bytes, mlkem_dk_seed: bytes, aad: bytes) -> bytes:
    if len(stanza) != STANZA_LEN:
        raise ValueError(f"MLKEM768-X25519 stanza must be {STANZA_LEN} bytes, got {len(stanza)}")

    version = struct.unpack_from(">H", stanza, 0)[0]
    if version != STANZA_VERSION:
        raise ValueError(f"unsupported stanza version: {version}")

    eph_x25519_pk_bytes = stanza[2:34]
    mlkem768_ct = stanza[34:1122]       # 1088 bytes
    wrap_nonce = stanza[1122:1134]
    wrapped_key_body = stanza[1134:1182]  # 48 bytes: ct(32) + tag(16)

    # X25519 component
    sk = X25519PrivateKey.from_private_bytes(x25519_sk)
    eph_pk = X25519PublicKey.from_public_bytes(eph_x25519_pk_bytes)
    recipient_pk_bytes = sk.public_key().public_bytes_raw()
    ss_x25519 = sk.exchange(eph_pk)

    # ML-KEM-768 decapsulation
    _, dk = ML_KEM_768.key_derive(mlkem_dk_seed)
    ss_mlkem = ML_KEM_768.decaps(dk, mlkem768_ct)

    # Hybrid KEK
    ikm = ss_x25519 + ss_mlkem
    salt = eph_x25519_pk_bytes + recipient_pk_bytes
    hkdf = HKDF(
        algorithm=SHA512(),
        length=32,
        salt=salt,
        info=b"hydralock:v1:mlkem768-x25519-kek",
    )
    kek = hkdf.derive(ikm)

    cipher = AESGCMSIV(kek)
    return cipher.decrypt(wrap_nonce, wrapped_key_body, aad)
