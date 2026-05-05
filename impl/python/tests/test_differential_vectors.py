import json
import os
import unittest
from pathlib import Path

from hydralock.ops.decrypt import (
    decrypt,
    PassKeyMaterial,
    X25519KeyMaterial,
    MlKem768X25519KeyMaterial,
)

VECTORS_DIR = Path(__file__).parent.parent.parent.parent / "vectors"


def load_vector(case_id: str):
    d = VECTORS_DIR / case_id
    container = (d / "container.hlock").read_bytes()
    plaintext = (d / "plaintext.bin").read_bytes()
    key_material = json.loads((d / "key_material.json").read_text())
    expected = json.loads((d / "expected.json").read_text())
    return container, plaintext, key_material, expected


class TestDiffPass001(unittest.TestCase):
    def test_decrypt(self):
        container, plaintext_expected, km_json, expected = load_vector("DIFF-PASS-001")
        passphrase = bytes.fromhex(km_json["passphrase_hex"])
        km = PassKeyMaterial(passphrase=passphrase)
        result = decrypt(container, km)

        self.assertEqual(result.plaintext, plaintext_expected)
        self.assertEqual(result.plaintext, bytes.fromhex(expected["plaintext_hex"]))
        self.assertEqual(result.logical_name, expected["logical_name"])
        self.assertEqual(result.format_version_major, expected["inspect"]["format_version_major"])
        self.assertEqual(result.format_version_minor, expected["inspect"]["format_version_minor"])
        self.assertEqual(result.suite_id, expected["inspect"]["suite_id"])
        self.assertEqual(result.header_hash.hex(), expected["inspect"]["header_hash"])
        self.assertEqual(result.threshold, expected["inspect"]["threshold"])
        self.assertEqual(result.total_shares, expected["inspect"]["total_shares"])
        self.assertEqual(result.wrapper_count, expected["inspect"]["wrapper_count"])
        self.assertEqual(len(container), expected["inspect"]["total_container_bytes"])


class TestDiffX25519001(unittest.TestCase):
    def test_decrypt(self):
        container, plaintext_expected, km_json, expected = load_vector("DIFF-X25519-001")
        sk = bytes.fromhex(km_json["recipient_sk_hex"])
        km = X25519KeyMaterial(secret_key=sk)
        result = decrypt(container, km)

        self.assertEqual(result.plaintext, plaintext_expected)
        self.assertEqual(result.plaintext, bytes.fromhex(expected["plaintext_hex"]))
        self.assertEqual(result.logical_name, expected["logical_name"])
        self.assertEqual(result.format_version_major, expected["inspect"]["format_version_major"])
        self.assertEqual(result.format_version_minor, expected["inspect"]["format_version_minor"])
        self.assertEqual(result.suite_id, expected["inspect"]["suite_id"])
        self.assertEqual(result.header_hash.hex(), expected["inspect"]["header_hash"])
        self.assertEqual(result.threshold, expected["inspect"]["threshold"])
        self.assertEqual(result.total_shares, expected["inspect"]["total_shares"])
        self.assertEqual(result.wrapper_count, expected["inspect"]["wrapper_count"])
        self.assertEqual(len(container), expected["inspect"]["total_container_bytes"])


class TestDiffMlKem001(unittest.TestCase):
    def test_decrypt(self):
        container, plaintext_expected, km_json, expected = load_vector("DIFF-MLKEM-001")
        x25519_sk = bytes.fromhex(km_json["x25519_sk_hex"])
        mlkem_dk_seed = bytes.fromhex(km_json["mlkem_dk_seed_hex"])
        km = MlKem768X25519KeyMaterial(x25519_sk=x25519_sk, mlkem_dk_seed=mlkem_dk_seed)
        result = decrypt(container, km)

        self.assertEqual(result.plaintext, plaintext_expected)
        self.assertEqual(result.plaintext, bytes.fromhex(expected["plaintext_hex"]))
        self.assertEqual(result.logical_name, expected["logical_name"])
        self.assertEqual(result.format_version_major, expected["inspect"]["format_version_major"])
        self.assertEqual(result.format_version_minor, expected["inspect"]["format_version_minor"])
        self.assertEqual(result.suite_id, expected["inspect"]["suite_id"])
        self.assertEqual(result.header_hash.hex(), expected["inspect"]["header_hash"])
        self.assertEqual(result.threshold, expected["inspect"]["threshold"])
        self.assertEqual(result.total_shares, expected["inspect"]["total_shares"])
        self.assertEqual(result.wrapper_count, expected["inspect"]["wrapper_count"])
        self.assertEqual(len(container), expected["inspect"]["total_container_bytes"])


if __name__ == "__main__":
    unittest.main()
