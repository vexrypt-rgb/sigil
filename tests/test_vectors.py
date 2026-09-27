"""
Verify tests/vectors/s1c.json against the reference implementation.

    python3 -m unittest discover -s tests -v

PUBLIC TEST-ONLY KEY MATERIAL lives in the vectors file. It is not a key.
The test uses a throwaway temporary keyring; ./keys and your SIGIL_HOME
are never read or written.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
VECTORS = ROOT / "tests" / "vectors" / "s1c.json"

_TMP = tempfile.TemporaryDirectory(prefix="sigil-vectors-test-")
os.environ["SIGIL_HOME"] = _TMP.name
sys.path.insert(0, str(ROOT))

import codebook  # noqa: E402
import sigil  # noqa: E402
from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: E402

sigil.HOME = Path(_TMP.name)


def _load() -> dict:
    return json.loads(VECTORS.read_text(encoding="utf-8"))


class S1CVectors(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.v = _load()
        cls.circles = {c["id"]: c for c in cls.v["circles"]}

    @classmethod
    def tearDownClass(cls) -> None:
        _TMP.cleanup()

    def use_keyring(self, ids: list[str]) -> None:
        for f in Path(_TMP.name).glob("circle-*.json"):
            f.unlink()
        for cid in ids:
            c = self.circles[cid]
            sigil.circle_create(c["name"], c["passphrase"], note="public test vector - not a key")

    def test_header(self) -> None:
        self.assertIn("PUBLIC TEST-ONLY", self.v["WARNING"])
        self.assertEqual(self.v["protocol"], sigil.VERSION)
        self.assertEqual(self.v["aad_prefix"], sigil.PROTOCOL)
        self.assertEqual(self.v["kdf"]["iterations"], sigil.PBKDF2_ITERS)
        self.assertEqual(self.v["lexicon_v2_sha256"], sigil.lexicon_hash())

    def test_circles(self) -> None:
        for c in self.v["circles"]:
            with self.subTest(circle=c["id"]):
                self.assertIn("DO-NOT-USE", c["passphrase"])
                key = sigil.derive_circle_key(c["name"], c["passphrase"])
                self.assertEqual(key.hex(), c["key_hex"])
                self.assertEqual(sigil.slugify(c["name"]), c["slug"])
                self.assertEqual(sigil.short_id(key), c["fingerprint"])
                self.assertEqual(c["kdf"], f"PBKDF2-HMAC-SHA256/{sigil.PBKDF2_ITERS}")

    def test_positive_open(self) -> None:
        for vec in self.v["positive"]:
            with self.subTest(vector=vec["id"]):
                self.use_keyring(vec["keyring"])
                self.assertEqual(len(vec["lines"]), len(vec["parts"]))
                for line, part in zip(vec["lines"], vec["parts"]):
                    got = sigil.open_line(line)
                    self.assertTrue(got["ok"])
                    self.assertEqual(got["mode"], "circle")
                    self.assertEqual(got["circle"], self.circles[vec["circle"]]["name"])
                    self.assertEqual(got["part"], f"{part['index']}/{part['total']}")
                    self.assertEqual(got["plaintext"], part["plaintext"])
                if not any(p["compact"] for p in vec["parts"]) and not vec["id"].startswith("lenient"):
                    # Raw UTF-8 chunks concatenate back to the exact original.
                    self.assertEqual("".join(p["plaintext"] for p in vec["parts"]), vec["plaintext"])
                    self.assertEqual(bytes.fromhex(vec["plaintext_utf8_hex"]).decode("utf-8"), vec["plaintext"])

    def test_positive_bytes(self) -> None:
        """Nonce + AAD + payload re-seal to the exact recorded blob (deterministic check)."""
        for vec in self.v["positive"]:
            key = bytes.fromhex(self.circles[vec["circle"]]["key_hex"])
            name = self.circles[vec["circle"]]["name"]
            slug = self.circles[vec["circle"]]["slug"]
            for part in vec["parts"]:
                with self.subTest(vector=vec["id"], part=part["index"]):
                    nonce = bytes.fromhex(part["nonce_hex"])
                    payload = bytes.fromhex(part["payload_hex"])
                    z = ".z" if part["compact"] else ""
                    aad = f"{sigil.PROTOCOL}.C.{name}{z}.{part['index']}/{part['total']}"
                    self.assertEqual(aad, part["aad"])
                    blob = sigil.b64e(nonce + AESGCM(key).encrypt(nonce, payload, aad.encode("utf-8")))
                    frag = f".{part['index']}/{part['total']}" if part["total"] > 1 else ""
                    token = f"{sigil.VERSION}C.{slug}{z}{frag}.{blob}"
                    if part.get("opened_compact_flag"):
                        # lenient vector: '.z' was inserted after sealing.
                        token = token.replace(f"C.{slug}.", f"C.{slug}.z.", 1)
                    self.assertEqual(token, part["token"])
                    expect = codebook.maybe_expand(payload) if part["compact"] else payload.decode("utf-8")
                    self.assertEqual(expect, part["plaintext"])

    def test_negative(self) -> None:
        for vec in self.v["negative"]:
            with self.subTest(vector=vec["id"]):
                self.use_keyring(vec["keyring"])
                with self.assertRaises(Exception):
                    sigil.open_line(vec["line"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
