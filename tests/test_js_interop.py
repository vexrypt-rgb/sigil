"""
Python <-> browser (sigil_s2.js) interop for S2, run through Node.

    python3 -m unittest discover -s tests -v     # skipped if `node` is missing

Keys are generated fresh in a temp keyring for each run and handed to the
Node driver on stdin; nothing is written to the repo.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import sigil  # noqa: E402

NODE = shutil.which("node")
DRIVER = ROOT / "tests" / "js" / "sigil_node.cjs"
PASS = "public-interop-test-passphrase-DO-NOT-USE"


def node(*args: str, job: dict | None = None) -> subprocess.CompletedProcess:
    return subprocess.run([NODE, str(DRIVER), *args], input=json.dumps(job) if job else None,
                          capture_output=True, text=True, timeout=300, cwd=ROOT)


def jwk(signet: dict) -> dict:
    sk = sigil._sk_from_pem(signet["sk_pem"])
    nums = sk.private_numbers()
    return {
        "kty": "EC", "crv": "P-256", "ext": True,
        "d": sigil.b64e(nums.private_value.to_bytes(32, "big")),
        "x": sigil.b64e(nums.public_numbers.x.to_bytes(32, "big")),
        "y": sigil.b64e(nums.public_numbers.y.to_bytes(32, "big")),
    }


def sign_jwk(signet: dict) -> dict:
    """Ed25519 private JWK (RFC 8037) for a signet's signing key."""
    sk = sigil._sign_sk_from_rec(signet)
    raw = sk.private_bytes(sigil.serialization.Encoding.Raw, sigil.serialization.PrivateFormat.Raw,
                           sigil.serialization.NoEncryption())
    return {"kty": "OKP", "crv": "Ed25519", "ext": True, "d": sigil.b64e(raw), "x": signet["sign_pk"]}


def js_signet(s: dict) -> dict:
    return {"name": s["name"], "short": s["short"], "pk": s["pk"], "jwk": jwk(s), "sign_jwk": sign_jwk(s)}


MESSAGES = [
    ("portal at 1847 12 -320", {}),
    ("abcdefghij" * 40, {}),
    ("Grüße 🧭 北 שלום e\u0301 " * 15, {}),
    ("nether roof stash at 0 128 0 bring the diamond pickaxe and the eye of ender " * 6, {"compact": True}),
    ("/".join(["stash", "portal", "diamond", "nether", "roof"] * 40), {"compact": True}),
    ("who sent this", {"sender": "Steve"}),
    ("abcdefghij" * 30, {"sender": "Alex", "compact": True}),
]


@unittest.skipIf(NODE is None, "node not installed")
class JsInterop(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.TemporaryDirectory(prefix="sigil-interop-test-")
        cls.saved_home = sigil.HOME
        sigil.HOME = Path(cls.tmp.name)
        sigil.circle_create("interop", PASS, note="public test value - not a key")
        cls.circle = sigil.load_circle("interop")
        cls.steve = sigil.signet_create("Steve")
        cls.alex = sigil.signet_create("Alex")
        sigil.remember_contact("Alex", cls.alex["pk"], "Alex", cls.alex["sign_pk"])
        sigil.remember_contact("Steve", cls.steve["pk"], "Steve", cls.steve["sign_pk"])
        # Mallory is in the circle but NOT in anyone's keyring (never saved to HOME).
        cls.mallory = sigil.signet_record("Mallory", sigil.ec.generate_private_key(sigil.ec.SECP256R1()),
                                          sigil.ed25519.Ed25519PrivateKey.generate())
        cls.ring = {
            "circles": [{"name": "interop", "pass": PASS}],
            "signets": [js_signet(s) for s in (cls.steve, cls.alex)],
            "contacts": [{"alias": s["name"], "short": s["short"], "pk": s["pk"], "spk": s["sign_pk"]}
                         for s in (cls.steve, cls.alex)],
        }

    @classmethod
    def tearDownClass(cls) -> None:
        sigil.HOME = cls.saved_home
        cls.tmp.cleanup()

    def setUp(self) -> None:
        sigil.HOME = Path(self.tmp.name)

    def test_js_selftest(self) -> None:
        p = node("selftest")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("js selftest ok", p.stdout)

    def test_js_opens_vectors(self) -> None:
        for name in ("s2c.json", "s2k.json", "s2s.json"):
            with self.subTest(vectors=name):
                p = node("vectors", str(ROOT / "tests" / "vectors" / name))
                self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
                self.assertIn(" 0 failed", p.stdout)

    def test_s2s_python_signs_js_verifies(self) -> None:
        for signer in (self.steve, self.alex):
            for text, kw in MESSAGES:
                with self.subTest(signer=signer["name"], text=text[:20], **kw):
                    lines = sigil.seal_circle_signed_s2(self.circle, signer, text, **kw)
                    p = node("job", job=dict(self.ring, op="open", lines=lines))
                    self.assertEqual(p.returncode, 0, p.stderr)
                    res = json.loads(p.stdout)
                    self.assertEqual(res["errors"], [])
                    self.assertEqual(len(res["messages"]), 1)
                    js = res["messages"][0]
                    self.assertTrue(js["verified"], js.get("error"))
                    self.assertEqual(js["signer"], signer["name"])
                    self.assertEqual(js["signerFp"], sigil.fingerprint(sigil.b64d(signer["sign_pk"])))
                    want = text.lower() if kw.get("compact") else text
                    self.assertEqual(js["text"], want)
        # Mallory holds the circle key but her signing key is unknown: JS must not show it.
        lines = sigil.seal_circle_signed_s2(self.circle, self.mallory, "I am Steve", sender="Steve")
        res = json.loads(node("job", job=dict(self.ring, op="open", lines=lines)).stdout)
        self.assertEqual(len(res["messages"]), 1)
        self.assertFalse(res["messages"][0]["verified"])
        self.assertIsNone(res["messages"][0]["text"])
        self.assertIn("unknown signer", res["messages"][0]["error"])

    def test_s2s_js_signs_python_verifies(self) -> None:
        jobs = [{"mode": "S", "text": text, "from_short": s["short"], "circle": {"name": "interop", "pass": PASS}, **kw}
                for s in (self.steve, self.alex, self.mallory) for text, kw in MESSAGES]
        ring = dict(self.ring, signets=self.ring["signets"] + [js_signet(self.mallory)])
        p = node("job", job=dict(ring, op="seal", messages=jobs))
        self.assertEqual(p.returncode, 0, p.stderr)
        sealed = json.loads(p.stdout)["lines"]
        for m, lines in zip(jobs, sealed, strict=True):
            with self.subTest(signer=m["from_short"], text=m["text"][:20]):
                self.assertTrue(all(x.startswith("S2S.") and len(x) <= 256 for x in lines))
                msgs = sigil.assemble_messages([sigil.open_line(x) for x in lines])
                self.assertEqual(len(msgs), 1)
                self.assertTrue(msgs[0]["complete"])
                if m["from_short"] == self.mallory["short"]:
                    self.assertFalse(msgs[0]["verified"])
                    self.assertIsNone(msgs[0]["text"])
                    continue
                self.assertTrue(msgs[0]["verified"], msgs[0].get("error"))
                who = self.steve if m["from_short"] == self.steve["short"] else self.alex
                self.assertEqual(msgs[0]["signer"], who["name"])
                self.assertEqual(msgs[0]["text"], m["text"].lower() if m.get("compact") else m["text"])

    def test_python_seals_js_opens(self) -> None:
        alex = sigil.find_contact("Alex")
        for mode in "CKE":
            for text, kw in MESSAGES:
                with self.subTest(mode=mode, text=text[:20], **kw):
                    if mode == "C":
                        lines = sigil.seal_circle_s2(self.circle, text, **kw)
                    else:
                        lines = sigil.seal_to_signet_s2(self.steve, alex, text, ephemeral=(mode == "E"), **kw)
                    py = sigil.assemble_messages([sigil.open_line(x) for x in lines])[0]
                    p = node("job", job=dict(self.ring, op="open", lines=lines))
                    self.assertEqual(p.returncode, 0, p.stderr)
                    res = json.loads(p.stdout)
                    self.assertEqual(res["errors"], [])
                    self.assertEqual(len(res["messages"]), 1)
                    js = res["messages"][0]
                    self.assertTrue(js["complete"])
                    self.assertEqual(js["text"], py["text"])
                    self.assertEqual(js["sender"], kw.get("sender"))

    def test_js_seals_python_opens(self) -> None:
        jobs = []
        for mode in "CKE":
            for text, kw in MESSAGES:
                m = {"mode": mode, "text": text, **kw}
                if mode == "C":
                    m["circle"] = {"name": "interop", "pass": PASS}
                else:
                    m.update(ephemeral=(mode == "E"), from_short=self.steve["short"],
                             contact={"short": self.alex["short"], "pk": self.alex["pk"]})
                jobs.append(m)
        p = node("job", job=dict(self.ring, op="seal", messages=jobs))
        self.assertEqual(p.returncode, 0, p.stderr)
        sealed = json.loads(p.stdout)["lines"]
        for m, lines in zip(jobs, sealed, strict=True):
            with self.subTest(mode=m["mode"], text=m["text"][:20]):
                self.assertTrue(all(x.startswith(f"S2{m['mode']}.") and len(x) <= 256 for x in lines))
                msgs = sigil.assemble_messages([sigil.open_line(x) for x in lines])
                self.assertEqual(len(msgs), 1)
                self.assertTrue(msgs[0]["complete"])
                if m.get("compact"):
                    self.assertEqual(msgs[0]["text"].lower(), m["text"].lower())
                else:
                    self.assertEqual(msgs[0]["text"], m["text"])
                self.assertEqual(msgs[0]["parts"][0]["sender"], m.get("sender"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
