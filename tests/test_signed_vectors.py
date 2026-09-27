"""
Verify tests/vectors/s2k.json (S2K signets) and tests/vectors/s2s.json (S2S
signed circle messages) against the reference implementation.

PUBLIC TEST-ONLY KEY MATERIAL lives in the vectors files (signet private keys
derived from public labels, circle passphrases). They are not keys. The tests
use a throwaway keyring; ./keys and your SIGIL_HOME are never touched.
"""

from __future__ import annotations

import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import sigil  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec, ed25519  # noqa: E402
from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: E402

V_K = json.loads((ROOT / "tests" / "vectors" / "s2k.json").read_text(encoding="utf-8"))
V_S = json.loads((ROOT / "tests" / "vectors" / "s2s.json").read_text(encoding="utf-8"))


def error_kind(m: dict) -> str:
    if not m["complete"]:
        return "incomplete"
    if m["verified"]:
        return ""
    return "bad-signature" if m["error"].startswith("BAD SIGNATURE") else "unknown-signer"


class KeyringMixin:
    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.TemporaryDirectory(prefix="sigil-signed-vectors-")
        cls.saved_home = sigil.HOME
        sigil.HOME = Path(cls.tmp.name)

    @classmethod
    def tearDownClass(cls) -> None:
        sigil.HOME = cls.saved_home
        cls.tmp.cleanup()

    def use(self, v: dict, own=(), contacts=(), circles=()) -> None:
        home = Path(self.tmp.name)
        for pat in ("signet-*.json", "contacts.json", "circle-*.json"):
            for f in home.glob(pat):
                f.unlink()
        signets = {s["id"]: s for s in v["signets"]}
        for sid in own:
            sigil.save_json(sigil.signet_path(signets[sid]["name"]), signets[sid]["record"])
        for sid in contacts:
            s = signets[sid]
            sigil.parse_announcement(s["announcement"])
            sigil.remember_contact(s["name"], s["pk"], s["name"], s["sign_pk"])
        cs = {c["id"]: c for c in v.get("circles", [])}
        for cid in circles:
            sigil.circle_create(cs[cid]["name"], cs[cid]["passphrase"], note="public test vector - not a key")


class TestSignets(unittest.TestCase):
    def test_signets_are_labelled_and_rederivable(self) -> None:
        for v in (V_K, V_S):
            self.assertIn("PUBLIC TEST-ONLY", v["WARNING"])
            for s in v["signets"]:
                with self.subTest(signet=s["id"]):
                    self.assertIn("DO-NOT-USE", s["label"])
                    n = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
                    d = int.from_bytes(hashlib.sha256((s["label"] + "-p256").encode()).digest(), "big") % (n - 1) + 1
                    self.assertEqual(d.to_bytes(32, "big").hex(), s["sk_hex"])
                    sk = sigil._sk_from_pem(s["record"]["sk_pem"])
                    self.assertEqual(sk.private_numbers().private_value, d)
                    self.assertEqual(sigil.b64e(sigil._pk_bytes(sk.public_key())), s["pk"])
                    self.assertEqual(sigil.short_id(sigil.b64d(s["pk"])), s["short"])
                    self.assertEqual(sigil.fingerprint(sigil.b64d(s["pk"])), s["fingerprint"])
                    self.assertEqual(s["fingerprint"][:4].lower(), s["short"])
                    seed = hashlib.sha256((s["label"] + "-ed25519").encode()).digest()
                    self.assertEqual(seed.hex(), s["sign_seed_hex"])
                    ssk = sigil._sign_sk_from_rec(s["record"])
                    spk = sigil._spk_bytes(ssk.public_key())
                    self.assertEqual(sigil.b64e(spk), s["sign_pk"])
                    self.assertEqual(sigil.s2s_keyid(spk).hex(), s["sign_keyid_hex"])
                    self.assertEqual(sigil.b64d(s["sign_fingerprint"])[:8].hex(), s["sign_keyid_hex"])
                    ann = sigil.parse_announcement(s["announcement"])
                    self.assertEqual((ann["pk"], ann["spk"]), (s["pk"], s["sign_pk"]))


class TestS2KVectors(KeyringMixin, unittest.TestCase):
    def test_directions(self) -> None:
        signets = {s["id"]: s for s in V_K["signets"]}
        for d in V_K["directions"]:
            with self.subTest(direction=f"{d['from']}->{d['to']}"):
                a, b = signets[d["from"]], signets[d["to"]]
                ctx = sigil.s2_context("K", a["short"], b["short"])
                self.assertEqual(ctx.decode(), d["ctx"])
                info = ctx + sigil.b64d(a["pk"]) + sigil.b64d(b["pk"])
                self.assertEqual(info.hex(), d["info_hex"])
                # Both ends derive the same key.
                k1 = sigil.ecdh_key(sigil._sk_from_pem(a["record"]["sk_pem"]), sigil._pk_from_b64(b["pk"]), info)
                k2 = sigil.ecdh_key(sigil._sk_from_pem(b["record"]["sk_pem"]), sigil._pk_from_b64(a["pk"]), info)
                self.assertEqual(k1.hex(), d["key_hex"])
                self.assertEqual(k2.hex(), d["key_hex"])
                shared = sigil._sk_from_pem(a["record"]["sk_pem"]).exchange(ec.ECDH(), sigil._pk_from_b64(b["pk"]))
                self.assertEqual(shared.hex(), d["ecdh_x_hex"])

    def test_positive(self) -> None:
        signets = {s["id"]: s for s in V_K["signets"]}
        for vec in V_K["positive"]:
            with self.subTest(vector=vec["id"]):
                self.use(V_K, vec["opener"]["own"], vec["opener"]["contacts"])
                got = [sigil.open_line(x) for x in vec["lines"]]
                for r, p in zip(got, vec["parts"], strict=True):
                    self.assertEqual(r["mode"], "signet")
                    self.assertEqual(r["from"], signets[vec["from"]]["name"])
                    self.assertEqual((r["plaintext"], r["sender"], r["mid"]), (p["plaintext"], p["sender"], p["mid_hex"]))
                msgs = sigil.assemble_messages(got)
                self.assertEqual(len(msgs), 1)
                self.assertEqual(msgs[0]["text"], vec["joined"])
                if not vec["seal"]["compact"]:
                    self.assertEqual(vec["joined"], vec["plaintext"])

    def test_positive_bytes(self) -> None:
        """Re-seal every part from the recorded nonce: byte-identical token."""
        signets = {s["id"]: s for s in V_K["signets"]}
        for vec in V_K["positive"]:
            a, b = signets[vec["from"]], signets[vec["to"]]
            ctx = sigil.s2_context("K", a["short"], b["short"])
            key = sigil.ecdh_key(sigil._sk_from_pem(a["record"]["sk_pem"]), sigil._pk_from_b64(b["pk"]),
                                 ctx + sigil.b64d(a["pk"]) + sigil.b64d(b["pk"]))
            for p in vec["parts"]:
                with self.subTest(vector=vec["id"], part=p["index"]):
                    header = bytes.fromhex(p["header_hex"])
                    self.assertEqual((header + ctx).hex(), p["aad_hex"])
                    nonce, payload = bytes.fromhex(p["nonce_hex"]), bytes.fromhex(p["payload_hex"])
                    blob = sigil.b64e(header + nonce + AESGCM(key).encrypt(nonce, payload, header + ctx))
                    self.assertEqual(f"S2K.{b['short']}.{a['short']}.{blob}", p["token"])

    def test_negative(self) -> None:
        for vec in V_K["negative"]:
            with self.subTest(vector=vec["id"]):
                self.use(V_K, vec["opener"]["own"], vec["opener"]["contacts"])
                with self.assertRaises(Exception):
                    sigil.open_line(vec["line"])


class TestS2SVectors(KeyringMixin, unittest.TestCase):
    def test_positive(self) -> None:
        signets = {s["id"]: s for s in V_S["signets"]}
        for vec in V_S["positive"]:
            with self.subTest(vector=vec["id"]):
                self.use(V_S, (), vec["verifier_keys"], ["main"])
                got = [sigil.open_line(x) for x in vec["lines"]]
                for r, p in zip(got, vec["parts"], strict=True):
                    self.assertEqual(r["mode"], "signed")
                    self.assertEqual((r["plaintext"], r["sender"], r["payload_hex"]),
                                     (p["plaintext"], p["sender"], p["payload_hex"]))
                msgs = sigil.assemble_messages(got)
                self.assertEqual(len(msgs), 1)
                m = msgs[0]
                self.assertTrue(m["verified"], m["error"])
                self.assertEqual(m["signer"], vec["expect"]["signer"])
                self.assertEqual(m["signer_fp"], signets[vec["signer"]]["sign_fingerprint"])
                self.assertEqual(m["text"], vec["joined"])
                if not vec["seal"]["compact"]:
                    self.assertEqual(vec["joined"], vec["plaintext"])
                else:
                    self.assertEqual(vec["joined"].lower(), vec["plaintext"].lower())

    def test_positive_bytes(self) -> None:
        """Signed bytes, deterministic Ed25519 signature and every sealed part re-derive exactly."""
        circles = {c["id"]: c for c in V_S["circles"]}
        signets = {s["id"]: s for s in V_S["signets"]}
        for vec in V_S["positive"]:
            with self.subTest(vector=vec["id"]):
                c = circles[vec["circle"]]
                key = bytes.fromhex(c["key_hex"])
                ctx = sigil.s2_context("S", c["name"])
                keyid = bytes.fromhex(vec["keyid_hex"])
                self.assertEqual(keyid.hex(), signets[vec["signer"]]["sign_keyid_hex"])
                parts = [(bytes.fromhex(p["header_hex"]), bytes.fromhex(p["payload_hex"])) for p in vec["parts"]]
                tbs = sigil.s2s_signed_bytes(ctx, keyid, parts)
                self.assertEqual(tbs.hex(), vec["signed_bytes_hex"])
                ssk = ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(signets[vec["signer"]]["sign_seed_hex"]))
                self.assertEqual(ssk.sign(tbs).hex(), vec["sig_hex"])
                for k, p in enumerate(vec["parts"]):
                    header, payload = parts[k]
                    sealed = payload + (keyid + bytes.fromhex(vec["sig_hex"]) if k == len(parts) - 1 else b"")
                    self.assertEqual(sealed.hex(), p["sealed_plaintext_hex"])
                    self.assertEqual((header + ctx).hex(), p["aad_hex"])
                    nonce = bytes.fromhex(p["nonce_hex"])
                    blob = sigil.b64e(header + nonce + AESGCM(key).encrypt(nonce, sealed, header + ctx))
                    self.assertEqual(f"S2S.{c['slug']}.{blob}", p["token"])
                    self.assertLessEqual(len(p["token"]), vec["seal"]["max_line"])

    def test_messages(self) -> None:
        for vec in V_S["messages"]:
            with self.subTest(vector=vec["id"]):
                self.use(V_S, (), vec["verifier_keys"], ["main"])
                opened = []
                for line in vec["lines"]:
                    try:
                        opened.append(sigil.open_line(line))
                    except ValueError:
                        pass
                msgs = sigil.assemble_messages(opened)
                verified = [m for m in msgs if m["verified"]]
                if vec["expect"]["verified"]:
                    self.assertEqual(len(verified), 1)
                    self.assertEqual(verified[0]["signer"], vec["expect"]["signer"])
                else:
                    self.assertEqual(verified, [])
                    self.assertTrue(all(m["text"] is None for m in msgs))
                    self.assertIn(vec["expect"]["error"], [error_kind(m) for m in msgs] or ["incomplete"])

    def test_negative(self) -> None:
        for vec in V_S["negative"]:
            with self.subTest(vector=vec["id"]):
                self.use(V_S, (), ["alice", "bob"], ["main"])
                with self.assertRaises(Exception):
                    sigil.open_line(vec["line"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
