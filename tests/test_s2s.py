"""
S2S (signed circle, sigil 0.5.0) round-trip, capacity, tamper, impersonation
and splice tests.

    python3 -m unittest discover -s tests -v

Throwaway keyrings in temp dirs only; passphrases are public test values and
signets are generated per run.
"""

from __future__ import annotations

import contextlib
import io
import random
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import sigil  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec, ed25519  # noqa: E402
from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: E402

PASS = "public-s2s-test-passphrase-DO-NOT-USE"


def reseal(circle: dict, token: str, fn) -> str:
    """A circle member's forgery: decrypt a part, edit header/plaintext, re-encrypt under the circle key."""
    key = sigil.derive_circle_key(circle["name"], circle["passphrase"])
    ctx = sigil.s2_context("S", circle["name"])
    head, blob = token.rsplit(".", 1)
    fr = sigil.s2_parse_frame(sigil.b64d(blob))
    pt = bytearray(AESGCM(key).decrypt(fr["nonce"], fr["ct"], fr["header"] + ctx))
    header = bytearray(fr["header"])
    fn(header, pt)
    return f"{head}.{sigil.b64e(bytes(header) + fr['nonce'] + AESGCM(key).encrypt(fr['nonce'], bytes(pt), bytes(header) + ctx))}"


class S2SBase(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.TemporaryDirectory(prefix="sigil-s2s-test-")
        cls.saved_home = sigil.HOME
        sigil.HOME = Path(cls.tmp.name)
        sigil.circle_create("s2stest", PASS, note="public test value - not a key")
        cls.circle = sigil.load_circle("s2stest")
        cls.alice = sigil.signet_create("Alice")
        cls.bob = sigil.signet_create("Bob")
        # Mallory is a circle member (she holds the passphrase) but not a trusted signer.
        cls.mallory = sigil.signet_record("Mallory", ec.generate_private_key(ec.SECP256R1()),
                                          ed25519.Ed25519PrivateKey.generate())
        for s in (cls.alice, cls.bob):
            sigil.remember_contact(s["name"], s["pk"], s["name"], s["sign_pk"])

    @classmethod
    def tearDownClass(cls) -> None:
        sigil.HOME = cls.saved_home
        cls.tmp.cleanup()

    def setUp(self) -> None:
        sigil.HOME = Path(self.tmp.name)

    def seal(self, text: str, signer=None, **kw) -> list[str]:
        return sigil.seal_circle_signed_s2(self.circle, signer or self.alice, text, **kw)

    def assemble(self, lines: list[str]) -> list[dict]:
        opened = []
        for line in lines:
            try:
                opened.append(sigil.open_line(line))
            except ValueError:
                pass
        return sigil.assemble_messages(opened)

    def verified(self, lines: list[str]) -> list[dict]:
        return [m for m in self.assemble(lines) if m["verified"]]


class RoundTrip(S2SBase):
    def test_lengths_and_line_limits(self) -> None:
        rnd = random.Random(7)
        for max_line in (256, 234, 180):
            for n in list(range(0, 40)) + list(range(60, 180, 7)) + [300, 600, 1200]:
                text = "".join(rnd.choice("abc XYZ 012") for _ in range(n))
                with self.subTest(max_line=max_line, n=n):
                    lines = self.seal(text, max_line=max_line)
                    self.assertTrue(all(len(x) <= max_line and x.startswith("S2S.") for x in lines))
                    m = self.verified(lines)
                    self.assertEqual(len(m), 1)
                    self.assertEqual(m[0]["text"], text)
                    self.assertEqual(m[0]["signer"], "Alice")
                    self.assertEqual(m[0]["signer_fp"], sigil.fingerprint(sigil.b64d(self.alice["sign_pk"])))

    def test_trailer_placement_is_minimal(self) -> None:
        """A message uses one extra line only when the 72-byte trailer does not fit the last part."""
        room1 = sigil.s2_payload_room(256, 9, False)
        roomm = sigil.s2_payload_room(256, 9, True)
        self.assertEqual(sigil.s2_capacity("S"), room1 - sigil.S2S_TRAILER)
        cases = {room1 - 72: 1, room1 - 71: 2, 2 * roomm - 72: 2, 2 * roomm - 71: 3}
        for n, lines in cases.items():
            with self.subTest(n=n):
                got = self.seal("a" * n)
                self.assertEqual(len(got), lines)
                self.assertEqual(self.verified(got)[0]["text"], "a" * n)
        # The spill part carries only the trailer: empty raw body, Z=0.
        spill = [sigil.open_line(x) for x in self.seal("a" * (room1 - 71))]
        self.assertEqual((spill[-1]["plaintext"], spill[-1]["codebook"], spill[-1]["payload_hex"]), ("", False, ""))

    def test_compact_unicode_sender(self) -> None:
        texts = ["nether roof stash at 0 128 0 bring the diamond pickaxe " * 5,
                 "Grüße 🧭 北 שלום e\u0301 " * 12, "/".join(["stash", "portal", "diamond"] * 40)]
        for text in texts:
            for compact in (False, True):
                with self.subTest(text=text[:20], compact=compact):
                    lines = self.seal(text.strip(), sender="Alice", compact=compact)
                    m = self.verified(lines)
                    self.assertEqual(len(m), 1)
                    self.assertEqual(m[0]["text"].lower(), text.strip().lower())
                    self.assertEqual(m[0]["parts"][0]["sender"], "Alice")

    def test_too_many_parts(self) -> None:
        with self.assertRaises(ValueError):
            self.seal("x" * 3000)

    def test_each_single_line_is_its_own_message(self) -> None:
        a, b = self.seal("first")[0], self.seal("second", signer=self.bob)[0]
        got = sorted((m["signer"], m["text"]) for m in self.verified([a, b]))
        self.assertEqual(got, [("Alice", "first"), ("Bob", "second")])

    def test_duplicates_ignored(self) -> None:
        lines = self.seal("abcdefghij" * 40)
        m = self.verified([lines[0]] + lines + [lines[1]])
        self.assertEqual(len(m), 1)


class Tamper(S2SBase):
    def test_every_bit_flip_by_outsider_fails(self) -> None:
        lines = self.seal("abcdefghij" * 25)
        for k, line in enumerate(lines):
            head, blob = line.rsplit(".", 1)
            data = sigil.b64d(blob)
            for pos in range(len(data)):
                bad = bytearray(data)
                bad[pos] ^= 0x01
                tampered = list(lines)
                tampered[k] = f"{head}.{sigil.b64e(bytes(bad))}"
                with self.subTest(line=k, pos=pos):
                    self.assertEqual(self.verified(tampered), [])

    def test_circle_member_edits_fail(self) -> None:
        """Mallory holds the circle key: she can re-encrypt, but cannot re-sign."""
        lines = self.seal("pay 5 diamonds to Mallory? no: pay 5 diamonds to Bob " * 3)
        last = len(lines) - 1

        def flip(pos):
            def f(h, pt):
                pt[pos] ^= 0x20
            return f
        for k in range(len(lines)):
            for pos in (0, 5, -1, -64, -65, -72):
                with self.subTest(part=k, pos=pos):
                    t = list(lines)
                    try:
                        t[k] = reseal(self.circle, lines[k], flip(pos))
                    except IndexError:
                        continue
                    self.assertEqual(self.verified(t), [])
        # Flags in the header: J flip on part 1 (header is in the signed bytes as well as the AAD).
        t = list(lines)
        t[0] = reseal(self.circle, lines[0], lambda h, pt: h.__setitem__(0, h[0] ^ sigil.S2_J))
        self.assertEqual(self.verified(t), [])
        # Truncation: drop the last part and relabel n.
        def relabel_n(n):
            def f(h, pt):
                h[1] = (h[1] & 0xF0) | (n - 1)
            return f
        if len(lines) > 2:
            t = [reseal(self.circle, x, relabel_n(len(lines) - 1)) for x in lines[:last]]
            self.assertEqual(self.verified(t), [])

    def test_s2c_is_never_signed(self) -> None:
        s2c = sigil.seal_circle_s2(self.circle, "unsigned", sender="Alice")
        msgs = self.assemble(s2c)
        self.assertFalse(msgs[0].get("signed"))
        with self.assertRaises(ValueError):
            sigil.open_line(s2c[0].replace("S2C.", "S2S.", 1))
        with self.assertRaises(ValueError):
            sigil.open_line(self.seal("signed")[0].replace("S2S.", "S2C.", 1))


class Impersonation(S2SBase):
    def test_unknown_signer_refused(self) -> None:
        m = self.assemble(self.seal("I am Alice", signer=self.mallory, sender="Alice"))
        self.assertFalse(m[0]["verified"])
        self.assertIsNone(m[0]["text"])
        self.assertIn("unknown signer", m[0]["error"])

    def test_keyid_swap_refused(self) -> None:
        keyid = sigil.s2s_keyid(sigil.b64d(self.alice["sign_pk"]))
        line = self.seal("I am Alice", signer=self.mallory, sender="Alice")[0]
        forged = reseal(self.circle, line, lambda h, pt: pt.__setitem__(slice(-72, -64), keyid))
        m = self.assemble([forged])
        self.assertFalse(m[0]["verified"])
        self.assertTrue(m[0]["error"].startswith("BAD SIGNATURE"))

    def test_known_signer_is_reported_not_sender_claim(self) -> None:
        sigil.remember_contact("Mallory", self.mallory["pk"], "Mallory", self.mallory["sign_pk"])
        try:
            m = self.verified(self.seal("I am Alice", signer=self.mallory, sender="Alice"))
            self.assertEqual((m[0]["signer"], m[0]["parts"][0]["sender"]), ("Mallory", "Alice"))
        finally:
            book = sigil.load_contacts()
            for k in [k for k, e in book["contacts"].items() if e["alias"] == "Mallory"]:
                del book["contacts"][k]
            sigil.save_json(sigil.contacts_path(), book)

    def test_no_signing_key_cannot_seal(self) -> None:
        old = sigil.signet_record("Old", ec.generate_private_key(ec.SECP256R1()))
        with self.assertRaises(ValueError):
            sigil.seal_circle_signed_s2(self.circle, old, "hi")


class Splice(S2SBase):
    def test_parts_of_two_messages_never_verify(self) -> None:
        a = self.seal("abcdefghij" * 30)
        b = self.seal("klmnopqrst" * 30)
        self.assertEqual(len(a), len(b))
        mid_a = sigil.s2_parse_frame(sigil.b64d(a[0].rsplit(".", 1)[1]))["mid"]
        # Plain splice: different ids, nothing assembles from the mix.
        mixed = [a[0], b[1]] + a[2:]
        self.assertEqual([m["text"] for m in self.verified(mixed)], [])
        # Rewritten id by a circle member: assembles, but the signature covers a's part 2.
        forged = reseal(self.circle, b[1], lambda h, pt: h.__setitem__(slice(2, 8), mid_a))
        self.assertEqual(self.verified([a[0], forged] + a[2:]), [])
        # Both messages intact and interleaved: both verify.
        both = sorted(m["text"] for m in self.verified([x for pair in zip(a, b) for x in pair]))
        self.assertEqual(both, sorted(["abcdefghij" * 30, "klmnopqrst" * 30]))

    def test_cross_circle_replay_fails(self) -> None:
        sigil.circle_create("s2sother", PASS, note="public test value - not a key")
        other = sigil.load_circle("s2sother")
        line = self.seal("only for s2stest")[0]
        # Mallory holds both circles: re-encrypt the exact plaintext under the other circle.
        key = sigil.derive_circle_key(self.circle["name"], PASS)
        fr = sigil.s2_parse_frame(sigil.b64d(line.rsplit(".", 1)[1]))
        pt = AESGCM(key).decrypt(fr["nonce"], fr["ct"], fr["header"] + sigil.s2_context("S", self.circle["name"]))
        k2 = sigil.derive_circle_key(other["name"], PASS)
        ctx2 = sigil.s2_context("S", other["name"])
        moved = f"S2S.{other['slug']}.{sigil.b64e(fr['header'] + fr['nonce'] + AESGCM(k2).encrypt(fr['nonce'], pt, fr['header'] + ctx2))}"
        m = self.assemble([moved])
        self.assertEqual(m[0]["circle"] if "circle" in m[0] else m[0]["parts"][0]["circle"], "s2sother")
        self.assertFalse(m[0]["verified"])


class Keys(S2SBase):
    def test_announcement_and_upgrade(self) -> None:
        ann = sigil.announce_signet(self.alice)
        self.assertTrue(ann.startswith("S2+PK.Alice."))
        p = sigil.parse_announcement(ann)
        self.assertEqual((p["pk"], p["spk"]), (self.alice["pk"], self.alice["sign_pk"]))
        old = sigil.signet_record("Legacy", ec.generate_private_key(ec.SECP256R1()))
        sigil.save_json(sigil.signet_path("Legacy"), old)
        self.assertTrue(sigil.announce_signet(old).startswith("S1+PK.Legacy."))
        up = sigil.signet_add_signing_key("Legacy")
        self.assertEqual((up["pk"], up["short"]), (old["pk"], old["short"]))
        self.assertTrue(sigil.announce_signet(up).startswith("S2+PK.Legacy."))
        self.assertEqual(len(self.verified(sigil.seal_circle_signed_s2(self.circle, up, "upgraded"))), 1)

    def test_bad_contact_signing_key(self) -> None:
        with self.assertRaises(SystemExit):
            sigil.remember_contact("X", self.alice["pk"], "X", sigil.b64e(b"\x01" * 31))


class Cli(S2SBase):
    def run_cli(self, *argv, stdin: str = "") -> tuple[str, str]:
        out, err = io.StringIO(), io.StringIO()
        old_stdin = sys.stdin
        sys.stdin = io.StringIO(stdin)
        try:
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                try:
                    sigil.main(list(argv))
                except SystemExit:
                    pass
        finally:
            sys.stdin = old_stdin
        return out.getvalue(), err.getvalue()

    def test_seal_sign_and_open(self) -> None:
        out, _ = self.run_cli("seal", "-c", "s2stest", "--sign", "--from-signet", "Bob", "--raw",
                              "meet at the portal " * 10)
        lines = out.split()
        self.assertTrue(lines and all(x.startswith("S2S.") for x in lines))
        out, err = self.run_cli("open", "\n".join(lines))
        self.assertIn("signer=Bob", out)
        self.assertIn(("meet at the portal " * 10), out + " ")
        # A forged one is not printed.
        forged = self.seal("I am Alice", signer=self.mallory)
        out, err = self.run_cli("open", forged[0])
        self.assertNotIn("I am Alice", out)
        self.assertIn("NOT shown", err)
        # Lone part of a multi-part message: nothing printed.
        out, err = self.run_cli("open", lines[0])
        self.assertEqual(out.strip(), "")
        self.assertIn("incomplete S2S", err)

    def test_sign_requires_circle(self) -> None:
        with self.assertRaises(SystemExit):
            sigil.main(["seal", "--to", "Alice", "--sign", "hi"])

    def test_fingerprint_command(self) -> None:
        out, _ = self.run_cli("fingerprint")
        self.assertIn(f"fp={sigil.fingerprint(sigil.b64d(self.alice['pk']))}", out)
        self.assertIn(f"sfp={sigil.fingerprint(sigil.b64d(self.alice['sign_pk']))}", out)


if __name__ == "__main__":
    unittest.main(verbosity=2)
