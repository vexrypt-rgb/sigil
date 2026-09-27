"""
S2 wire format round-trip and tamper tests.

    python3 -m unittest discover -s tests -v

Throwaway keyrings in temp dirs only; passphrases are public test values.
"""

from __future__ import annotations

import contextlib
import io
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import codebook  # noqa: E402
import sigil  # noqa: E402

PASS = "public-s2-test-passphrase-DO-NOT-USE"
LEX = [w for w in codebook.codebook_v2() if w.isalpha() and w.islower()]


def edit_blob(token: str, fn) -> str:
    head, blob = token.rsplit(".", 1)
    data = bytearray(sigil.b64d(blob))
    fn(data)
    return f"{head}.{sigil.b64e(bytes(data))}"


class S2Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.TemporaryDirectory(prefix="sigil-s2-test-")
        cls.saved_home = sigil.HOME
        sigil.HOME = Path(cls.tmp.name)
        sigil.circle_create("s2test", PASS, note="public test value - not a key")
        cls.circle = sigil.load_circle("s2test")
        cls.steve = sigil.signet_create("Steve")
        cls.alex = sigil.signet_create("Alex")
        sigil.remember_contact("Alex", cls.alex["pk"], "Alex")
        sigil.remember_contact("Steve", cls.steve["pk"], "Steve")

    @classmethod
    def tearDownClass(cls) -> None:
        sigil.HOME = cls.saved_home
        cls.tmp.cleanup()

    def setUp(self) -> None:
        sigil.HOME = Path(self.tmp.name)

    def seal(self, mode: str, text: str, **kw) -> list[str]:
        if mode == "C":
            return sigil.seal_circle_s2(self.circle, text, **kw)
        return sigil.seal_to_signet_s2(self.steve, sigil.find_contact("Alex"), text,
                                       ephemeral=(mode == "E"), **kw)

    def open_all(self, lines: list[str]) -> list[dict]:
        return sigil.assemble_messages([sigil.open_line(line) for line in lines])

    def roundtrip(self, mode: str, text: str, **kw) -> tuple[list[str], dict]:
        lines = self.seal(mode, text, **kw)
        for line in lines:
            self.assertTrue(line.startswith(f"S2{mode}."), line)
            self.assertLessEqual(len(line), kw.get("max_line", 256))
        msgs = self.open_all(lines)
        self.assertEqual(len(msgs), 1)
        self.assertTrue(msgs[0]["complete"])
        return lines, msgs[0]


class S2RoundTrip(S2Base):
    def test_raw_one_two_three_parts_all_modes(self) -> None:
        for mode in "CKE":
            cap1 = sigil.s2_capacity(mode)
            capn = sigil.s2_capacity(mode, multi=True)
            for n, length in ((1, cap1), (2, cap1 + 1), (3, 2 * capn + 5)):
                with self.subTest(mode=mode, n=n):
                    text = "".join("abcdefghijklmnopqrstuvwxyz0123456789"[(i * 7) % 36] for i in range(length))
                    lines, msg = self.roundtrip(mode, text)
                    self.assertEqual(len(lines), n)
                    self.assertEqual(msg["text"], text)
                    if n > 1:
                        mids = {r["mid"] for r in msg["parts"]}
                        self.assertEqual(len(mids), 1)
                        self.assertEqual(len(bytes.fromhex(mids.pop())), sigil.S2_MID_LEN)
                    else:
                        self.assertEqual(msg["parts"][0]["mid"], "")

    def test_single_line_capacity_is_exact(self) -> None:
        for mode in "CKE":
            for max_line in (256, 234, 180):
                with self.subTest(mode=mode, max_line=max_line):
                    cap = sigil.s2_capacity(mode, max_line)
                    self.assertEqual(len(self.seal(mode, "a" * cap, max_line=max_line)), 1)
                    self.assertEqual(len(self.seal(mode, "a" * (cap + 1), max_line=max_line)), 2)

    def test_unicode(self) -> None:
        text = "Grüße 🧭 北 -320 / ñ / שלום / e\u0301 " * 12
        for mode in "CKE":
            with self.subTest(mode=mode):
                lines, msg = self.roundtrip(mode, text)
                self.assertGreater(len(lines), 1)
                self.assertEqual(msg["text"], text)

    def test_compact_multipart_spaces_exact(self) -> None:
        text = " ".join(LEX[(i * 13) % 500] for i in range(320))
        for mode in "CKE":
            with self.subTest(mode=mode):
                lines, msg = self.roundtrip(mode, text, compact=True)
                self.assertGreaterEqual(len(lines), 3)
                self.assertTrue(all(r["codebook"] for r in msg["parts"]))
                self.assertTrue(all(r["join"] for r in msg["parts"][:-1]))
                self.assertEqual(msg["text"], text)

    def test_compact_midword_split_exact(self) -> None:
        text = "/".join(LEX[(i * 7) % 300] for i in range(260))  # no spaces anywhere
        lines, msg = self.roundtrip("C", text, compact=True)
        parts = msg["parts"]
        self.assertGreaterEqual(len(parts), 3)
        self.assertTrue(all(r["codebook"] and not r["join"] for r in parts))
        midword = [k for k in range(len(parts) - 1)
                   if parts[k]["plaintext"][-1:].isalpha() and parts[k + 1]["plaintext"][:1].isalpha()]
        self.assertTrue(midword, "expected at least one cut inside a word")
        self.assertEqual(msg["text"], text)
        # The same text through S1: its stitcher has to guess, and inserts spaces.
        s1 = sigil.assemble_messages([sigil.open_line(x) for x in
                                      sigil.seal_circle(self.circle, text, compact=True)])
        self.assertNotEqual(s1[0]["text"], text)

    def test_compact_case_only_difference(self) -> None:
        text = ("Nether Roof stash at 0 128 0 then the Ruined Portal " * 10).strip()
        _, msg = self.roundtrip("C", text, compact=True)
        self.assertEqual(msg["text"].lower(), text.lower())

    def test_compact_never_reshapes_text(self) -> None:
        # Codebook v2 alone would space out a 40-char token and drop the
        # double space; S2's sealer sends such parts raw instead.
        text = "stash  at " + "q" * 40 + " ok,no space"
        self.assertNotEqual(codebook.expand(codebook.compress(text)), text)
        _, msg = self.roundtrip("C", text, compact=True)
        self.assertEqual(msg["text"], text)

    def test_sender(self) -> None:
        for mode in "CKE":
            with self.subTest(mode=mode):
                _, msg = self.roundtrip(mode, "abcdefghij" * 40, sender="Steve")
                self.assertEqual(msg["parts"][0]["sender"], "Steve")
                self.assertTrue(all(r["sender"] is None for r in msg["parts"][1:]))
                self.assertEqual(msg["text"], "abcdefghij" * 40)
        with self.assertRaises(ValueError):
            self.seal("C", "x", sender="n" * (sigil.S2_MAX_SENDER + 1))

    def test_too_many_parts(self) -> None:
        with self.assertRaises(ValueError):
            self.seal("C", "a" * (sigil.s2_capacity("C", multi=True) * sigil.S2_MAX_PARTS + 1))
        lines = self.seal("C", "a" * (sigil.s2_capacity("C", multi=True) * sigil.S2_MAX_PARTS))
        self.assertEqual(len(lines), sigil.S2_MAX_PARTS)


class S2Tamper(S2Base):
    def assert_fails(self, line: str) -> None:
        with self.assertRaises(Exception):
            sigil.open_line(line)

    def test_sender_tamper_fails(self) -> None:
        for mode in "CKE":
            with self.subTest(mode=mode):
                tok = self.seal(mode, "meet at spawn", sender="Steve")[0]
                fr = sigil.s2_parse_frame(sigil.b64d(tok.rsplit(".", 1)[1]), mode == "E")
                ct_at = len(fr["header"]) + len(fr["eph"]) + sigil.NONCE_LEN
                self.assert_fails(edit_blob(tok, lambda d: d.__setitem__(ct_at + 1, d[ct_at + 1] ^ 1)))
                self.assert_fails(edit_blob(tok, lambda d: d.__setitem__(0, d[0] ^ sigil.S2_S)))
                # A loose suffix does not change the authenticated sender.
                self.assertEqual(sigil.open_line(tok + " #Mallory")["sender"], "Steve")

    def test_relabelled_part_fails(self) -> None:
        lines = self.seal("C", "abcdefghij" * 40)
        self.assertEqual(len(lines), 3)
        for new in ((1 << 4) | 2, (0 << 4) | 1, (2 << 4) | 3):
            with self.subTest(part_byte=new):
                self.assert_fails(edit_blob(lines[0], lambda d: d.__setitem__(1, new)))

    def test_flag_flips_fail(self) -> None:
        z = self.seal("C", " ".join(LEX[:250]), compact=True)
        self.assertTrue(len(z) > 1)
        for bit in (sigil.S2_Z, sigil.S2_J, sigil.S2_S, sigil.S2_M, 0x10, 0x80):
            with self.subTest(bit=bit):
                self.assert_fails(edit_blob(z[0], lambda d: d.__setitem__(0, d[0] ^ bit)))

    def test_cross_message_splice_fails(self) -> None:
        a = self.seal("C", "abcdefghij" * 40)
        b = self.seal("C", "klmnopqrst" * 40)
        self.assertEqual((len(a), len(b)), (3, 3))
        # Every line still opens, but the ids differ: nothing is assembled.
        msgs = self.open_all([a[0], b[1], a[2]])
        self.assertFalse(any(m["complete"] for m in msgs))
        # Forging B's part 2 into A by rewriting the message id breaks the tag.
        mid_a = sigil.b64d(a[0].rsplit(".", 1)[1])[2:2 + sigil.S2_MID_LEN]
        self.assert_fails(edit_blob(b[1], lambda d: d.__setitem__(slice(2, 2 + sigil.S2_MID_LEN), mid_a)))
        # And the CLI prints no stitched message for the splice.
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            sigil.main(["open", "\n".join([a[0], b[1], a[2]])])
        self.assertNotIn("3 parts]", out.getvalue())
        self.assertIn("incomplete S2 message", err.getvalue())

    def test_cross_mode_and_version_fail(self) -> None:
        tok = self.seal("C", "hello")[0]
        s1 = sigil.seal_circle(self.circle, "hello")[0]
        self.assert_fails("S1C." + tok.split(".", 1)[1])           # S2 frame as S1
        self.assert_fails(f"S2C.{self.circle['slug']}.{s1.rsplit('.', 1)[1]}")  # S1 blob as S2
        k = self.seal("K", "hello")[0]
        self.assert_fails("S2E." + k.split(".", 1)[1].split(".", 1)[1])


class S2Compat(S2Base):
    def cli(self, *argv: str, stdin: str = "") -> str:
        out = io.StringIO()
        old_stdin = sys.stdin
        sys.stdin = io.StringIO(stdin)
        try:
            with contextlib.redirect_stdout(out):
                sigil.main(list(argv))
        finally:
            sys.stdin = old_stdin
        return out.getvalue()

    def test_s1_tokens_still_open(self) -> None:
        text = "abcdefghij" * 40
        for lines in (sigil.seal_circle(self.circle, text),
                      sigil.seal_to_signet(self.steve, sigil.find_contact("Alex"), text),
                      sigil.seal_to_signet(self.steve, sigil.find_contact("Alex"), text, ephemeral=True)):
            with self.subTest(head=lines[0][:3]):
                self.assertTrue(lines[0].startswith("S1"))
                msgs = self.open_all(lines)
                self.assertTrue(msgs[0]["complete"])
                self.assertEqual(msgs[0]["text"], text)

    def test_mixed_s1_and_s2_lines(self) -> None:
        out = self.cli("open", "\n".join(sigil.seal_circle(self.circle, "old peer") +
                                         sigil.seal_circle_s2(self.circle, "new peer")))
        self.assertIn("old peer", out)
        self.assertIn("new peer", out)

    def test_cli_default_s2_and_wire_flag(self) -> None:
        saved = os.environ.pop("SIGIL_WIRE", None)
        try:
            s2 = self.cli("seal", "-c", "s2test", "--raw", "portal at 1847 12 -320").split()
            self.assertTrue(s2[0].startswith("S2C."), s2)
            s1 = self.cli("seal", "-c", "s2test", "--wire", "S1", "portal at 1847 12 -320").split()
            self.assertTrue(s1[0].startswith("S1C."), s1)
            opened = self.cli("open", s2[0] + "\n" + s1[0])
            self.assertEqual(opened.count("portal at 1847 12 -320"), 2)
            snd = self.cli("seal", "-c", "s2test", "--sender", "Steve", "hi there").split()[0]
            meta = self.cli("open", snd).splitlines()[0]
            self.assertIn("sender=Steve (circle member claim)", meta)
        finally:
            if saved is not None:
                os.environ["SIGIL_WIRE"] = saved


if __name__ == "__main__":
    unittest.main(verbosity=2)
