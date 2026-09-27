"""
Regression tests for `sigil open` fragment stitching.

    python3 -m unittest discover -s tests -v

Raw (non-codebook) fragments are cut mid-word by the plain chunker, so the
stitcher must concatenate them byte-exact. Only codebook (`.z`) fragments get
whitespace restoration at part boundaries.

Every test runs against a throwaway keyring in a temporary directory; ./keys
and your SIGIL_HOME are never read or written. The passphrase below is a
public test value, not a key.
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

import codebook  # noqa: E402
import sigil  # noqa: E402

TEST_PASSPHRASE = "public-test-passphrase-DO-NOT-USE"


class OpenStitch(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="sigil-stitch-test-")
        self._saved_home = sigil.HOME
        sigil.HOME = Path(self._tmp.name)
        sigil.circle_create("stitchtest", TEST_PASSPHRASE, note="public test value - not a key")
        self.circle = sigil.load_circle("stitchtest")

    def tearDown(self) -> None:
        sigil.HOME = self._saved_home
        self._tmp.cleanup()

    def cli_open(self, lines: list[str]) -> list[str]:
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            sigil.main(["open", "\n".join(lines)])
        return out.getvalue().splitlines()

    def assert_stitched(self, lines: list[str], expected: str) -> None:
        printed = self.cli_open(lines)
        self.assertEqual(len(printed), 2, printed)
        self.assertTrue(printed[0].endswith(f" {len(lines)} parts]"), printed[0])
        self.assertEqual(printed[1], expected)

    # -- raw fragments: exact concatenation --------------------------------

    def test_raw_circle_three_parts_mid_word(self) -> None:
        msg = "".join("abcdefghijklmnopqrstuvwxyz0123456789"[(i * 7) % 36] for i in range(400))
        lines = sigil.seal_circle(self.circle, msg)
        self.assertEqual(len(lines), 3)
        self.assertFalse(any(".z." in line for line in lines))
        pieces = [sigil.open_line(line)["plaintext"] for line in lines]
        # The chunker really did cut between two alphanumerics (mid-word).
        for left, right in zip(pieces, pieces[1:]):
            self.assertTrue(left[-1].isalnum() and right[0].isalnum(), (left[-1], right[0]))
        self.assertEqual("".join(pieces), msg)
        self.assert_stitched(lines, msg)

    def test_raw_circle_three_parts_prose(self) -> None:
        rng = random.Random(7)
        words = ["portal", "at", "1847", "Nether", "roof,", "stash", "the", "elytra.", "don't", "sell"]
        msg = " ".join(rng.choice(words) for _ in range(62))
        lines = sigil.seal_circle(self.circle, msg)
        self.assertEqual(len(lines), 3)
        self.assertFalse(any(".z." in line for line in lines))
        self.assert_stitched(lines, msg)

    def test_raw_signet_three_parts_mid_word(self) -> None:
        steve = sigil.signet_create("Steve")
        alex = sigil.signet_create("Alex")
        sigil.remember_contact("Alex", alex["pk"], "Alex")
        sigil.remember_contact("Steve", steve["pk"], "Steve")
        msg = "".join("abcdefghijklmnopqrstuvwxyz"[(i * 5) % 26] for i in range(380))
        lines = sigil.seal_to_signet(steve, sigil.find_contact("Alex"), msg)
        self.assertEqual(len(lines), 3)
        self.assert_stitched(lines, msg)

    def test_compact_requested_but_raw_parts_stay_exact(self) -> None:
        # Non-dictionary text: the codebook does not shrink it, so every part
        # goes out raw (no .z) even with compact=True, and is cut mid-word.
        msg = "".join("qxzvkjwbfp"[(i * 3) % 10] for i in range(300))
        lines = sigil.seal_circle(self.circle, msg, compact=True)
        self.assertGreaterEqual(len(lines), 2)
        self.assertFalse(any(".z." in line for line in lines))
        self.assert_stitched(lines, msg)

    # -- codebook fragments: still readable --------------------------------

    def test_compact_multipart_still_readable(self) -> None:
        vocab = [w for w in codebook.codebook_v2() if w.isalpha() and w.islower()][:400]
        rng = random.Random(1847)
        tokens = []
        for k in range(330):
            tokens.append(rng.choice(vocab) + ("," if k % 11 == 10 else ""))
        msg = " ".join(tokens)
        # Precondition: this text survives the (lossy) codebook as one piece.
        self.assertEqual(codebook.expand(codebook.compress(msg)), msg)
        lines = sigil.seal_circle(self.circle, msg, compact=True)
        self.assertGreaterEqual(len(lines), 3)
        self.assertTrue(all(".z." in line for line in lines))
        pieces = [sigil.open_line(line)["plaintext"] for line in lines]
        # The codebook drops each part's trailing space...
        self.assertNotEqual("".join(pieces), msg)
        # ...and the stitcher puts it back.
        self.assert_stitched(lines, msg)


if __name__ == "__main__":
    unittest.main(verbosity=2)
