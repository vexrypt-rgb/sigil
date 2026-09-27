#!/usr/bin/env python3
"""
Measure per-line plaintext capacity of S1 vs S2 (incl. S2S signed) with the real sealers.

    python3 tools/capacity.py

Raw (non-codebook) ASCII, no sender. "single" = longest message that stays
one line; "per part" = plaintext bytes carried by a full fragment (part 1 of a
long message). Uses a throwaway keyring in a temp dir and public test values only.
"""

from __future__ import annotations

import functools
import os
import sys
import tempfile
from pathlib import Path

_TMP = tempfile.TemporaryDirectory(prefix="sigil-capacity-")
os.environ["SIGIL_HOME"] = _TMP.name
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import sigil  # noqa: E402

sigil.HOME = Path(_TMP.name)
sigil.derive_circle_key = functools.lru_cache(None)(sigil.derive_circle_key)

WHISPER = len("/msg ") + 16 + 1  # 16-char player name


def main() -> None:
    sigil.circle_create("capacitytest", "public-capacity-test-DO-NOT-USE")
    circle = sigil.load_circle("capacitytest")
    me, them = sigil.signet_create("CapMe"), sigil.signet_create("CapThem")
    sigil.remember_contact("CapThem", them["pk"], "CapThem")
    sigil.remember_contact("CapMe", me["pk"], "CapMe")  # so the S1K/S2K parts can be opened here
    contact = sigil.find_contact("CapThem")

    sealers = {
        ("S1", "C"): lambda t, m: sigil.seal_circle(circle, t, max_line=m),
        ("S1", "K"): lambda t, m: sigil.seal_to_signet(me, contact, t, max_line=m),
        ("S1", "E"): lambda t, m: sigil.seal_to_signet(me, contact, t, ephemeral=True, max_line=m),
        ("S2", "C"): lambda t, m: sigil.seal_circle_s2(circle, t, max_line=m),
        ("S2", "K"): lambda t, m: sigil.seal_to_signet_s2(me, contact, t, max_line=m),
        ("S2", "E"): lambda t, m: sigil.seal_to_signet_s2(me, contact, t, ephemeral=True, max_line=m),
        ("S2", "S"): lambda t, m: sigil.seal_circle_signed_s2(circle, me, t, max_line=m),
    }

    def single(fn, m: int) -> int:
        lo, hi = 0, 400
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if len(fn("a" * mid, m)) == 1:
                lo = mid
            else:
                hi = mid - 1
        return lo

    def per_part(fn, m: int) -> tuple[int, int]:
        text = "".join(chr(97 + i % 26) for i in range(1500))
        lines = fn(text, m)
        longest = max(len(line) for line in lines)
        first = sigil.open_line(lines[0])["plaintext"]
        return len(first.encode("utf-8")), longest

    print(f"{'wire':4} {'mode':4} {'max_line':>8} {'single':>7} {'per part':>9} {'longest line':>13}")
    for m in (256, 256 - WHISPER):
        for (wire, mode), fn in sealers.items():
            s = single(fn, m)
            pp, longest = per_part(fn, m)
            flag = "" if longest <= m else "  (exceeds max_line)"
            print(f"{wire:4} {mode:4} {m:8} {s:7} {pp:9} {longest:13}{flag}")
    print()
    print("lines needed for N raw bytes (S2C vs S2S signed vs S2K)")
    print(f"{'max_line':>8} " + " ".join(f"{n:>11}" for n in (40, 67, 84, 120, 200, 300, 600)))
    for m in (256, 256 - WHISPER):
        for mode in ("C", "S", "K"):
            fn = sealers[("S2", mode)]
            print(f"{m:8} " + " ".join(f"{'S2' + mode + ' ' + str(len(fn('a' * n, m))):>11}" for n in (40, 67, 84, 120, 200, 300, 600)))
    _TMP.cleanup()


if __name__ == "__main__":
    main()
