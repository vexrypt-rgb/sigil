#!/usr/bin/env python3
"""
Generate SIGIL cross-language test vectors:
  tests/vectors/s1c.json  S1C circle messages
  tests/vectors/s2c.json  S2C circle messages (S2 frame header, message id, sender)

PUBLIC TEST-ONLY KEY MATERIAL. The passphrases below are published on
purpose so other implementations (Java, JS, ...) can check themselves
against the reference implementation. They are NOT keys. Never use them
for real messages.

How the vectors are made (no production code is changed or bypassed):
  * Every positive token is produced by the real `sigil.seal_circle`,
    which draws its nonce from os.urandom as usual. The script then
    *records* the output. Re-running the script gives new nonces and a
    different file; that is expected. Commit the file you verified.
  * The nonce is public and already sits in the first 12 bytes of each
    blob, so a port can re-seal a recorded part with that nonce and
    compare byte-for-byte. The script copies it out as `nonce_hex` for
    convenience, together with the exact AAD string and the exact bytes
    that went into AES-GCM (`payload_hex`: UTF-8, or codebook-packed
    for `.z` parts).
  * Negative vectors are derived from recorded tokens by editing them
    (flip a byte, change a header field) or by sealing under a circle the
    opener does not hold.

Nothing touches ./keys or your real SIGIL_HOME: a temporary keyring dir is
used and deleted.

Usage:
  python3 tools/make_vectors.py                 # rewrite s1c.json and s2c.json
  python3 tools/make_vectors.py --suite s2c     # rewrite only s2c.json
  python3 tools/make_vectors.py --suite s1c --stdout   # print instead

S2 vectors are circle-only on purpose: S2K/S2E vectors would need a private
key in the repo. Those modes are covered by round-trip tests and by the live
Python<->JS interop test with keys generated at test time.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "tests" / "vectors" / "s1c.json"
OUT2 = ROOT / "tests" / "vectors" / "s2c.json"

# Must be set before sigil is imported: sigil reads SIGIL_HOME at import time.
_TMP = tempfile.TemporaryDirectory(prefix="sigil-vectors-")
os.environ["SIGIL_HOME"] = _TMP.name
sys.path.insert(0, str(ROOT))

import sigil  # noqa: E402
from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: E402

sigil.HOME = Path(_TMP.name)

WARNING = (
    "PUBLIC TEST-ONLY KEY MATERIAL. These passphrases are published on purpose "
    "for cross-implementation testing. They are NOT keys. Never use them for real messages."
)

CIRCLES = {
    # id: (name, passphrase)
    "main": ("sigil-vector-test", "sigil-public-test-vector-passphrase-DO-NOT-USE"),
    # Same name, different passphrase: the "wrong key" circle.
    "wrongpass": ("sigil-vector-test", "sigil-public-test-vector-WRONG-passphrase-DO-NOT-USE"),
    # Different name, same slug ("sigi"), same passphrase: exercises slug collision
    # and proves the name is bound into salt + AAD.
    "sameslug": ("sigil-vector-other", "sigil-public-test-vector-passphrase-DO-NOT-USE"),
    # Mixed-case name: AAD and salt are case-preserving.
    "mixedcase": ("Sigil-Vector-MixedCase", "sigil-public-test-vector-passphrase-DO-NOT-USE"),
}


def use_keyring(circles: dict, ids: list[str]) -> None:
    """Make the temporary keyring hold exactly these circles (files are keyed by name)."""
    for f in Path(_TMP.name).glob("circle-*.json"):
        f.unlink()
    for cid in ids:
        c = circles[cid]
        sigil.circle_create(c["name"], c["passphrase"], note="public test vector - not a key")


def circle_record(cid: str) -> dict:
    name, passphrase = CIRCLES[cid]
    for f in Path(_TMP.name).glob("circle-*.json"):
        f.unlink()
    rec = sigil.circle_create(name, passphrase, note="public test vector - not a key")
    key = sigil.derive_circle_key(name, passphrase)
    salt = hashlib.sha256(f"{sigil.PROTOCOL}.circle.salt.{name}".encode("utf-8")).digest()[:16]
    return {
        "id": cid,
        "name": name,
        "passphrase": passphrase,
        "slug": rec["slug"],
        "fingerprint": rec["fingerprint"],
        "kdf": rec["kdf"],
        "salt_hex": salt.hex(),
        "key_hex": key.hex(),
    }


def parse_token(token: str) -> dict:
    """Split a bare S1C token into its public header fields (mirrors sigil.open_line)."""
    parts = token.split(".")
    blob = parts[-1]
    mid = parts[1:-1]
    index, total = 1, 1
    if mid and "/" in mid[-1] and mid[-1].replace("/", "").isdigit():
        a, b = mid[-1].split("/", 1)
        index, total = int(a), int(b)
        mid = mid[:-1]
    compact = bool(mid) and mid[-1] == "z"
    if compact:
        mid = mid[:-1]
    return {"slug": mid[0], "index": index, "total": total, "compact": compact, "blob": blob}


def describe_parts(circle: dict, tokens: list[str], circles: dict, keyring: list[str]) -> list[dict]:
    use_keyring(circles, keyring)
    key = bytes.fromhex(circle["key_hex"])
    out = []
    for tok in tokens:
        h = parse_token(tok)
        data = sigil.b64d(h["blob"])
        nonce, ct = data[: sigil.NONCE_LEN], data[sigil.NONCE_LEN:]
        z = ".z" if h["compact"] else ""
        aad = f"{sigil.PROTOCOL}.C.{circle['name']}{z}.{h['index']}/{h['total']}"
        payload = AESGCM(key).decrypt(nonce, ct, aad.encode("utf-8"))
        opened = sigil.open_line(tok)
        out.append({
            "token": tok,
            "index": h["index"],
            "total": h["total"],
            "compact": h["compact"],
            "nonce_hex": nonce.hex(),
            "aad": aad,
            "payload_hex": payload.hex(),
            "plaintext": opened["plaintext"],
        })
    return out


def positive(vid, circles, cid, plaintext, *, compact=False, max_line=256, note="", wrap=None, keyring=None):
    circle = circles[cid]
    keyring = keyring or [cid]
    tokens = sigil.seal_circle(_record_for(circle), plaintext, max_line=max_line, compact=compact)
    parts = describe_parts(circle, tokens, circles, keyring)
    lines = [wrap.format(token=t) if wrap else t for t in tokens]
    return {
        "id": vid,
        "circle": cid,
        "keyring": keyring,
        "seal": {"compact": compact, "max_line": max_line},
        "plaintext": plaintext,
        "plaintext_utf8_hex": plaintext.encode("utf-8").hex(),
        "lines": lines,
        "parts": parts,
        "joined_parts": "".join(p["plaintext"] for p in parts),
        "note": note,
    }


def _record_for(circle: dict) -> dict:
    # Build the in-memory record sigil.seal_circle expects without relying on
    # load_circle's first-match lookup (several vector circles share a name/slug).
    return {"name": circle["name"], "passphrase": circle["passphrase"], "slug": circle["slug"]}


def flip_blob_byte(token: str, pos: int) -> str:
    head, blob = token.rsplit(".", 1)
    data = bytearray(sigil.b64d(blob))
    data[pos] ^= 0x01
    return f"{head}.{sigil.b64e(bytes(data))}"


def largest_single_line(rec: dict, max_line: int) -> int:
    n = 1
    while len(sigil.seal_circle(rec, "a" * (n + 1), max_line=max_line)) == 1:
        n += 1
    return n


def build() -> dict:
    circles = {cid: circle_record(cid) for cid in CIRCLES}
    main_rec = _record_for(circles["main"])
    single_max = largest_single_line(main_rec, 256)
    single_max_180 = largest_single_line(main_rec, 180)

    pos = [
        positive("plain-short", circles, "main", "portal at 1847 12 -320",
                 note="Raw UTF-8, one line."),
        positive("plain-empty", circles, "main", "",
                 note="Empty plaintext still seals to a valid 28-byte blob."),
        positive("plain-single-line-max", circles, "main", "a" * single_max,
                 note=f"Longest ASCII run ({single_max} B) that sigil keeps in one line at max_line=256."),
        positive("plain-first-split", circles, "main", "a" * (single_max + 1),
                 note="One byte more than plain-single-line-max: sigil's chunker splits into i/n parts."),
        positive("plain-max-line-180", circles, "main", "b" * single_max_180,
                 max_line=180, note=f"Longest single line at max_line=180 ({single_max_180} B)."),
        positive("plain-multipart-3", circles, "main", "abcdefghij" * 30,
                 note="Three i/n parts. Parts split mid-word; concatenating part plaintexts restores the "
                      "original exactly (see note on CLI stitching in README)."),
        positive("unicode-mixed", circles, "main", "Grüße 🧭 北 -320 / ñ / שלום / e\u0301",
                 note="Multi-byte UTF-8, emoji (4-byte), RTL, combining mark."),
        positive("unicode-multipart-emoji", circles, "main", "🧱" * 60,
                 note="4-byte code points; the chunker must never split inside a code point."),
        positive("newline", circles, "main", "line one\nline two",
                 note="Newlines survive inside the ciphertext."),
        positive("compact-z", circles, "main", "nether roof stash at 0 128 0", compact=True,
                 note="Codebook v2 (.z). payload_hex is the packed codebook stream (starts 0xC2)."),
        positive("compact-no-gain", circles, "main", "Zq9xKv7Wm3", compact=True,
                 note="compact requested but the codebook does not shrink it: no .z flag, raw UTF-8 payload."),
        positive("compact-multipart", circles, "main", (
                 ("nether roof stash at 0 128 0 bring the diamond pickaxe and the eye of ender "
                  "meet at the ruined portal after dragon ") * 14).strip(),
                 compact=True, note="Codebook v2 with i/n parts. Each part is packed and sealed separately."),
        positive("compact-lossy", circles, "main", "Nether Roof stash at 0 128 0 ", compact=True,
                 note="Codebook v2 is lossy by design: dictionary words come back lowercase and trailing "
                      "whitespace is dropped. parts[].plaintext / joined_parts hold what sigil returns."),
        positive("mixed-case-name", circles, "mixedcase", "case matters in the AAD",
                 note="Circle name is case-preserving in salt and AAD."),
        positive("slug-collision", circles, "main", "tag picks the winner", keyring=["sameslug", "main"],
                 note="Two circles share slug 'sigi'; the opener tries both and the GCM tag decides."),
        positive("buried-in-text", circles, "main", "coords later",
                 wrap="check this tome {token} please",
                 note="The parser accepts a token buried in other text."),
        positive("sender-suffix", circles, "main", "anon or not",
                 wrap="{token} #Steve",
                 note="sigil appends ' #sender' outside the token when a sender is given; it is NOT authenticated."),
    ]

    # A raw token with a '.z' flag added still opens: open_line retries the
    # non-compact AAD when the compact AAD fails. Recorded as a positive
    # (lenient parser behaviour) so ports match it.
    base = positive("tmp", circles, "main", "lenient z retry")
    tok = base["parts"][0]["token"]
    head = f"S1C.{circles['main']['slug']}."
    zadded = tok.replace(head, head + "z.", 1)
    lenient = dict(base)
    lenient.update({
        "id": "lenient-z-flag-added",
        "lines": [zadded],
        "note": "'.z' inserted into a raw token after sealing. sigil still opens it because open_line "
                "falls back to the non-compact AAD. Header fields other than .z are authenticated.",
    })
    lenient["parts"] = [dict(base["parts"][0], token=zadded, opened_compact_flag=True)]
    pos.append(lenient)

    # ---- negatives -------------------------------------------------------
    short = positive("tmp", circles, "main", "tamper me")["parts"][0]["token"]
    multi = positive("tmp", circles, "main", "abcdefghij" * 30)["parts"]
    ztok = positive("tmp", circles, "main", "nether roof stash at 0 128 0", compact=True)["parts"][0]["token"]
    wrong = sigil.seal_circle(_record_for(circles["wrongpass"]), "you should not read this")[0]
    other = sigil.seal_circle(_record_for(circles["sameslug"]), "wrong name same slug")[0]
    blob_len = len(sigil.b64d(short.rsplit(".", 1)[1]))
    p1 = multi[0]["token"]

    neg = [
        {"id": "tampered-tag", "line": flip_blob_byte(short, blob_len - 1),
         "reason": "Last byte of the GCM tag flipped."},
        {"id": "tampered-ciphertext", "line": flip_blob_byte(short, sigil.NONCE_LEN),
         "reason": "First ciphertext byte flipped."},
        {"id": "tampered-nonce", "line": flip_blob_byte(short, 0),
         "reason": "First nonce byte flipped."},
        {"id": "wrong-passphrase", "line": wrong,
         "reason": "Same circle name, different passphrase (key mismatch)."},
        {"id": "wrong-name-same-slug", "line": other,
         "reason": "Sealed under 'sigil-vector-other' (same slug, same passphrase); opener only holds "
                   "'sigil-vector-test'. Name is bound into salt and AAD."},
        {"id": "fragment-index-swapped", "line": p1.replace(".1/3.", ".2/3.", 1),
         "reason": "Part 1/3 relabelled 2/3: i/n is in the AAD."},
        {"id": "fragment-total-changed", "line": p1.replace(".1/3.", ".1/2.", 1),
         "reason": "Part 1/3 relabelled 1/2: i/n is in the AAD."},
        {"id": "z-flag-removed", "line": ztok.replace(".z.", ".", 1),
         "reason": "'.z' removed from a compact token: '.z' is in the AAD and there is no fallback this way."},
        {"id": "slug-unknown", "line": short.replace(f".{circles['main']['slug']}.", ".qqqq.", 1),
         "reason": "Slug matches no circle on the keyring."},
        {"id": "truncated-blob", "line": f"S1C.{circles['main']['slug']}.{sigil.b64e(b'x' * 20)}",
         "reason": "Blob shorter than nonce + tag (28 bytes)."},
        {"id": "not-sigil", "line": "hello world, nothing sealed here",
         "reason": "No S1 token present."},
    ]
    for n in neg:
        n["keyring"] = ["main"]

    return {
        "format": "sigil-test-vectors",
        "format_version": 1,
        "WARNING": WARNING,
        "suite": "S1C circle messages",
        "protocol": sigil.VERSION,
        "aad_prefix": sigil.PROTOCOL,
        "generator": "tools/make_vectors.py (records real sigil.seal_circle output; random nonces)",
        "lexicon_v2_sha256": sigil.lexicon_hash(),
        "kdf": {
            "alg": "PBKDF2-HMAC-SHA256",
            "iterations": sigil.PBKDF2_ITERS,
            "length": 32,
            "salt": "SHA-256(UTF-8('SIGIL.v1.circle.salt.' + name))[0:16]",
        },
        "seal": {
            "cipher": "AES-256-GCM",
            "nonce_len": sigil.NONCE_LEN,
            "tag_len": sigil.TAG_LEN,
            "aad": "UTF-8('SIGIL.v1.C.' + name + ('.z' if compact else '') + '.' + i + '/' + n)",
            "blob": "base64url_nopad(nonce || ciphertext || tag)",
            "token": "S1C.<slug>[.z][.<i>/<n> only if n>1].<blob>",
        },
        "fields": {
            "positive[].keyring": "circle ids the opener holds",
            "positive[].lines": "exact chat lines (may wrap the token in other text)",
            "positive[].parts[].plaintext": "what sigil.open_line returns for that part (codebook-expanded for .z)",
            "positive[].parts[].payload_hex": "exact bytes that went into AES-GCM",
            "negative[]": "every line must FAIL to open with the given keyring",
        },
        "circles": list(circles.values()),
        "positive": pos,
        "negative": neg,
    }


# ---------------------------------------------------------------------------
# S2C
# ---------------------------------------------------------------------------

def s2_describe(circle: dict, tokens: list[str], keyring: list[str], circles: dict) -> list[dict]:
    use_keyring(circles, keyring)
    key = bytes.fromhex(circle["key_hex"])
    ctx = sigil.s2_context("C", circle["name"])
    out = []
    for tok in tokens:
        fr = sigil.s2_parse_frame(sigil.b64d(tok.rsplit(".", 1)[1]))
        aad = fr["header"] + ctx
        payload = AESGCM(key).decrypt(fr["nonce"], fr["ct"], aad)
        opened = sigil.open_line(tok)
        out.append({
            "token": tok,
            "index": fr["index"],
            "total": fr["total"],
            "flags": fr["flags"],
            "codebook": bool(fr["flags"] & sigil.S2_Z),
            "join": bool(fr["flags"] & sigil.S2_J),
            "sender": opened["sender"],
            "header_hex": fr["header"].hex(),
            "mid_hex": fr["mid"].hex(),
            "nonce_hex": fr["nonce"].hex(),
            "aad_hex": aad.hex(),
            "payload_hex": payload.hex(),
            "plaintext": opened["plaintext"],
        })
    return out


def s2_positive(vid, circles, cid, plaintext, *, compact=False, max_line=256, sender="", note="",
                wrap=None, keyring=None):
    circle = circles[cid]
    keyring = keyring or [cid]
    tokens = sigil.seal_circle_s2(_record_for(circle), plaintext, sender=sender, max_line=max_line,
                                  compact=compact)
    parts = s2_describe(circle, tokens, keyring, circles)
    joined = sigil.stitch_parts([(p["plaintext"], p["codebook"], p["join"]) for p in parts])
    return {
        "id": vid,
        "circle": cid,
        "keyring": keyring,
        "seal": {"compact": compact, "max_line": max_line, "sender": sender},
        "plaintext": plaintext,
        "plaintext_utf8_hex": plaintext.encode("utf-8").hex(),
        "lines": [wrap.format(token=t) if wrap else t for t in tokens],
        "parts": parts,
        "joined": joined,
        "joined_equals_plaintext": joined == plaintext,
        "note": note,
    }


def s2_edit(token: str, fn) -> str:
    head, blob = token.rsplit(".", 1)
    data = bytearray(sigil.b64d(blob))
    fn(data)
    return f"{head}.{sigil.b64e(bytes(data))}"


def s2_single_max(rec: dict, max_line: int) -> int:
    lo, hi = 0, 400
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if len(sigil.seal_circle_s2(rec, "a" * mid, max_line=max_line)) == 1:
            lo = mid
        else:
            hi = mid - 1
    return lo


def build_s2() -> dict:
    circles = {cid: circle_record(cid) for cid in CIRCLES}
    main_rec = _record_for(circles["main"])
    single_max = s2_single_max(main_rec, 256)
    single_max_180 = s2_single_max(main_rec, 180)
    lex_words = ["stash", "portal", "diamond", "nether", "roof", "pickaxe", "ender", "dragon"]
    slash_run = "/".join(lex_words * 30)

    pos = [
        s2_positive("plain-short", circles, "main", "portal at 1847 12 -320",
                    note="Raw UTF-8, one line: header is the single flags byte 0x00."),
        s2_positive("plain-empty", circles, "main", "", note="Empty plaintext: 1 + 12 + 16 byte frame."),
        s2_positive("plain-single-line-max", circles, "main", "a" * single_max,
                    note=f"Longest ASCII run ({single_max} B) that fits one line at max_line=256."),
        s2_positive("plain-first-split", circles, "main", "a" * (single_max + 1),
                    note="One byte more: two parts, each with part byte + 6-byte message id."),
        s2_positive("plain-max-line-180", circles, "main", "b" * single_max_180, max_line=180,
                    note=f"Longest single line at max_line=180 ({single_max_180} B)."),
        s2_positive("plain-multipart-3", circles, "main", "abcdefghij" * 40,
                    note="Three raw parts cut mid-word; J=0 everywhere; rejoin is exact."),
        s2_positive("unicode-mixed", circles, "main", "Grüße 🧭 北 -320 / ñ / שלום / e\u0301",
                    note="Multi-byte UTF-8, emoji, RTL, combining mark."),
        s2_positive("unicode-multipart-emoji", circles, "main", "🧱" * 80,
                    note="4-byte code points; parts never split inside a code point."),
        s2_positive("newline", circles, "main", "line one\nline two", note="Newlines survive."),
        s2_positive("compact-z", circles, "main", "nether roof stash at 0 128 0", compact=True,
                    note="Codebook v2 body (flags bit Z). payload_hex starts with 0xC2."),
        s2_positive("compact-no-gain", circles, "main", "Zq9xKv7Wm3", compact=True,
                    note="Compact requested, codebook does not shrink it: Z=0, raw UTF-8."),
        s2_positive("compact-multipart-spaces", circles, "main", (
                    ("nether roof stash at 0 128 0 bring the diamond pickaxe and the eye of ender "
                     "meet at the ruined portal after dragon ") * 14).strip(), compact=True,
                    note="Compact parts cut at a space that is consumed: J=1 on every part but the last. "
                         "Rejoin is exact (S1 needed a heuristic here)."),
        s2_positive("compact-multipart-midword", circles, "main", slash_run, compact=True,
                    note="No spaces at all: compact parts are cut mid-word (J=0) and still rejoin exactly. "
                         "S1's stitcher would insert a space at each cut."),
        s2_positive("compact-case", circles, "main", "Nether Roof stash at 0 128 0", compact=True,
                    note="Sealer policy: the codebook may lowercase dictionary words, so parts[].plaintext "
                         "can differ from the input in letter case only."),
        s2_positive("sender-single", circles, "main", "anon or not", sender="Steve",
                    note="Sender sealed inside the ciphertext (flags bit S): [len][UTF-8 name] then body. "
                         "Any holder of the circle key can claim any name."),
        s2_positive("sender-multipart", circles, "main", "abcdefghij" * 40, sender="Steve",
                    note="Sender field only in part 1; S=0 on later parts."),
        s2_positive("sender-compact", circles, "main", "nether roof stash at 0 128 0", compact=True,
                    sender="Alex", note="Sender field precedes the codebook body."),
        s2_positive("mixed-case-name", circles, "mixedcase", "case matters in the AAD",
                    note="Circle name is case-preserving in salt and AAD."),
        s2_positive("slug-collision", circles, "main", "tag picks the winner", keyring=["sameslug", "main"],
                    note="Two circles share slug 'sigi'; the GCM tag decides."),
        s2_positive("buried-in-text", circles, "main", "coords later",
                    wrap="check this tome {token} please", note="Token buried in other text."),
        s2_positive("loose-suffix-ignored", circles, "main", "who sent this", sender="Steve",
                    wrap="{token} #Mallory",
                    note="A loose ' #name' after the token is not part of S2; the sender is the sealed 'Steve'."),
    ]

    # ---- negatives (every line must fail to open) -------------------------
    short = s2_positive("tmp", circles, "main", "tamper me")["parts"][0]["token"]
    snd = s2_positive("tmp", circles, "main", "tamper me", sender="Steve")["parts"][0]["token"]
    multi = s2_positive("tmp", circles, "main", "abcdefghij" * 40)["parts"]
    other_msg = s2_positive("tmp", circles, "main", "klmnopqrst" * 40)["parts"]
    zmulti = s2_positive("tmp", circles, "main", (
        ("nether roof stash at 0 128 0 bring the diamond pickaxe and the eye of ender "
         "meet at the ruined portal after dragon ") * 14).strip(), compact=True)["parts"]
    assert len(zmulti) > 1 and zmulti[0]["join"]
    ztok = s2_positive("tmp", circles, "main", "nether roof stash at 0 128 0", compact=True)["parts"][0]["token"]
    wrong = sigil.seal_circle_s2(_record_for(circles["wrongpass"]), "you should not read this")[0]
    other = sigil.seal_circle_s2(_record_for(circles["sameslug"]), "wrong name same slug")[0]
    s1tok = sigil.seal_circle(_record_for(circles["main"]), "an S1 token")[0]
    p1, p2 = multi[0]["token"], multi[1]["token"]
    q2 = other_msg[1]["token"]
    mid_a = bytes.fromhex(multi[0]["mid_hex"])
    blob_len = len(sigil.b64d(short.rsplit(".", 1)[1]))
    slug = circles["main"]["slug"]

    def set_byte(pos, val):
        def f(d):
            d[pos] = val
        return f

    def xor_byte(pos, val):
        def f(d):
            d[pos] ^= val
        return f

    def as_single(d):
        d[0] &= ~sigil.S2_M & 0xFF
        del d[1:2 + sigil.S2_MID_LEN]

    def put_mid(mid):
        def f(d):
            d[2:2 + sigil.S2_MID_LEN] = mid
        return f

    neg = [
        {"id": "tampered-tag", "line": s2_edit(short, xor_byte(blob_len - 1, 1)), "reason": "Last tag byte flipped."},
        {"id": "tampered-ciphertext", "line": s2_edit(short, xor_byte(1 + sigil.NONCE_LEN, 1)),
         "reason": "First ciphertext byte flipped."},
        {"id": "tampered-nonce", "line": s2_edit(short, xor_byte(1, 1)), "reason": "First nonce byte flipped."},
        {"id": "sender-name-tampered", "line": s2_edit(snd, xor_byte(1 + sigil.NONCE_LEN + 1, 1)),
         "reason": "First byte of the sealed sender name flipped (inside the ciphertext)."},
        {"id": "sender-flag-cleared", "line": s2_edit(snd, xor_byte(0, sigil.S2_S)),
         "reason": "S bit cleared: the header is in the AAD."},
        {"id": "sender-flag-set", "line": s2_edit(short, xor_byte(0, sigil.S2_S)),
         "reason": "S bit set on a token without a sender field."},
        {"id": "z-flag-removed", "line": s2_edit(ztok, xor_byte(0, sigil.S2_Z)),
         "reason": "Z bit cleared on a codebook part. No lenient fallback in S2."},
        {"id": "z-flag-added", "line": s2_edit(short, xor_byte(0, sigil.S2_Z)),
         "reason": "Z bit set on a raw part. (S1 accepted '.z' added; S2 does not.)"},
        {"id": "join-flag-flipped", "line": s2_edit(zmulti[0]["token"], xor_byte(0, sigil.S2_J)),
         "reason": "J bit cleared on part 1 of a compact message: rejoin info is authenticated."},
        {"id": "join-flag-on-last-part", "line": s2_edit(multi[-1]["token"], xor_byte(0, sigil.S2_J)),
         "reason": "J set on the last part: rejected before decryption."},
        {"id": "reserved-bit-set", "line": s2_edit(short, xor_byte(0, 0x10)),
         "reason": "Reserved header bit set: rejected (future format)."},
        {"id": "fragment-index-relabelled", "line": s2_edit(p1, set_byte(1, (1 << 4) | 2)),
         "reason": "Part 1/3 relabelled 2/3: the part byte is in the AAD."},
        {"id": "fragment-total-relabelled", "line": s2_edit(p1, set_byte(1, (0 << 4) | 1)),
         "reason": "Part 1/3 relabelled 1/2."},
        {"id": "multi-part-as-single", "line": s2_edit(p1, as_single),
         "reason": "Part 1/3 rewritten as a single-part frame (M cleared, part+mid removed)."},
        {"id": "message-id-rewritten", "line": s2_edit(q2, put_mid(mid_a)),
         "reason": "Part 2 of message B given message A's id to splice it into A: the id is in the AAD."},
        {"id": "wrong-passphrase", "line": wrong, "reason": "Same name, different passphrase."},
        {"id": "wrong-name-same-slug", "line": other,
         "reason": "Sealed under 'sigil-vector-other' (same slug, same passphrase); name is in salt and AAD."},
        {"id": "s1-frame-relabelled-s2", "line": f"S2C.{slug}.{s1tok.rsplit('.', 1)[1]}",
         "reason": "An S1 blob presented as S2: different AAD domain (S1 AAD starts 'SIGIL.v1', S2 with the header)."},
        {"id": "slug-unknown", "line": short.replace(f"S2C.{slug}.", "S2C.qqqq.", 1),
         "reason": "Slug matches no circle."},
        {"id": "truncated-blob", "line": f"S2C.{slug}.{sigil.b64e(b'\x00' + b'x' * 20)}",
         "reason": "Frame shorter than header + nonce + tag."},
        {"id": "not-sigil", "line": "hello world, nothing sealed here", "reason": "No token."},
    ]
    for n in neg:
        n["keyring"] = ["main"]

    # ---- message-level vectors (grouping by message id) -------------------
    msgs = [
        {"id": "cross-message-splice", "keyring": ["main"], "lines": [p1, q2, multi[2]["token"]],
         "complete": [],
         "reason": "Parts 1 and 3 of message A with part 2 of message B (same n): every line opens, "
                   "but ids differ, so no complete message may be assembled."},
        {"id": "two-messages-interleaved", "keyring": ["main"],
         "lines": [p1, other_msg[0]["token"], p2, other_msg[1]["token"], multi[2]["token"], other_msg[2]["token"]],
         "complete": ["abcdefghij" * 40, "klmnopqrst" * 40],
         "reason": "Interleaved parts of two messages regroup by message id."},
        {"id": "duplicate-part-ignored", "keyring": ["main"], "lines": [p1, p1, p2, multi[2]["token"]],
         "complete": ["abcdefghij" * 40], "reason": "A replayed part is ignored, not joined twice."},
        {"id": "missing-part", "keyring": ["main"], "lines": [p1, multi[2]["token"]], "complete": [],
         "reason": "Part 2/3 missing: nothing is assembled."},
    ]

    return {
        "format": "sigil-test-vectors",
        "format_version": 1,
        "WARNING": WARNING,
        "suite": "S2C circle messages",
        "protocol": sigil.VERSION2,
        "aad_prefix": sigil.PROTOCOL2,
        "generator": "tools/make_vectors.py --suite s2c (records real sigil.seal_circle_s2 output; random nonces/ids)",
        "lexicon_v2_sha256": sigil.lexicon_hash(),
        "kdf": {
            "alg": "PBKDF2-HMAC-SHA256",
            "iterations": sigil.PBKDF2_ITERS,
            "length": 32,
            "salt": "SHA-256(UTF-8('SIGIL.v1.circle.salt.' + name))[0:16]  (unchanged from S1)",
        },
        "seal": {
            "cipher": "AES-256-GCM",
            "nonce_len": sigil.NONCE_LEN,
            "tag_len": sigil.TAG_LEN,
            "header": "flags(1) [part(1) = (i-1)<<4 | (n-1), mid(6)] ; flags: Z=0x01 J=0x02 M=0x04 S=0x08, "
                      "0xF0 reserved; part+mid present iff M (n>1)",
            "aad": "header || UTF-8('SIGIL.v2.C.' + name)",
            "plaintext": "[len(1) UTF-8 sender, iff S, part 1 only] || body (codebook v2 iff Z, else UTF-8)",
            "blob": "base64url_nopad(header || nonce || ciphertext || tag)",
            "token": "S2C.<slug>.<blob>",
            "rejoin": "concat over i of text_i + (' ' if J_i else '')",
        },
        "fields": {
            "positive[].parts[].payload_hex": "exact bytes that went into AES-GCM (sender field + body)",
            "positive[].parts[].aad_hex": "exact AAD bytes",
            "positive[].joined": "rejoined message (exact; equals plaintext except codebook letter case)",
            "negative[]": "every line must FAIL to open with the given keyring",
            "messages[]": "open all lines, then assemble: exactly these complete messages may result",
        },
        "circles": list(circles.values()),
        "positive": pos,
        "negative": neg,
        "messages": msgs,
    }


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--stdout", action="store_true")
    ap.add_argument("--suite", choices=["s1c", "s2c", "all"], default="all")
    args = ap.parse_args()
    jobs = []
    try:
        if args.suite in ("s1c", "all"):
            jobs.append((OUT, build()))
        if args.suite in ("s2c", "all"):
            jobs.append((OUT2, build_s2()))
    finally:
        _TMP.cleanup()
    for out, data in jobs:
        text = json.dumps(data, indent=2, ensure_ascii=False) + "\n"
        if args.stdout:
            sys.stdout.write(text)
        else:
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(text, encoding="utf-8")
            extra = f", {len(data['messages'])} message-level" if "messages" in data else ""
            print(f"wrote {out.relative_to(ROOT)}: {len(data['positive'])} positive, "
                  f"{len(data['negative'])} negative{extra}")


if __name__ == "__main__":
    main()
