#!/usr/bin/env python3
"""
Generate SIGIL cross-language test vectors:
  tests/vectors/s1c.json  S1C circle messages
  tests/vectors/s2c.json  S2C circle messages (S2 frame header, message id, sender)
  tests/vectors/s2k.json  S2K signet messages (P-256 ECDH), public test signets
  tests/vectors/s2s.json  S2S signed circle messages (Ed25519), public test signets

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

S2K and S2S vectors use public TEST-ONLY signets whose private keys are
derived from public labels ("sigil-public-test-signet-<name>-...-DO-NOT-USE").
They are published on purpose, like RFC test vectors, and are not keys.
S2E is covered by round-trip tests and the live Python<->JS interop test.
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
OUT_K = ROOT / "tests" / "vectors" / "s2k.json"
OUT_S = ROOT / "tests" / "vectors" / "s2s.json"

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


# ---------------------------------------------------------------------------
# Test signets (S2K and S2S). PUBLIC TEST-ONLY KEY MATERIAL, derived from a
# public label so anyone can re-derive them. They are NOT keys.
# ---------------------------------------------------------------------------

from cryptography.hazmat.primitives import serialization as _ser  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec as _ec, ed25519 as _ed  # noqa: E402

P256_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
SIGNET_WARNING = (
    "PUBLIC TEST-ONLY KEY MATERIAL. These signet private keys (P-256 and Ed25519) are derived from public "
    "labels ('sigil-public-test-signet-<name>-...-DO-NOT-USE') and published on purpose for cross-implementation "
    "testing. They are NOT keys. Never use them for real messages. Circle passphrases likewise."
)
TEST_SIGNET_NAMES = {"alice": "Alice", "bob": "Bob", "carol": "Carol", "mallory": "Mallory"}


def _b64u_int(n: int) -> str:
    return sigil.b64e(n.to_bytes(32, "big"))


def test_signet(sid: str) -> dict:
    label = f"sigil-public-test-signet-{sid}-DO-NOT-USE"
    d = int.from_bytes(hashlib.sha256((label + "-p256").encode()).digest(), "big") % (P256_ORDER - 1) + 1
    sk = _ec.derive_private_key(d, _ec.SECP256R1())
    seed = hashlib.sha256((label + "-ed25519").encode()).digest()
    ssk = _ed.Ed25519PrivateKey.from_private_bytes(seed)
    rec = sigil.signet_record(TEST_SIGNET_NAMES[sid], sk, ssk)
    rec["created"] = "2026-09-27T00:00:00Z"
    nums = sk.public_key().public_numbers()
    spk = sigil.b64d(rec["sign_pk"])
    return {
        "id": sid,
        "label": label,
        "record": rec,  # exactly what `sigil signet new` writes to signet-*.json (fixed created date)
        "name": rec["name"],
        "short": rec["short"],
        "pk": rec["pk"],
        "fingerprint": sigil.fingerprint(sigil.b64d(rec["pk"])),
        "sk_hex": d.to_bytes(32, "big").hex(),
        "jwk": {"kty": "EC", "crv": "P-256", "x": _b64u_int(nums.x), "y": _b64u_int(nums.y),
                "d": _b64u_int(d)},
        "sign_pk": rec["sign_pk"],
        "sign_short": rec["sign_short"],
        "sign_fingerprint": sigil.fingerprint(spk),
        "sign_keyid_hex": sigil.s2s_keyid(spk).hex(),
        "sign_seed_hex": seed.hex(),
        "sign_jwk": {"kty": "OKP", "crv": "Ed25519", "x": rec["sign_pk"], "d": sigil.b64e(seed)},
        "announcement": sigil.announce_signet(rec),
    }


def use_signets(signets: dict, own: list[str], contacts: list[str], circles: dict = None,
                circle_ids: list[str] = ()) -> None:
    """Temporary keyring = exactly these own signets, contacts (with signing keys) and circles."""
    home = Path(_TMP.name)
    for pat in ("signet-*.json", "contacts.json", "circle-*.json"):
        for f in home.glob(pat):
            f.unlink()
    for sid in own:
        sigil.save_json(sigil.signet_path(signets[sid]["name"]), signets[sid]["record"])
    for sid in contacts:
        s = signets[sid]
        sigil.remember_contact(s["name"], s["pk"], s["name"], s["sign_pk"])
    for cid in circle_ids:
        c = circles[cid]
        sigil.circle_create(c["name"], c["passphrase"], note="public test vector - not a key")


# ------------------------------------------------------------------- S2K

def s2k_direction(signets: dict, frm: str, to: str) -> dict:
    a, b = signets[frm], signets[to]
    sk = sigil._sk_from_pem(a["record"]["sk_pem"])
    pk = sigil._pk_from_b64(b["pk"])
    ctx = sigil.s2_context("K", a["short"], b["short"])
    info = ctx + sigil.b64d(a["pk"]) + sigil.b64d(b["pk"])
    shared = sk.exchange(_ec.ECDH(), pk)
    return {"from": frm, "to": to, "ctx": ctx.decode(), "ecdh_x_hex": shared.hex(), "info_hex": info.hex(),
            "key_hex": sigil.ecdh_key(sk, pk, info).hex()}


def s2k_positive(vid, signets, frm, to, plaintext, *, compact=False, max_line=256, sender="", note="",
                 opener=None):
    opener = opener or {"own": [to], "contacts": [frm]}
    use_signets(signets, [frm], [to])
    lines = sigil.seal_to_signet_s2(signets[frm]["record"], sigil.find_contact(signets[to]["name"]), plaintext,
                                    max_line=max_line, compact=compact, sender=sender)
    d = s2k_direction(signets, frm, to)
    key = bytes.fromhex(d["key_hex"])
    ctx = d["ctx"].encode()
    use_signets(signets, opener["own"], opener["contacts"])
    parts = []
    for tok in lines:
        fr = sigil.s2_parse_frame(sigil.b64d(tok.rsplit(".", 1)[1]))
        aad = fr["header"] + ctx
        payload = AESGCM(key).decrypt(fr["nonce"], fr["ct"], aad)
        got = sigil.open_line(tok)
        parts.append({"token": tok, "index": fr["index"], "total": fr["total"], "flags": fr["flags"],
                      "codebook": bool(fr["flags"] & sigil.S2_Z), "join": bool(fr["flags"] & sigil.S2_J),
                      "sender": got["sender"], "from": got["from"], "header_hex": fr["header"].hex(),
                      "mid_hex": fr["mid"].hex(), "nonce_hex": fr["nonce"].hex(), "aad_hex": aad.hex(),
                      "payload_hex": payload.hex(), "plaintext": got["plaintext"]})
    joined = sigil.stitch_parts([(p["plaintext"], p["codebook"], p["join"]) for p in parts])
    return {"id": vid, "from": frm, "to": to, "opener": opener,
            "seal": {"compact": compact, "max_line": max_line, "sender": sender},
            "plaintext": plaintext, "lines": lines, "parts": parts, "joined": joined,
            "joined_equals_plaintext": joined == plaintext, "note": note}


def build_s2k() -> dict:
    signets = {sid: test_signet(sid) for sid in TEST_SIGNET_NAMES}
    use_signets(signets, ["alice"], ["bob"])
    lo, hi = 0, 400
    while lo < hi:
        mid = (lo + hi + 1) // 2
        n = len(sigil.seal_to_signet_s2(signets["alice"]["record"], sigil.find_contact("Bob"), "a" * mid))
        lo, hi = (mid, hi) if n == 1 else (lo, mid - 1)
    single_max = lo
    pos = [
        s2k_positive("plain-short", signets, "alice", "bob", "portal at 1847 12 -320",
                     note="Alice -> Bob, raw, one line."),
        s2k_positive("reverse-direction", signets, "bob", "alice", "portal at 1847 12 -320",
                     note="Bob -> Alice uses a different key (ctx and info order are directional)."),
        s2k_positive("plain-empty", signets, "alice", "bob", "", note="Empty plaintext."),
        s2k_positive("plain-single-line-max", signets, "alice", "bob", "a" * single_max,
                     note=f"Longest ASCII run ({single_max} B) in one S2K line at max_line=256."),
        s2k_positive("plain-first-split", signets, "alice", "bob", "a" * (single_max + 1),
                     note="One byte more: two parts with part byte + message id."),
        s2k_positive("whisper-budget", signets, "alice", "bob", "b" * 136, max_line=234,
                     note="136 B = one S2K line in a /msg whisper budget (max_line=234)."),
        s2k_positive("plain-multipart-3", signets, "alice", "bob", "abcdefghij" * 40, note="Three raw parts."),
        s2k_positive("unicode-mixed", signets, "alice", "bob", "Grüße 🧭 北 -320 / ñ / שלום / e\u0301",
                     note="Multi-byte UTF-8."),
        s2k_positive("compact-z", signets, "alice", "bob", "nether roof stash at 0 128 0", compact=True,
                     note="Codebook v2 body."),
        s2k_positive("sender-field", signets, "alice", "bob", "who sent this", sender="Alice",
                     note="Sealed sender name. The authenticated identity is the route's from key (Alice), "
                          "not this field."),
        s2k_positive("sender-claim-not-identity", signets, "mallory", "bob", "I am Alice", sender="Alice",
                     opener={"own": ["bob"], "contacts": ["alice", "mallory"]},
                     note="Mallory (a known contact) claims sender 'Alice'. It opens, but 'from' is Mallory: "
                          "only the key proves the sender."),
    ]
    short = pos[0]["lines"][0]
    multi = pos[6]["lines"]
    a, b, m, c = (signets[x]["short"] for x in ("alice", "bob", "mallory", "carol"))
    # Mallory seals to Bob with her own key but writes Alice's short id as the sender.
    use_signets(signets, ["mallory"], ["bob"])
    mal = sigil.seal_to_signet_s2(signets["mallory"]["record"], sigil.find_contact("Bob"), "trust me, I am Alice")[0]
    forged_route = mal.replace(f"S2K.{b}.{m}.", f"S2K.{b}.{a}.", 1)
    use_signets(signets, ["alice"], ["carol"])
    to_carol = sigil.seal_to_signet_s2(signets["alice"]["record"], sigil.find_contact("Carol"), "for carol only")[0]
    blob_len = len(sigil.b64d(short.rsplit(".", 1)[1]))
    std = {"own": ["bob"], "contacts": ["alice"]}
    neg = [
        {"id": "tampered-tag", "line": s2_edit(short, lambda d: d.__setitem__(blob_len - 1, d[blob_len - 1] ^ 1)),
         "opener": std, "reason": "Last tag byte flipped."},
        {"id": "tampered-header", "line": s2_edit(short, lambda d: d.__setitem__(0, d[0] ^ sigil.S2_S)),
         "opener": std, "reason": "S flag set: header is in the AAD."},
        {"id": "impersonation-route-relabelled", "line": forged_route, "opener": std,
         "reason": "Mallory seals with her own key and writes Alice's short id as sender. Bob derives the key "
                   "from Alice's public key, so the tag fails."},
        {"id": "impersonation-unknown-sender", "line": mal, "opener": std,
         "reason": "Mallory's own honest token: Bob has no contact with her short id."},
        {"id": "reflection", "line": short.replace(f"S2K.{b}.{a}.", f"S2K.{a}.{b}.", 1),
         "opener": {"own": ["alice"], "contacts": ["bob"]},
         "reason": "Alice->Bob token reflected back to Alice as if Bob sent it: the direction key differs."},
        {"id": "wrong-recipient", "line": to_carol.replace(f"S2K.{c}.", f"S2K.{b}.", 1), "opener": std,
         "reason": "Alice->Carol token relabelled to Bob."},
        {"id": "not-for-me", "line": to_carol, "opener": std,
         "reason": "Addressed to Carol's short id; Bob holds no such signet."},
        {"id": "fragment-relabelled", "line": s2_edit(multi[0], lambda d: d.__setitem__(1, (1 << 4) | 2)),
         "opener": std, "reason": "Part 1/3 relabelled 2/3."},
        {"id": "truncated", "line": f"S2K.{b}.{a}.{sigil.b64e(bytes(20))}", "opener": std,
         "reason": "Frame shorter than header + nonce + tag."},
    ]
    return {
        "format": "sigil-test-vectors", "format_version": 1, "WARNING": SIGNET_WARNING,
        "suite": "S2K signet messages (static-static P-256 ECDH)", "protocol": sigil.VERSION2,
        "aad_prefix": sigil.PROTOCOL2, "sigil_version": sigil.__version__,
        "generator": "tools/make_vectors.py --suite s2k (records real sigil.seal_to_signet_s2 output; "
                     "random nonces/ids; deterministic public test keys)",
        "lexicon_v2_sha256": sigil.lexicon_hash(),
        "key": {
            "ctx": "UTF-8('SIGIL.v2.K.' + from_short + '.' + to_short)",
            "ikm": "ECDH-P256(from_sk, to_pk): 32-byte x coordinate",
            "hkdf": "HKDF-SHA256(ikm, salt=none (32 zero bytes), info = ctx || from_pk33 || to_pk33, L=32)",
            "aad": "header || ctx", "token": "S2K.<to_short>.<from_short>.<blob>",
            "short": "b64url(SHA-256(pk33))[0:4].lower()", "fingerprint": "b64url(SHA-256(pk33)) (43 chars)",
        },
        "fields": {
            "signets[]": "public test signets; record = sigil keyring JSON; jwk/sk_hex = same P-256 key",
            "directions[]": "ctx, ECDH x, HKDF info and resulting AES key per direction",
            "positive[].opener": "which signets the opener owns and which contacts it holds",
            "positive[].parts[].from": "contact name sigil reports as the proven sender",
            "negative[]": "every line must FAIL to open with the given opener keyring",
        },
        "signets": list(signets.values()),
        "directions": [s2k_direction(signets, "alice", "bob"), s2k_direction(signets, "bob", "alice"),
                       s2k_direction(signets, "mallory", "bob")],
        "positive": pos, "negative": neg,
    }


# ------------------------------------------------------------------- S2S

def s2s_positive(vid, circles, signets, signer, plaintext, *, compact=False, max_line=256, sender="",
                 note="", verifier_keys=None, expect_signer=None):
    circle = circles["main"]
    verifier_keys = verifier_keys or ["alice", "bob"]
    lines = sigil.seal_circle_signed_s2(_record_for(circle), signets[signer]["record"], plaintext,
                                        sender=sender, max_line=max_line, compact=compact)
    use_signets(signets, [], verifier_keys, circles, ["main"])
    key = bytes.fromhex(circle["key_hex"])
    ctx = sigil.s2_context("S", circle["name"])
    opened = [sigil.open_line(t) for t in lines]
    parts = []
    for tok, r in zip(lines, opened):
        fr = sigil.s2_parse_frame(sigil.b64d(tok.rsplit(".", 1)[1]))
        aad = fr["header"] + ctx
        full = AESGCM(key).decrypt(fr["nonce"], fr["ct"], aad)
        parts.append({"token": tok, "index": fr["index"], "total": fr["total"], "flags": fr["flags"],
                      "codebook": bool(fr["flags"] & sigil.S2_Z), "join": bool(fr["flags"] & sigil.S2_J),
                      "sender": r["sender"], "header_hex": fr["header"].hex(), "mid_hex": fr["mid"].hex(),
                      "nonce_hex": fr["nonce"].hex(), "aad_hex": aad.hex(), "payload_hex": r["payload_hex"],
                      "sealed_plaintext_hex": full.hex(), "plaintext": r["plaintext"]})
    msgs = sigil.assemble_messages(opened)
    assert len(msgs) == 1 and msgs[0]["verified"], msgs
    tbs = sigil.s2s_signed_bytes(ctx, bytes.fromhex(opened[-1]["keyid"]),
                                 [(bytes.fromhex(p["header_hex"]), bytes.fromhex(p["payload_hex"])) for p in parts])
    return {"id": vid, "circle": "main", "signer": signer, "verifier_keys": verifier_keys,
            "seal": {"compact": compact, "max_line": max_line, "sender": sender},
            "plaintext": plaintext, "lines": lines, "parts": parts,
            "keyid_hex": opened[-1]["keyid"], "sig_hex": opened[-1]["sig_hex"], "signed_bytes_hex": tbs.hex(),
            "joined": msgs[0]["text"], "expect": {"verified": True, "signer": signets[expect_signer or signer]["name"]},
            "note": note}


def _reseal_s2s(circle: dict, token: str, fn) -> str:
    """What a circle member (who holds the circle key but not the signer's key) can do: decrypt, edit, re-seal."""
    key = bytes.fromhex(circle["key_hex"])
    ctx = sigil.s2_context("S", circle["name"])
    head, blob = token.rsplit(".", 1)
    fr = sigil.s2_parse_frame(sigil.b64d(blob))
    pt = bytearray(AESGCM(key).decrypt(fr["nonce"], fr["ct"], fr["header"] + ctx))
    header = bytearray(fr["header"])
    fn(header, pt)
    header, pt = bytes(header), bytes(pt)
    return f"{head}.{sigil.b64e(header + fr['nonce'] + AESGCM(key).encrypt(fr['nonce'], pt, header + ctx))}"


def build_s2s() -> dict:
    circles = {cid: circle_record(cid) for cid in CIRCLES}
    signets = {sid: test_signet(sid) for sid in TEST_SIGNET_NAMES}
    main = circles["main"]
    rec = _record_for(main)
    alice = signets["alice"]["record"]

    def single_max(max_line):
        lo, hi = 0, 400
        while lo < hi:
            mid = (lo + hi + 1) // 2
            n = len(sigil.seal_circle_signed_s2(rec, alice, "a" * mid, max_line=max_line))
            lo, hi = (mid, hi) if n == 1 else (lo, mid - 1)
        return lo
    smax, smax_w = single_max(256), single_max(234)
    # Longest 2-part raw message whose trailer still fits in part 2 (next byte adds a signature-only part).
    room = sigil.s2_payload_room(256, 9, True)
    two_max = 2 * room - sigil.S2S_TRAILER
    pos = [
        s2s_positive("signed-short", circles, signets, "alice", "portal at 1847 12 -320",
                     note="One line: [body] || keyid(8) || Ed25519 sig(64) inside the ciphertext."),
        s2s_positive("signed-empty", circles, signets, "alice", "", note="Empty body still signed."),
        s2s_positive("signed-single-line-max", circles, signets, "alice", "a" * smax,
                     note=f"Longest ASCII body ({smax} B) that fits one S2S line with its trailer at max_line=256."),
        s2s_positive("signed-whisper-single-max", circles, signets, "alice", "w" * smax_w, max_line=234,
                     note=f"Whisper budget (max_line=234): {smax_w} B in one signed line."),
        s2s_positive("signature-only-part", circles, signets, "alice", "a" * (smax + 1),
                     note="One byte more than one line: part 1 carries the text, part 2 only the trailer."),
        s2s_positive("trailer-in-last-part", circles, signets, "alice", "c" * two_max,
                     note=f"{two_max} B: two parts, the trailer fills the rest of part 2."),
        s2s_positive("trailer-spills", circles, signets, "alice", "c" * (two_max + 1),
                     note="One byte more: a third, signature-only part."),
        s2s_positive("signed-multipart-3", circles, signets, "bob", "abcdefghij" * 40,
                     note="Several parts; the signature covers every header and part plaintext."),
        s2s_positive("signed-unicode", circles, signets, "alice", "Grüße 🧭 北 -320 / ñ / שלום / e\u0301",
                     note="Multi-byte UTF-8."),
        s2s_positive("signed-compact", circles, signets, "alice", (
                     ("nether roof stash at 0 128 0 bring the diamond pickaxe and the eye of ender "
                      "meet at the ruined portal after dragon ") * 3).strip(), compact=True,
                     note="Codebook parts: the signature covers the packed bytes."),
        s2s_positive("signed-sender", circles, signets, "alice", "anon or not", sender="Alice",
                     note="Sender field in part 1, trailer in the last part."),
        s2s_positive("sender-claim-vs-signer", circles, signets, "mallory", "I am Alice", sender="Alice",
                     verifier_keys=["alice", "mallory"],
                     note="Mallory's key is known and she claims 'Alice': the message verifies, and the signer "
                          "is Mallory. Trust the signer, not the sender field."),
    ]
    one = pos[0]["lines"][0]
    multi = pos[7]["lines"]
    sponly = pos[4]["lines"]
    other = sigil.seal_circle_signed_s2(rec, signets["bob"]["record"], "klmnopqrst" * 40)
    assert len(other) == len(multi)
    mal_claims = sigil.seal_circle_signed_s2(rec, signets["mallory"]["record"], "I am Alice", sender="Alice")[0]
    a_keyid = bytes.fromhex(signets["alice"]["sign_keyid_hex"])

    def flip_sig(h, pt):
        pt[-1] ^= 1

    def flip_body(h, pt):
        pt[0] ^= 1

    def put_alice_keyid(h, pt):
        pt[-sigil.S2S_TRAILER:-sigil.S2S_SIG_LEN] = a_keyid

    def put_mid(mid):
        def f(h, pt):
            h[2:2 + sigil.S2_MID_LEN] = mid
        return f

    mid_a = sigil.s2_parse_frame(sigil.b64d(multi[0].rsplit(".", 1)[1]))["mid"]
    std = ["alice", "bob"]
    # Circle member drops the signature part of a 2-part message and relabels part 1 as a single-line frame.
    def as_single(h, pt):
        del h[1:]
        h[0] &= ~sigil.S2_M & 0xFF
    dropped = _reseal_s2s(main, sponly[0], as_single)
    msgs = [
        {"id": "circle-member-flips-signature", "verifier_keys": std, "lines": [_reseal_s2s(main, one, flip_sig)],
         "expect": {"verified": False, "error": "bad-signature"},
         "reason": "A circle member re-seals the part with one signature bit flipped."},
        {"id": "circle-member-edits-body", "verifier_keys": std, "lines": [_reseal_s2s(main, one, flip_body)],
         "expect": {"verified": False, "error": "bad-signature"},
         "reason": "A circle member changes the text and re-seals it; the signature no longer matches."},
        {"id": "impersonation-unknown-key", "verifier_keys": std, "lines": [mal_claims],
         "expect": {"verified": False, "error": "unknown-signer"},
         "reason": "Mallory (not a known key) signs and claims sender 'Alice': refused, unknown key id."},
        {"id": "impersonation-keyid-swapped", "verifier_keys": std,
         "lines": [_reseal_s2s(main, mal_claims, put_alice_keyid)],
         "expect": {"verified": False, "error": "bad-signature"},
         "reason": "Mallory writes Alice's key id next to her own signature: Alice's key does not verify it."},
        {"id": "splice-other-message-part", "verifier_keys": std,
         "lines": [multi[0], _reseal_s2s(main, other[1], put_mid(mid_a))] + multi[2:],
         "expect": {"verified": False, "error": "bad-signature"},
         "reason": "Part 2 of Bob's other message, re-sealed by a circle member with this message's id: "
                   "the message assembles, but the signature covers the original part 2."},
        {"id": "splice-without-rewrite", "verifier_keys": std, "lines": [multi[0], other[1]] + multi[2:],
         "expect": {"verified": False, "error": "incomplete"},
         "reason": "Part 2 of another message with a different id: never assembled."},
        {"id": "signature-part-dropped", "verifier_keys": std, "lines": [dropped],
         "expect": {"verified": False, "error": "unknown-signer"},
         "reason": "Signature-only part dropped by a circle member, part 1 relabelled as a single-line frame: its "
                   "last 72 body bytes are read as keyid || sig, match no known key id, and nothing is shown."},
        {"id": "missing-part", "verifier_keys": std, "lines": [multi[0], multi[-1]],
         "expect": {"verified": False, "error": "incomplete"}, "reason": "A part is missing: nothing is verified."},
        {"id": "no-verifier-keys", "verifier_keys": [], "lines": [one],
         "expect": {"verified": False, "error": "unknown-signer"},
         "reason": "The opener holds the circle but no signing keys: the message is not attributed or shown."},
        {"id": "duplicate-part-ignored", "verifier_keys": std, "lines": [multi[0], multi[0]] + multi[1:],
         "expect": {"verified": True, "signer": "Bob"}, "reason": "A replayed part is ignored."},
    ]
    blob_len = len(sigil.b64d(one.rsplit(".", 1)[1]))
    slug = main["slug"]
    wrongpass = sigil.seal_circle_signed_s2(_record_for(circles["wrongpass"]), alice, "wrong circle key")[0]
    neg = [
        {"id": "tampered-tag", "line": s2_edit(one, lambda d: d.__setitem__(blob_len - 1, d[blob_len - 1] ^ 1)),
         "reason": "GCM tag flipped (outsider)."},
        {"id": "s2s-presented-as-s2c", "line": one.replace("S2S.", "S2C.", 1),
         "reason": "Different ctx ('SIGIL.v2.C.' vs 'SIGIL.v2.S.'): a signed token never opens as a circle token."},
        {"id": "s2c-presented-as-s2s",
         "line": sigil.seal_circle_s2(rec, "unsigned circle message")[0].replace("S2C.", "S2S.", 1),
         "reason": "An unsigned S2C token relabelled S2S does not open."},
        {"id": "wrong-passphrase", "line": wrongpass, "reason": "Signed under another circle key."},
        {"id": "short-trailer", "line": _reseal_s2s(main, one, lambda h, pt: pt.__delitem__(slice(0, len(pt)))),
         "reason": "Last part with fewer than 72 plaintext bytes: rejected on open."},
        {"id": "slug-unknown", "line": one.replace(f"S2S.{slug}.", "S2S.qqqq.", 1), "reason": "No circle."},
    ]
    return {
        "format": "sigil-test-vectors", "format_version": 1, "WARNING": SIGNET_WARNING,
        "suite": "S2S signed circle messages (Ed25519)", "protocol": sigil.VERSION2, "aad_prefix": sigil.PROTOCOL2,
        "sigil_version": sigil.__version__,
        "generator": "tools/make_vectors.py --suite s2s (records real sigil.seal_circle_signed_s2 output; random "
                     "nonces/ids; Ed25519 signatures are deterministic)",
        "lexicon_v2_sha256": sigil.lexicon_hash(),
        "seal": {
            "token": "S2S.<slug>.<blob>", "key": "circle key (as S2C)", "ctx": "UTF-8('SIGIL.v2.S.' + name)",
            "aad": "header || ctx",
            "plaintext": "as S2C; the LAST part additionally ends with keyid(8) || sig(64)",
            "keyid": "SHA-256(Ed25519 public key)[0:8]",
            "signed_bytes": "'SIGIL.v2.sig' 0x00 || u16(len ctx) ctx || keyid || u8(n) || for each part: "
                            "u8(len header) header || u16(len pt) pt   (pt without the trailer; big-endian)",
            "sig": "Ed25519 (RFC 8032, pure) over signed_bytes",
            "sealer_policy": "trailer goes into the last text part when it fits, else into an extra part with an "
                             "empty raw body",
        },
        "fields": {
            "signets[]": "public test signets (see s2k.json); sign_seed_hex / sign_jwk = Ed25519 private key",
            "positive[].verifier_keys": "signing public keys the opener holds",
            "positive[].parts[].payload_hex": "part plaintext without the trailer (what the signature covers)",
            "positive[].parts[].sealed_plaintext_hex": "exact bytes that went into AES-GCM (with trailer)",
            "positive[].signed_bytes_hex / sig_hex": "exact Ed25519 input and signature (deterministic)",
            "messages[]": "open + assemble + verify: expect.verified and expect.error "
                          "(bad-signature | unknown-signer | incomplete)",
            "negative[]": "every line must FAIL to open",
        },
        "circles": list(circles.values()),
        "signets": list(signets.values()),
        "positive": pos, "negative": neg, "messages": msgs,
    }


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--stdout", action="store_true")
    ap.add_argument("--suite", choices=["s1c", "s2c", "s2k", "s2s", "all"], default="all")
    args = ap.parse_args()
    jobs = []
    try:
        if args.suite in ("s1c", "all"):
            jobs.append((OUT, build()))
        if args.suite in ("s2c", "all"):
            jobs.append((OUT2, build_s2()))
        if args.suite in ("s2k", "all"):
            jobs.append((OUT_K, build_s2k()))
        if args.suite in ("s2s", "all"):
            jobs.append((OUT_S, build_s2s()))
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
