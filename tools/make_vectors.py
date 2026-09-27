#!/usr/bin/env python3
"""
Generate SIGIL S1C cross-language test vectors -> tests/vectors/s1c.json

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
  python3 tools/make_vectors.py            # rewrite tests/vectors/s1c.json
  python3 tools/make_vectors.py --stdout   # print instead
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


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--stdout", action="store_true")
    args = ap.parse_args()
    try:
        data = build()
    finally:
        _TMP.cleanup()
    text = json.dumps(data, indent=2, ensure_ascii=False) + "\n"
    if args.stdout:
        sys.stdout.write(text)
    else:
        OUT.parent.mkdir(parents=True, exist_ok=True)
        OUT.write_text(text, encoding="utf-8")
        print(f"wrote {OUT.relative_to(ROOT)}: {len(data['positive'])} positive, {len(data['negative'])} negative")


if __name__ == "__main__":
    main()
