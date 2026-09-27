#!/usr/bin/env python3
"""
SIGIL — Sealed In-the-open Glyphs for Informal Links
A public-facing encryption system for open chats and whispers
(Minecraft, Discord, IRC, SMS, carrier pigeon).

Protocol versions: S2 (default for sealing) and S1 (still opened; seal
with --wire S1 for old peers). S2S (signed circle, Ed25519) since 0.5.0. This file is both the reference
implementation and the CLI.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import sys
import textwrap
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

import codebook

__version__ = "0.5.0"

# S1 constants. PROTOCOL also names the circle-key salt, which S2 reuses
# unchanged (same keys, same keyrings). S2 constants live in the S2 section.
VERSION = "S1"
PROTOCOL = "SIGIL.v1"
PBKDF2_ITERS = 210_000
NONCE_LEN = 12
TAG_LEN = 16  # AES-GCM tag, appended by AESGCM.encrypt
P256_COMPRESSED_LEN = 33
ED25519_PK_LEN = 32

# Default keyring lives next to this script unless SIGIL_HOME is set.
HOME = Path(os.environ.get("SIGIL_HOME", Path(__file__).resolve().parent / "keys"))


# ---------------------------------------------------------------------------
# Encoding: unpadded URL-safe base64. Alphanumeric + - _ only.
# Compact enough for Minecraft's 256-char send limit.
# ---------------------------------------------------------------------------

def b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def b64d(text: str) -> bytes:
    pad = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + pad)


def short_id(data: bytes, n: int = 4) -> str:
    """Stable public fingerprint, 4 chars."""
    return b64e(hashlib.sha256(data).digest())[:n].lower()


def fingerprint(raw_public_key: bytes) -> str:
    """Full public-key fingerprint: b64url(SHA-256(raw key)), 43 chars. short_id is its first 4, lowercased."""
    return b64e(hashlib.sha256(raw_public_key).digest())


def slugify(name: str, n: int = 4) -> str:
    """Public, non-secret label. Collisions are ok — GCM tags disambiguate."""
    cleaned = "".join(c for c in name.lower() if c.isalnum()) or "circ"
    return (cleaned + ("x" * n))[:n]


# ---------------------------------------------------------------------------
# Keyring
# ---------------------------------------------------------------------------

def _ensure_home() -> Path:
    HOME.mkdir(parents=True, exist_ok=True)
    return HOME


def _atomic_write(path: Path, text: str) -> None:
    _ensure_home()
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    tmp.replace(path)


def circle_path(name: str) -> Path:
    return _ensure_home() / f"circle-{slugify(name, 12)}.json"


def signet_path(name: str) -> Path:
    return _ensure_home() / f"signet-{slugify(name, 12)}.json"


def contacts_path() -> Path:
    return _ensure_home() / "contacts.json"


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def save_json(path: Path, obj: dict) -> None:
    _atomic_write(path, json.dumps(obj, indent=2, sort_keys=True))
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def speak_fingerprint(fp: str) -> str:
    """Two public codebook words you can read aloud to confirm a fingerprint."""
    words = []
    lex = Path(__file__).resolve().parent / "lexicon_v2.txt"
    if lex.exists():
        for w in lex.read_text(encoding="ascii").splitlines():
            if w.isalpha() and 3 <= len(w) <= 10 and not w.startswith("pad"):
                words.append(w)
            if len(words) >= 256:
                break
    if len(words) < 256:
        words = [f"word{i:03d}" for i in range(256)]
    digest = hashlib.sha256(f"{PROTOCOL}.speak.{fp}".encode("utf-8")).digest()
    return f"{words[digest[0]]} {words[digest[1]]}"


def dice_phrase(n: int = 5) -> str:
    pool = []
    lex = Path(__file__).resolve().parent / "lexicon_v2.txt"
    if lex.exists():
        for w in lex.read_text(encoding="ascii").splitlines():
            if w.isalpha() and 4 <= len(w) <= 10 and not w.startswith("pad"):
                pool.append(w)
    if len(pool) < 64:
        raise SystemExit("lexicon_v2.txt missing; cannot dice a passphrase.")
    out = []
    for _ in range(n):
        idx = int.from_bytes(os.urandom(2), "big") % len(pool)
        out.append(pool[idx])
    return " ".join(out)


def lexicon_hash() -> str:
    path = Path(__file__).resolve().parent / "lexicon_v2.txt"
    if not path.exists():
        return "missing"
    return hashlib.sha256(path.read_bytes()).hexdigest()


def append_transcript(meta: str, plaintext: str) -> None:
    log = _ensure_home() / "transcript.log"
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    line = plaintext.replace("\n", " / ")
    with log.open("a", encoding="utf-8") as fh:
        fh.write(f"{stamp} {meta} {line}\n")
    try:
        os.chmod(log, 0o600)
    except OSError:
        pass


def wrap_backup(passphrase: str) -> str:
    blob = {
        "circles": list_circles(),
        "signets": list_signets(),
        "contacts": load_contacts(),
    }
    raw = json.dumps(blob).encode("utf-8")
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=PBKDF2_ITERS)
    key = kdf.derive(passphrase.encode("utf-8"))
    nonce = os.urandom(NONCE_LEN)
    ct = AESGCM(key).encrypt(nonce, raw, f"{PROTOCOL}.backup".encode("utf-8"))
    return "S1B." + b64e(salt + nonce + ct)


def unwrap_backup(token: str, passphrase: str) -> dict:
    if not token.strip().startswith("S1B."):
        raise SystemExit("Not a SIGIL backup token (expected S1B.)")
    data = b64d(token.strip().split(".", 1)[1])
    salt, nonce, ct = data[:16], data[16:28], data[28:]
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=PBKDF2_ITERS)
    key = kdf.derive(passphrase.encode("utf-8"))
    raw = AESGCM(key).decrypt(nonce, ct, f"{PROTOCOL}.backup".encode("utf-8"))
    return json.loads(raw.decode("utf-8"))


# ---------------------------------------------------------------------------
# Circle keys (shared passphrase — the usual "our group on this server" mode)
# ---------------------------------------------------------------------------

def derive_circle_key(circle_name: str, passphrase: str) -> bytes:
    """
    Deterministic stretching so both sides get the same 256-bit key from
    the same name + passphrase. Salt is bound to the circle name so two
    circles that reuse a passphrase still diverge.
    """
    salt = hashlib.sha256(f"{PROTOCOL}.circle.salt.{circle_name}".encode("utf-8")).digest()[:16]
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERS,
    )
    return kdf.derive(passphrase.encode("utf-8"))


def circle_create(name: str, passphrase: str, note: str = "") -> dict:
    key = derive_circle_key(name, passphrase)
    rec = {
        "kind": "circle",
        "name": name,
        "slug": slugify(name),
        "fingerprint": short_id(key),
        "kdf": f"PBKDF2-HMAC-SHA256/{PBKDF2_ITERS}",
        "created": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "note": note,
        # We store the passphrase so the CLI can seal/open later.
        # Protect the keyring like you would a password file.
        "passphrase": passphrase,
    }
    save_json(circle_path(name), rec)
    return rec


def load_circle(name_or_slug: str) -> dict:
    target = name_or_slug.lower()
    matches = []
    for path in _ensure_home().glob("circle-*.json"):
        rec = load_json(path)
        if rec["name"].lower() == target or rec["slug"] == target:
            matches.append(rec)
    if not matches:
        raise SystemExit(f"No circle named '{name_or_slug}'. Create one with: sigil circle new")
    return matches[0]


def list_circles() -> list[dict]:
    return [load_json(p) for p in sorted(_ensure_home().glob("circle-*.json"))]


# ---------------------------------------------------------------------------
# Signets (P-256 identities for directed whispers)
# ---------------------------------------------------------------------------

def _sk_from_pem(pem: str) -> ec.EllipticCurvePrivateKey:
    return serialization.load_pem_private_key(pem.encode("utf-8"), password=None)


def _pk_from_b64(blob: str) -> ec.EllipticCurvePublicKey:
    raw = b64d(blob)
    return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), raw)


def _pk_bytes(pk: ec.EllipticCurvePublicKey) -> bytes:
    return pk.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.CompressedPoint,
    )


def _pem(sk) -> str:
    return sk.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")


def _spk_bytes(pk: ed25519.Ed25519PublicKey) -> bytes:
    return pk.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)


def _sign_fields(sign_sk: ed25519.Ed25519PrivateKey) -> dict:
    """Signet fields for the Ed25519 signing key used by S2S (0.5.0+)."""
    spk = _spk_bytes(sign_sk.public_key())
    return {"sign_alg": "Ed25519", "sign_pk": b64e(spk), "sign_short": short_id(spk), "sign_sk_pem": _pem(sign_sk)}


def signet_record(name: str, sk: ec.EllipticCurvePrivateKey,
                  sign_sk: Optional[ed25519.Ed25519PrivateKey] = None) -> dict:
    """Keyring record for a signet: P-256 (S1K/S2K/S2E) plus an Ed25519 signing key (S2S)."""
    pk = sk.public_key()
    rec = {
        "kind": "signet",
        "name": name,
        "short": short_id(_pk_bytes(pk)),
        "pk": b64e(_pk_bytes(pk)),
        "sk_pem": _pem(sk),
        "curve": "P-256",
        "created": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    if sign_sk is not None:
        rec.update(_sign_fields(sign_sk))
    return rec


def signet_create(name: str) -> dict:
    rec = signet_record(name, ec.generate_private_key(ec.SECP256R1()), ed25519.Ed25519PrivateKey.generate())
    save_json(signet_path(name), rec)
    return rec


def signet_add_signing_key(name_or_short: str) -> dict:
    """Give a pre-0.5 signet an Ed25519 signing key (keeps its P-256 key and short id)."""
    rec = load_signet(name_or_short)
    if rec.get("sign_pk"):
        return rec
    rec.update(_sign_fields(ed25519.Ed25519PrivateKey.generate()))
    save_json(signet_path(rec["name"]), rec)
    return rec


def _sign_sk_from_rec(rec: dict) -> ed25519.Ed25519PrivateKey:
    if not rec.get("sign_sk_pem"):
        raise ValueError(f"Signet '{rec.get('name')}' has no signing key. Run: sigil signet upgrade {rec.get('name')}")
    sk = serialization.load_pem_private_key(rec["sign_sk_pem"].encode("utf-8"), password=None)
    if not isinstance(sk, ed25519.Ed25519PrivateKey):
        raise ValueError("Signet signing key is not Ed25519.")
    if b64e(_spk_bytes(sk.public_key())) != rec.get("sign_pk"):
        raise ValueError("Signet signing key does not match its public key (corrupt record).")
    return sk


def load_signet(name_or_short: str) -> dict:
    target = name_or_short.lower()
    for path in _ensure_home().glob("signet-*.json"):
        rec = load_json(path)
        if rec["name"].lower() == target or rec["short"] == target:
            return rec
    raise SystemExit(f"No local signet '{name_or_short}'. Create one with: sigil signet new")


def list_signets() -> list[dict]:
    return [load_json(p) for p in sorted(_ensure_home().glob("signet-*.json"))]


def load_contacts() -> dict:
    p = contacts_path()
    if not p.exists():
        return {"contacts": {}}
    return load_json(p)


def remember_contact(alias: str, pk_b64: str, name_hint: str = "", spk_b64: str = "") -> dict:
    raw = b64d(pk_b64)
    if len(raw) not in (33, 65):
        raise SystemExit("Contact public key has the wrong length.")
    # Normalize to compressed.
    pk = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), raw)
    compressed = b64e(_pk_bytes(pk))
    book = load_contacts()
    entry = {
        "alias": alias,
        "name_hint": name_hint or alias,
        "pk": compressed,
        "short": short_id(_pk_bytes(pk)),
        "added": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    if spk_b64:
        spk = b64d(spk_b64)
        if len(spk) != ED25519_PK_LEN:
            raise SystemExit("Contact signing key must be a 32-byte Ed25519 public key.")
        ed25519.Ed25519PublicKey.from_public_bytes(spk)
        entry["spk"] = b64e(spk)
        entry["sshort"] = short_id(spk)
    book.setdefault("contacts", {})[alias.lower()] = entry
    # Also index by short id.
    book["contacts"][entry["short"]] = entry
    save_json(contacts_path(), book)
    return entry


def find_contact(alias_or_short: str) -> dict:
    book = load_contacts().get("contacts", {})
    key = alias_or_short.lower()
    if key in book:
        return book[key]
    for entry in book.values():
        if entry["short"] == key or entry["alias"].lower() == key:
            return entry
    raise SystemExit(
        f"Unknown contact '{alias_or_short}'. Import their public signet with: "
        "sigil contact add ALIAS KEY"
    )


# ---------------------------------------------------------------------------
# Seal / open
# ---------------------------------------------------------------------------

def _chunk_plain(text: str, max_payload_chars: int) -> list[str]:
    """
    max_payload_chars is the room left for the encoded ciphertext blob
    inside a 256-char Minecraft line after the header.
    """
    raw = text.encode("utf-8")
    # Each byte becomes ~4/3 chars. Leave slack for header.
    # We split on Unicode codepoints first so we don't cut mid-character
    # after a decode round-trip; then fall back to byte chunks if needed.
    if len(b64e(b"\x00" * NONCE_LEN + raw + b"\x00" * TAG_LEN)) <= max_payload_chars:
        return [text]
    parts = []
    buf = []
    acc = 0
    # Conservative: 1 unicode char ~ 4 encoded chars worst-case (4-byte UTF-8
    # plus GCM expansion). Use a safer byte budget.
    byte_budget = max(24, int(max_payload_chars * 3 / 4) - NONCE_LEN - TAG_LEN - 8)
    current = b""
    for ch in text:
        piece = ch.encode("utf-8")
        if current and len(current) + len(piece) > byte_budget:
            parts.append(current.decode("utf-8"))
            current = piece
        else:
            current += piece
    if current:
        parts.append(current.decode("utf-8"))
    return parts or [""]


def _chunk_compact(text: str, max_payload_bytes: int) -> list[str]:
    """Split text so each compressed part fits in max_payload_bytes."""
    budget = max(8, max_payload_bytes)
    parts: list[str] = []
    rest = text
    while rest:
        lo, hi = 1, len(rest)
        best = 1
        while lo <= hi:
            mid = (lo + hi) // 2
            packed, _ = codebook.maybe_compress(rest[:mid])
            if len(packed) <= budget:
                best = mid
                lo = mid + 1
            else:
                hi = mid - 1
        # Prefer a word boundary so fragments stitch cleanly.
        if best < len(rest):
            snapped = rest[:best].rfind(" ")
            if snapped >= max(8, best // 4):
                best = snapped + 1
        parts.append(rest[:best])
        rest = rest[best:]
    return parts or [""]


def _seal_payload(text: str, compact: bool) -> tuple[bytes, bool]:
    if compact:
        return codebook.maybe_compress(text)
    return text.encode("utf-8"), False


def _open_payload(raw: bytes, compact: bool) -> str:
    if compact:
        return codebook.maybe_expand(raw)
    return raw.decode("utf-8")


def _is_codebook_payload(raw: bytes, compact: bool) -> bool:
    """True when _open_payload(raw, compact) ran the (lossy) codebook expander."""
    return compact and raw[:1] in (codebook.MAGIC, codebook.MAGIC2)


def seal_circle(
    circle: dict,
    plaintext: str,
    sender: str = "",
    max_line: int = 256,
    compact: bool = False,
) -> list[str]:
    key = derive_circle_key(circle["name"], circle["passphrase"])
    slug = circle["slug"]
    sender = sender or "anon"
    header = 12 + len(slug) + (2 if compact else 0)
    room = max(32, max_line - header)
    raw_budget = max(24, room * 3 // 4 - NONCE_LEN - TAG_LEN)
    if compact:
        parts = _chunk_compact(plaintext, raw_budget)
    else:
        parts = _chunk_plain(plaintext, room)
    lines = []
    total = len(parts)
    for i, part in enumerate(parts, start=1):
        body, used_z = _seal_payload(part, compact)
        nonce = os.urandom(NONCE_LEN)
        zmark = ".z" if used_z else ""
        aad = f"{PROTOCOL}.C.{circle['name']}{'.z' if used_z else ''}.{i}/{total}".encode("utf-8")
        ct = AESGCM(key).encrypt(nonce, body, aad)
        blob = b64e(nonce + ct)
        if total == 1:
            line = f"{VERSION}C.{slug}{zmark}.{blob}"
        else:
            line = f"{VERSION}C.{slug}{zmark}.{i}/{total}.{blob}"
        if sender and sender != "anon":
            line = f"{line} #{sender}"
        lines.append(line)
    return lines


def _try_open_circle_blob(
    circle: dict, blob: str, index: int, total: int, compact: bool
) -> Optional[tuple[str, bool]]:
    """Return (plaintext, codebook_decoded) or None if it does not open."""
    key = derive_circle_key(circle["name"], circle["passphrase"])
    data = b64d(blob)
    if len(data) < NONCE_LEN + TAG_LEN:
        return None
    nonce, ct = data[:NONCE_LEN], data[NONCE_LEN:]
    z = ".z" if compact else ""
    aad = f"{PROTOCOL}.C.{circle['name']}{z}.{index}/{total}".encode("utf-8")
    try:
        pt = AESGCM(key).decrypt(nonce, ct, aad)
        return _open_payload(pt, compact), _is_codebook_payload(pt, compact)
    except Exception:
        return None


def ecdh_key(sk: ec.EllipticCurvePrivateKey, pk: ec.EllipticCurvePublicKey, info: bytes) -> bytes:
    shared = sk.exchange(ec.ECDH(), pk)
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=info,
    ).derive(shared)


def seal_to_signet(
    local: dict,
    contact: dict,
    plaintext: str,
    ephemeral: bool = False,
    max_line: int = 256,
    compact: bool = False,
) -> list[str]:
    their_pk = _pk_from_b64(contact["pk"])
    their_short = contact["short"]
    parts_budget = max(32, max_line - 16 - len(their_short) - (2 if compact else 0))
    if ephemeral:
        parts_budget -= 50
    raw_budget = max(24, parts_budget * 3 // 4 - NONCE_LEN - TAG_LEN)
    parts = _chunk_compact(plaintext, raw_budget) if compact else _chunk_plain(plaintext, parts_budget)
    lines = []
    total = len(parts)
    for i, part in enumerate(parts, start=1):
        body, used_z = _seal_payload(part, compact)
        z = ".z" if used_z else ""
        nonce = os.urandom(NONCE_LEN)
        if ephemeral:
            eph = ec.generate_private_key(ec.SECP256R1())
            eph_pk = _pk_bytes(eph.public_key())
            info = f"{PROTOCOL}.E.{their_short}{z}.{i}/{total}".encode("utf-8")
            key = ecdh_key(eph, their_pk, info)
            ct = AESGCM(key).encrypt(nonce, body, info)
            blob = b64e(eph_pk + nonce + ct)
            prefix = f"{VERSION}E.{their_short}{z}"
        else:
            my_sk = _sk_from_pem(local["sk_pem"])
            my_pk_b = _pk_bytes(my_sk.public_key())
            their_pk_b = _pk_bytes(their_pk)
            info = f"{PROTOCOL}.K.{local['short']}.{their_short}{z}.{i}/{total}".encode("utf-8")
            key = ecdh_key(my_sk, their_pk, info + my_pk_b + their_pk_b)
            ct = AESGCM(key).encrypt(nonce, body, info)
            blob = b64e(nonce + ct)
            prefix = f"{VERSION}K.{their_short}.{local['short']}{z}"
        if total == 1:
            lines.append(f"{prefix}.{blob}")
        else:
            lines.append(f"{prefix}.{i}/{total}.{blob}")
    return lines


_TOKEN_HEADS = ("S1C.", "S1K.", "S1E.", "S2C.", "S2K.", "S2E.", "S2S.")


def open_line(line: str) -> dict:
    """
    Attempt to decrypt a single SIGIL line against the local keyring.
    Returns a dict with plaintext plus metadata, or raises ValueError.
    """
    raw = line.strip()
    # Allow wrapping like: [Sigil] S1C.xxxx.yyyy
    for token in raw.replace(",", " ").split():
        if token[:4] in _TOKEN_HEADS:
            raw = token
            break
    if raw.startswith(VERSION2):
        return open_line_s2(raw)
    parts = raw.split(".")
    if len(parts) < 3 or not parts[0].startswith("S1"):
        raise ValueError("Not a SIGIL S1 message.")
    kind = parts[0][2:]  # C / K / E
    # Optional fragment field i/n sits just before the blob.
    frag_i, frag_n = 1, 1
    blob = parts[-1]
    mid = parts[1:-1]
    if mid and "/" in mid[-1] and mid[-1].replace("/", "").isdigit():
        a, b = mid[-1].split("/", 1)
        frag_i, frag_n = int(a), int(b)
        mid = mid[:-1]
    compact = False
    if mid and mid[-1] == "z":
        compact = True
        mid = mid[:-1]

    if kind == "C":
        if not mid:
            raise ValueError("Circle message missing slug.")
        slug = mid[0]
        last_err = None
        for circle in list_circles():
            if circle["slug"] != slug and circle["name"].lower() != slug:
                continue
            got = _try_open_circle_blob(circle, blob, frag_i, frag_n, compact)
            if got is None and compact:
                got = _try_open_circle_blob(circle, blob, frag_i, frag_n, False)
            if got is not None:
                pt, used_codebook = got
                return {
                    "ok": True,
                    "mode": "circle",
                    "circle": circle["name"],
                    "slug": circle["slug"],
                    "part": f"{frag_i}/{frag_n}",
                    "compact": compact,
                    "codebook": used_codebook,
                    "plaintext": pt,
                }
        raise ValueError(f"Could not open circle message for slug '{slug}'. Wrong circle or passphrase.")

    if kind == "K":
        if len(mid) < 2:
            raise ValueError("Directed message missing short-ids.")
        to_short, from_short = mid[0], mid[1]
        # We are the recipient if one of our signets matches to_short.
        local = None
        for s in list_signets():
            if s["short"] == to_short:
                local = s
                break
        if local is None:
            raise ValueError(f"Directed at signet {to_short}, which is not on this keyring.")
        contact = None
        try:
            contact = find_contact(from_short)
        except SystemExit:
            raise ValueError(
                f"Sender {from_short} is not in your contact book. "
                "Import their public signet first."
            )
        my_sk = _sk_from_pem(local["sk_pem"])
        their_pk = _pk_from_b64(contact["pk"])
        my_pk_b = _pk_bytes(my_sk.public_key())
        their_pk_b = _pk_bytes(their_pk)
        z = ".z" if compact else ""
        info = f"{PROTOCOL}.K.{from_short}.{to_short}{z}.{frag_i}/{frag_n}".encode("utf-8")
        key = ecdh_key(my_sk, their_pk, info + their_pk_b + my_pk_b)
        data = b64d(blob)
        nonce, ct = data[:NONCE_LEN], data[NONCE_LEN:]
        body = AESGCM(key).decrypt(nonce, ct, info)
        return {
            "ok": True,
            "mode": "signet",
            "to": local["name"],
            "from": contact.get("name_hint", from_short),
            "part": f"{frag_i}/{frag_n}",
            "codebook": _is_codebook_payload(body, compact),
            "plaintext": _open_payload(body, compact),
        }

    if kind == "E":
        if not mid:
            raise ValueError("Ephemeral message missing recipient short-id.")
        to_short = mid[0]
        local = None
        for s in list_signets():
            if s["short"] == to_short:
                local = s
                break
        if local is None:
            raise ValueError(f"Ephemeral packet is for {to_short}, not on this keyring.")
        data = b64d(blob)
        if len(data) < P256_COMPRESSED_LEN + NONCE_LEN + TAG_LEN:
            raise ValueError("Ephemeral packet is truncated.")
        eph_raw = data[:P256_COMPRESSED_LEN]
        nonce = data[P256_COMPRESSED_LEN:P256_COMPRESSED_LEN + NONCE_LEN]
        ct = data[P256_COMPRESSED_LEN + NONCE_LEN:]
        eph_pk = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), eph_raw)
        my_sk = _sk_from_pem(local["sk_pem"])
        z = ".z" if compact else ""
        info = f"{PROTOCOL}.E.{to_short}{z}.{frag_i}/{frag_n}".encode("utf-8")
        key = ecdh_key(my_sk, eph_pk, info)
        body = AESGCM(key).decrypt(nonce, ct, info)
        return {
            "ok": True,
            "mode": "ephemeral",
            "to": local["name"],
            "from": "ephemeral-sender",
            "part": f"{frag_i}/{frag_n}",
            "codebook": _is_codebook_payload(body, compact),
            "plaintext": _open_payload(body, compact),
        }

    raise ValueError(f"Unknown SIGIL kind '{kind}'.")


def _codebook_boundary_space(left: str, right: str) -> bool:
    """
    Whitespace restoration for a part boundary that touches a codebook part.

    Codebook v2 does not store spaces; expand_v2 re-inserts one between two
    word/number tokens and after .,:;?! -- and the encoder drops a part's
    trailing (and leading) whitespace. _chunk_compact cuts after a space, so
    that space vanishes at every boundary. Re-apply the decoder's own
    implicit-space rule across the boundary. This is still a heuristic: a
    compact part cut mid-word (no space to snap to) gets a spurious space.
    Telling the two apart needs a boundary marker the S1 payload does not
    carry, and adding one would change the wire format.
    """
    if not left or not right:
        return False
    a, b = left[-1], right[0]
    return (a.isalnum() and b.isalnum()) or (a in ".,:;?!" and b.isalnum())


def stitch_parts(parts: list[tuple]) -> str:
    """
    Join decoded fragments, already in i/n order.

    S1 items are (plaintext, codebook). Raw parts are exact UTF-8 slices (the
    plain chunker cuts mid-word), so a raw|raw boundary is concatenated
    byte-exact. Only a boundary next to a codebook-decoded part gets
    whitespace restored, heuristically (see _codebook_boundary_space).

    S2 items are (plaintext, codebook, join). The authenticated J flag says
    whether exactly one space follows the part, so S2 is exact: no heuristic.
    """
    joined = ""
    prev_codebook = False
    for k, item in enumerate(parts):
        text, used_codebook = item[0], item[1]
        join = item[2] if len(item) > 2 else None
        if join is not None:
            joined += text + (" " if join else "")
            continue
        if k and (prev_codebook or used_codebook) and _codebook_boundary_space(joined, text):
            joined += " "
        joined += text
        prev_codebook = used_codebook
    return joined


# ---------------------------------------------------------------------------
# S2 wire format (see README "Wire format S2"). Same primitives and keys as
# S1: AES-256-GCM, PBKDF2-HMAC-SHA256 circle keys, ECDH P-256 + HKDF-SHA256.
# What S2 adds: an authenticated binary frame header carrying the codebook
# flag, an exact rejoin flag, i/n and a random message id, plus an optional
# sender field inside the ciphertext.
# ---------------------------------------------------------------------------

VERSION2 = "S2"
PROTOCOL2 = "SIGIL.v2"
S2_Z = 0x01         # body is a codebook v2 stream
S2_J = 0x02         # rejoin: exactly one U+0020 follows this part's text
S2_M = 0x04         # multi-part: part byte + message id follow the flags byte
S2_S = 0x08         # plaintext starts with a sender field (part 1 only)
S2_RESERVED = 0xF0  # must be zero
S2_MID_LEN = 6      # 48-bit random message id (multi-part only)
S2_MAX_PARTS = 16
S2_MAX_SENDER = 32  # bytes of UTF-8
S2_KINDS = ("C", "K", "E", "S")
# S2S (signed circle, 0.5.0): the last part carries keyid || Ed25519 signature.
S2S_KEYID_LEN = 8
S2S_SIG_LEN = 64
S2S_TRAILER = S2S_KEYID_LEN + S2S_SIG_LEN
S2S_SIG_DOMAIN = b"SIGIL.v2.sig\x00"
DEFAULT_WIRE = os.environ.get("SIGIL_WIRE", "S2").strip().upper() or "S2"


def _b64_room(chars: int) -> int:
    """Largest byte count whose unpadded base64url fits in `chars` characters."""
    if chars <= 0:
        return 0
    return (chars // 4) * 3 + max(0, chars % 4 - 1)


def s2_header(flags: int, index: int, total: int, mid: bytes = b"") -> bytes:
    """Frame header bytes: flags [part mid]. These bytes start every AAD."""
    if flags & (S2_RESERVED | S2_M):
        raise ValueError("s2_header: flags must not carry reserved or M bits")
    if total == 1:
        if index != 1 or mid:
            raise ValueError("single-part S2 frame has no part field or message id")
        return bytes([flags])
    if not (2 <= total <= S2_MAX_PARTS and 1 <= index <= total) or len(mid) != S2_MID_LEN:
        raise ValueError("bad S2 part field")
    return bytes([flags | S2_M, ((index - 1) << 4) | (total - 1)]) + mid


def s2_parse_frame(data: bytes, ephemeral: bool = False) -> dict:
    """Split an S2 frame into header fields, eph key, nonce and ciphertext."""
    if not data:
        raise ValueError("Empty S2 blob.")
    flags = data[0]
    if flags & S2_RESERVED:
        raise ValueError("S2 header sets reserved bits (newer format?).")
    pos, index, total, mid = 1, 1, 1, b""
    if flags & S2_M:
        if len(data) < 2 + S2_MID_LEN:
            raise ValueError("S2 blob truncated.")
        index, total = (data[1] >> 4) + 1, (data[1] & 0x0F) + 1
        if total < 2 or index > total:
            raise ValueError("Bad S2 part field.")
        mid = data[2:2 + S2_MID_LEN]
        pos = 2 + S2_MID_LEN
    if flags & S2_J and index == total:
        raise ValueError("S2 join flag set on the last part.")
    if flags & S2_S and index != 1:
        raise ValueError("S2 sender flag set on a part other than 1.")
    header = data[:pos]
    eph = b""
    if ephemeral:
        eph = data[pos:pos + P256_COMPRESSED_LEN]
        pos += P256_COMPRESSED_LEN
    nonce, ct = data[pos:pos + NONCE_LEN], data[pos + NONCE_LEN:]
    if len(eph) != (P256_COMPRESSED_LEN if ephemeral else 0) or len(nonce) != NONCE_LEN or len(ct) < TAG_LEN:
        raise ValueError("S2 blob truncated.")
    return {"flags": flags, "index": index, "total": total, "mid": mid,
            "header": header, "eph": eph, "nonce": nonce, "ct": ct}


def s2_context(kind: str, *route: str) -> bytes:
    """UTF-8 'SIGIL.v2.<kind>.<route...>'. AAD = header || context."""
    return f"{PROTOCOL2}.{kind}.{'.'.join(route)}".encode("utf-8")


def _s2_body(text: str, compact: bool) -> tuple[bytes, bool]:
    """
    Sealer policy (not part of the wire format): a part uses the codebook
    only if it shrinks AND expands back to the same text up to letter case.
    Parts the codebook would reshape (dropped/inserted spaces, long tokens,
    '_' vs ' ') go out raw, so S2 compact is exact except that dictionary
    words may come back lowercase.
    """
    raw = text.encode("utf-8")
    if compact:
        packed, used = codebook.maybe_compress(text)
        if used and codebook.expand_v2(packed).lower() == text.lower():
            return packed, True
    return raw, False


def _s2_sender_field(sender: str) -> bytes:
    if not sender:
        return b""
    raw = sender.encode("utf-8")
    if len(raw) > S2_MAX_SENDER:
        raise ValueError(f"Sender name is longer than {S2_MAX_SENDER} UTF-8 bytes.")
    return bytes([len(raw)]) + raw


def s2_payload_room(max_line: int, prefix_len: int, multi: bool, eph_len: int = 0) -> int:
    """Plaintext bytes (sender field + body) that fit one S2 line."""
    header = 2 + S2_MID_LEN if multi else 1
    return _b64_room(max_line - prefix_len) - header - eph_len - NONCE_LEN - TAG_LEN


def s2_split(
    text: str, compact: bool, sender: str, max_line: int, prefix_len: int, eph_len: int = 0, tail: int = 0
) -> list[tuple[str, bool]]:
    """
    Cut text into (part_text, join) pairs that fit S2 lines. Rejoining is
    exact by construction: text == "".join(p + (" " if j else "") ...).
    Compact mode prefers to cut at a space and consumes it (join=True), so
    the codebook never has to carry boundary whitespace; otherwise a part is
    cut mid-word (join=False), which is still exact.

    `tail` bytes are reserved at the end of the LAST part (S2S: keyid ||
    signature). If the last text part has no room for them, an extra part
    with empty text carries the tail alone.
    """
    sfield = len(_s2_sender_field(sender))
    single = s2_payload_room(max_line, prefix_len, False, eph_len)
    if sfield + len(_s2_body(text, compact)[0]) + tail <= single:
        return [(text, False)]
    parts = _s2_split_multi(text, compact, sfield, max_line, prefix_len, eph_len)
    if tail:
        room = s2_payload_room(max_line, prefix_len, True, eph_len)
        if tail > room:
            raise ValueError("max_line is too small for an S2S signature part.")
        last = len(_s2_body(parts[-1][0], compact)[0]) + (sfield if len(parts) == 1 else 0)
        if len(parts) == 1 or last + tail > room:
            parts.append(("", False))
    if len(parts) > S2_MAX_PARTS:
        raise ValueError(
            f"S2 carries at most {S2_MAX_PARTS} parts; this message needs {len(parts)}. "
            "Shorten it, raise --max-line, or use --wire S1."
        )
    return parts


def _s2_split_multi(
    text: str, compact: bool, sfield: int, max_line: int, prefix_len: int, eph_len: int
) -> list[tuple[str, bool]]:
    """The multi-part cut of s2_split (the text does not fit one line)."""
    room = s2_payload_room(max_line, prefix_len, True, eph_len)
    if room - sfield < 8:
        raise ValueError("max_line is too small for an S2 fragment.")

    def size(s: str) -> int:
        return len(_s2_body(s, compact)[0])

    parts: list[tuple[str, bool]] = []
    rest = text
    while rest:
        budget = room - (sfield if not parts else 0)
        # No codebook token packs more than ~12 characters per byte; the cap
        # only keeps the search cheap (a smaller part is still correct).
        span = min(len(rest), budget * 12)
        if span == len(rest) and size(rest) <= budget:
            parts.append((rest, False))
            break
        lo, hi, best = 1, span, 0
        while lo <= hi:
            mid = (lo + hi) // 2
            if size(rest[:mid]) <= budget:
                best, lo = mid, mid + 1
            else:
                hi = mid - 1
        if best == 0:
            raise ValueError("max_line is too small for an S2 fragment.")
        cut, join = best, False
        if compact:
            floor = max(1, best // 2)
            c = rest.rfind(" ", floor, best + 1)
            while c >= floor and size(rest[:c]) > budget:
                c = rest.rfind(" ", floor, c)
            # Never consume the final character: J must be 0 on the last part.
            if c >= floor and c + 1 < len(rest):
                cut, join = c, True
        parts.append((rest[:cut], join))
        rest = rest[cut + (1 if join else 0):]
    return parts


def s2_frames(
    text: str, compact: bool, sender: str, max_line: int, prefix_len: int, eph_len: int = 0, tail: int = 0
) -> list[tuple[bytes, bytes]]:
    """Return (header, plaintext) per part, ready for AES-GCM (tail bytes not included)."""
    parts = s2_split(text, compact, sender, max_line, prefix_len, eph_len, tail)
    total = len(parts)
    mid = os.urandom(S2_MID_LEN) if total > 1 else b""
    out = []
    for i, (part, join) in enumerate(parts, start=1):
        # The S2S signature-only part is always raw (empty body, Z=0).
        body, used_z = _s2_body(part, compact) if part else (b"", False)
        flags = (S2_Z if used_z else 0) | (S2_J if join else 0)
        sfield = b""
        if i == 1 and sender:
            flags |= S2_S
            sfield = _s2_sender_field(sender)
        out.append((s2_header(flags, i, total, mid), sfield + body))
    return out


def s2_unpack_plaintext(flags: int, pt: bytes) -> tuple[Optional[str], str]:
    """Plaintext -> (sender or None, part text)."""
    sender = None
    if flags & S2_S:
        n = pt[0] if pt else 0
        if not 1 <= n <= S2_MAX_SENDER or len(pt) < 1 + n:
            raise ValueError("Bad S2 sender field.")
        sender, pt = pt[1:1 + n].decode("utf-8"), pt[1 + n:]
    if flags & S2_Z:
        if pt[:1] != codebook.MAGIC2:
            raise ValueError("S2 codebook body does not start with the v2 magic byte.")
        return sender, codebook.expand_v2(pt)
    return sender, pt.decode("utf-8")


def _s2_check_lines(lines: list[str], max_line: int) -> list[str]:
    for line in lines:
        if len(line) > max_line:  # budgets are exact; this is a guard, not a code path
            raise AssertionError(f"S2 line {len(line)} > max_line {max_line}")
    return lines


def seal_circle_s2(
    circle: dict, plaintext: str, sender: str = "", max_line: int = 256, compact: bool = False
) -> list[str]:
    key = derive_circle_key(circle["name"], circle["passphrase"])
    prefix = f"{VERSION2}C.{circle['slug']}."
    ctx = s2_context("C", circle["name"])
    lines = []
    for header, pt in s2_frames(plaintext, compact, sender, max_line, len(prefix)):
        nonce = os.urandom(NONCE_LEN)
        ct = AESGCM(key).encrypt(nonce, pt, header + ctx)
        lines.append(prefix + b64e(header + nonce + ct))
    return _s2_check_lines(lines, max_line)


def s2s_keyid(spk: bytes) -> bytes:
    """S2S key id: the first 8 bytes of SHA-256(Ed25519 public key) (= the fingerprint's first 8 bytes)."""
    return hashlib.sha256(spk).digest()[:S2S_KEYID_LEN]


def s2s_signed_bytes(ctx: bytes, keyid: bytes, parts: list[tuple[bytes, bytes]]) -> bytes:
    """
    What the S2S Ed25519 signature covers: the whole message.

      "SIGIL.v2.sig" 0x00 || u16(len ctx) ctx || keyid(8) || u8(n)
        || for i in 1..n: u8(len header_i) header_i || u16(len pt_i) pt_i

    header_i are the exact header bytes (flags, part byte, message id) and pt_i
    the exact part plaintexts (sender field + body, codebook-packed if Z)
    without the trailer. All lengths big-endian.
    """
    if not 1 <= len(parts) <= S2_MAX_PARTS or len(keyid) != S2S_KEYID_LEN:
        raise ValueError("bad S2S signing input")
    out = bytearray(S2S_SIG_DOMAIN)
    out += len(ctx).to_bytes(2, "big") + ctx + keyid + bytes([len(parts)])
    for header, pt in parts:
        out += bytes([len(header)]) + header + len(pt).to_bytes(2, "big") + pt
    return bytes(out)


def seal_circle_signed_s2(
    circle: dict, signet: dict, plaintext: str, sender: str = "", max_line: int = 256, compact: bool = False
) -> list[str]:
    """
    S2S: an S2C-style circle message whose last part ends with
    keyid(8) || Ed25519(signet signing key, s2s_signed_bytes(...)).
    Circle confidentiality plus proof of which signet wrote the whole message.
    """
    sign_sk = _sign_sk_from_rec(signet)
    keyid = s2s_keyid(_spk_bytes(sign_sk.public_key()))
    key = derive_circle_key(circle["name"], circle["passphrase"])
    prefix = f"{VERSION2}S.{circle['slug']}."
    ctx = s2_context("S", circle["name"])
    frames = s2_frames(plaintext, compact, sender, max_line, len(prefix), tail=S2S_TRAILER)
    sig = sign_sk.sign(s2s_signed_bytes(ctx, keyid, frames))
    lines = []
    for k, (header, pt) in enumerate(frames):
        if k == len(frames) - 1:
            pt = pt + keyid + sig
        nonce = os.urandom(NONCE_LEN)
        ct = AESGCM(key).encrypt(nonce, pt, header + ctx)
        lines.append(prefix + b64e(header + nonce + ct))
    return _s2_check_lines(lines, max_line)


def seal_to_signet_s2(
    local: dict,
    contact: dict,
    plaintext: str,
    ephemeral: bool = False,
    max_line: int = 256,
    compact: bool = False,
    sender: str = "",
) -> list[str]:
    their_pk = _pk_from_b64(contact["pk"])
    their_pk_b = _pk_bytes(their_pk)
    to_short = contact["short"]
    lines = []
    if ephemeral:
        prefix = f"{VERSION2}E.{to_short}."
        ctx = s2_context("E", to_short)
        for header, pt in s2_frames(plaintext, compact, sender, max_line, len(prefix), P256_COMPRESSED_LEN):
            eph = ec.generate_private_key(ec.SECP256R1())
            eph_pk = _pk_bytes(eph.public_key())
            key = ecdh_key(eph, their_pk, ctx + eph_pk + their_pk_b)
            nonce = os.urandom(NONCE_LEN)
            ct = AESGCM(key).encrypt(nonce, pt, header + ctx)
            lines.append(prefix + b64e(header + eph_pk + nonce + ct))
    else:
        my_sk = _sk_from_pem(local["sk_pem"])
        my_pk_b = _pk_bytes(my_sk.public_key())
        prefix = f"{VERSION2}K.{to_short}.{local['short']}."
        ctx = s2_context("K", local["short"], to_short)
        key = ecdh_key(my_sk, their_pk, ctx + my_pk_b + their_pk_b)
        for header, pt in s2_frames(plaintext, compact, sender, max_line, len(prefix)):
            nonce = os.urandom(NONCE_LEN)
            ct = AESGCM(key).encrypt(nonce, pt, header + ctx)
            lines.append(prefix + b64e(header + nonce + ct))
    return _s2_check_lines(lines, max_line)


def open_line_s2(token: str) -> dict:
    """Open one bare S2 token against the local keyring (raises ValueError)."""
    fields = token.split(".")
    kind = fields[0][2:]
    if fields[0][:2] != VERSION2 or kind not in S2_KINDS or len(fields) < 3:
        raise ValueError("Not a SIGIL S2 message.")
    route, blob = fields[1:-1], fields[-1]
    try:
        data = b64d(blob)
    except Exception:
        raise ValueError("S2 blob is not base64url.")
    fr = s2_parse_frame(data, ephemeral=(kind == "E"))
    base = {
        "ok": True,
        "version": 2,
        "part": f"{fr['index']}/{fr['total']}",
        "mid": fr["mid"].hex(),
        "join": bool(fr["flags"] & S2_J),
        "compact": bool(fr["flags"] & S2_Z),
        "codebook": bool(fr["flags"] & S2_Z),
    }

    def finish(pt: bytes, extra: dict) -> dict:
        sender, text = s2_unpack_plaintext(fr["flags"], pt)
        out = dict(base, **extra)
        out["sender"] = sender
        out["plaintext"] = text
        return out

    if kind == "S":
        if len(route) != 1:
            raise ValueError("S2 signed token needs exactly one slug.")
        slug = route[0]
        for circle in list_circles():
            if circle["slug"] != slug and circle["name"].lower() != slug:
                continue
            key = derive_circle_key(circle["name"], circle["passphrase"])
            ctx = s2_context("S", circle["name"])
            try:
                pt = AESGCM(key).decrypt(fr["nonce"], fr["ct"], fr["header"] + ctx)
            except Exception:
                continue
            extra = {"mode": "signed", "circle": circle["name"], "slug": circle["slug"],
                     "header_hex": fr["header"].hex(), "ctx_hex": ctx.hex()}
            if fr["index"] == fr["total"]:
                if len(pt) < S2S_TRAILER:
                    raise ValueError("S2S last part is too short for its signature trailer.")
                pt, trailer = pt[:-S2S_TRAILER], pt[-S2S_TRAILER:]
                extra["keyid"] = trailer[:S2S_KEYID_LEN].hex()
                extra["sig_hex"] = trailer[S2S_KEYID_LEN:].hex()
            extra["payload_hex"] = pt.hex()
            return finish(pt, extra)
        raise ValueError(f"Could not open signed circle message for slug '{slug}'. Wrong circle or passphrase.")

    if kind == "C":
        if len(route) != 1:
            raise ValueError("S2 circle token needs exactly one slug.")
        slug = route[0]
        for circle in list_circles():
            if circle["slug"] != slug and circle["name"].lower() != slug:
                continue
            key = derive_circle_key(circle["name"], circle["passphrase"])
            aad = fr["header"] + s2_context("C", circle["name"])
            try:
                pt = AESGCM(key).decrypt(fr["nonce"], fr["ct"], aad)
            except Exception:
                continue
            return finish(pt, {"mode": "circle", "circle": circle["name"], "slug": circle["slug"]})
        raise ValueError(f"Could not open circle message for slug '{slug}'. Wrong circle or passphrase.")

    if kind == "K":
        if len(route) != 2:
            raise ValueError("S2 signet token needs <to>.<from>.")
        to_short, from_short = route
        local = next((s for s in list_signets() if s["short"] == to_short), None)
        if local is None:
            raise ValueError(f"Directed at signet {to_short}, which is not on this keyring.")
        try:
            contact = find_contact(from_short)
        except SystemExit:
            raise ValueError(f"Sender {from_short} is not in your contact book. Import their public signet first.")
        my_sk = _sk_from_pem(local["sk_pem"])
        their_pk = _pk_from_b64(contact["pk"])
        ctx = s2_context("K", from_short, to_short)
        key = ecdh_key(my_sk, their_pk, ctx + _pk_bytes(their_pk) + _pk_bytes(my_sk.public_key()))
        pt = AESGCM(key).decrypt(fr["nonce"], fr["ct"], fr["header"] + ctx)
        return finish(pt, {"mode": "signet", "to": local["name"],
                           "from": contact.get("name_hint", from_short)})

    # kind == "E"
    if len(route) != 1:
        raise ValueError("S2 ephemeral token needs exactly one recipient short-id.")
    to_short = route[0]
    local = next((s for s in list_signets() if s["short"] == to_short), None)
    if local is None:
        raise ValueError(f"Ephemeral packet is for {to_short}, not on this keyring.")
    my_sk = _sk_from_pem(local["sk_pem"])
    eph_pk = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), fr["eph"])
    ctx = s2_context("E", to_short)
    key = ecdh_key(my_sk, eph_pk, ctx + fr["eph"] + _pk_bytes(my_sk.public_key()))
    pt = AESGCM(key).decrypt(fr["nonce"], fr["ct"], fr["header"] + ctx)
    return finish(pt, {"mode": "ephemeral", "to": local["name"], "from": "ephemeral-sender"})


def s2_capacity(mode: str, max_line: int = 256, multi: bool = False, slug_len: int = 4) -> int:
    """
    Exact plaintext bytes per S2 line (no sender field). For S the figure is
    the last (or only) line, which also carries the 72-byte signature trailer;
    earlier S2S parts carry as much as S2C parts.
    """
    prefix = {"C": 5 + slug_len, "S": 5 + slug_len, "K": 14, "E": 9}[mode]
    eph = P256_COMPRESSED_LEN if mode == "E" else 0
    tail = S2S_TRAILER if mode == "S" else 0
    return max(0, s2_payload_room(max_line, prefix, multi, eph) - tail)


def signing_keys() -> list[dict]:
    """Every Ed25519 public key this keyring can verify with: own signets and contacts."""
    out, seen = [], set()
    for rec in list_signets():
        if rec.get("sign_pk") and rec["sign_pk"] not in seen:
            seen.add(rec["sign_pk"])
            out.append({"name": rec["name"], "spk": rec["sign_pk"], "own": True})
    for entry in load_contacts().get("contacts", {}).values():
        if entry.get("spk") and entry["spk"] not in seen:
            seen.add(entry["spk"])
            out.append({"name": entry.get("alias") or entry.get("name_hint"), "spk": entry["spk"], "own": False})
    return out


def s2s_verify(parts: list[dict], keys: Optional[list[dict]] = None) -> dict:
    """
    Verify a complete S2S message (opened parts in index order). Returns
    {"verified": bool, "signer": name or None, "signer_fp": fingerprint or None,
     "keyid": hex, "error": str or None}. Only keys whose key id matches are
    tried; the signature must verify under the full public key.
    """
    last = parts[-1]
    keyid = bytes.fromhex(last["keyid"])
    sig = bytes.fromhex(last["sig_hex"])
    ctx = bytes.fromhex(last["ctx_hex"])
    tbs = s2s_signed_bytes(ctx, keyid, [(bytes.fromhex(r["header_hex"]), bytes.fromhex(r["payload_hex"]))
                                        for r in parts])
    keys = signing_keys() if keys is None else keys
    candidates = [k for k in keys if s2s_keyid(b64d(k["spk"])) == keyid]
    for k in candidates:
        spk = b64d(k["spk"])
        try:
            ed25519.Ed25519PublicKey.from_public_bytes(spk).verify(sig, tbs)
        except Exception:
            continue
        return {"verified": True, "signer": k["name"], "signer_fp": fingerprint(spk), "keyid": keyid.hex(),
                "error": None}
    err = ("BAD SIGNATURE: forged or altered by someone holding the circle key" if candidates
           else f"unknown signer key id {keyid.hex()} (import their S2+PK announcement)")
    return {"verified": False, "signer": None, "signer_fp": None, "keyid": keyid.hex(), "error": err}


def open_messages(text: str) -> list[dict]:
    results = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            results.append(open_line(line))
        except Exception as e:
            results.append({"ok": False, "error": str(e), "line": line[:80]})
    return results


# ---------------------------------------------------------------------------
# Public announcements (what you paste once into an open chat)
# ---------------------------------------------------------------------------

def announce_circle(circle: dict) -> str:
    return (
        f"S1+CIRCLE.{circle['slug']}.{circle['name'].replace('.', '_')}"
        f".fp{circle['fingerprint']}"
    )


def announce_signet(signet: dict) -> str:
    """S2+PK (P-256 + Ed25519 signing key, 0.5.0+) when the signet has a signing key, else S1+PK."""
    name = signet['name'].replace('.', '_')
    if signet.get("sign_pk"):
        return f"S2+PK.{name}.{signet['short']}.{signet['pk']}.{signet['sign_pk']}"
    return f"S1+PK.{name}.{signet['short']}.{signet['pk']}"


def parse_announcement(line: str) -> dict:
    raw = line.strip()
    for token in raw.replace(",", " ").split():
        if token.startswith("S1+") or token.startswith("S2+"):
            raw = token
            break
    parts = raw.split(".")
    if parts[0] == "S2+PK" and len(parts) == 5:
        return {"kind": "signet-announcement", "name": parts[1], "short": parts[2], "pk": parts[3],
                "spk": parts[4]}
    if parts[0] == "S1+CIRCLE" and len(parts) >= 4:
        return {"kind": "circle-announcement", "slug": parts[1], "name": parts[2], "fp": parts[3]}
    if parts[0] == "S1+PK" and len(parts) >= 4:
        return {
            "kind": "signet-announcement",
            "name": parts[1],
            "short": parts[2],
            "pk": parts[3],
        }
    raise ValueError("Not a SIGIL announcement.")


# ---------------------------------------------------------------------------
# Capacity helper — how much plaintext fits in one Minecraft chat line
# ---------------------------------------------------------------------------

def capacity(mode: str, slug_len: int = 4) -> int:
    """Approximate UTF-8 byte budget for a single 256-char line."""
    if mode == "C":
        header = len(f"S1C.{'x'*slug_len}.")
        encoded_room = 256 - header
        return max(0, encoded_room * 3 // 4 - NONCE_LEN - TAG_LEN)
    if mode == "K":
        header = len("S1K.xxxx.xxxx.")
        encoded_room = 256 - header
        return max(0, encoded_room * 3 // 4 - NONCE_LEN - TAG_LEN)
    if mode == "E":
        header = len("S1E.xxxx.")
        encoded_room = 256 - header
        raw_room = encoded_room * 3 // 4
        return max(0, raw_room - P256_COMPRESSED_LEN - NONCE_LEN - TAG_LEN)
    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

HELP_EPILOG = """
examples:
  sigil circle new deepcave
  sigil seal -c deepcave "portal at 1847 12 -320, tell no one"
  sigil open S1C.deep.abc...

  sigil signet new Steve
  sigil publish
  sigil contact add Alex S1+PK.Alex.k9wq.BASE64KEY
  sigil seal -to Alex "don't sell the elytra yet"
  sigil open S1K.k9wq.r2ab.BASE64...
"""


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="sigil",
        description="SIGIL — encrypt messages for open chats and Minecraft whispers.",
        epilog=HELP_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    c = sub.add_parser("circle", help="Manage shared-passphrase circles")
    csub = c.add_subparsers(dest="ccmd", required=True)
    n = csub.add_parser("new", help="Create a circle")
    n.add_argument("name")
    n.add_argument("-p", "--passphrase", default=None, help="If omitted, you will be prompted")
    n.add_argument("--dice", type=int, nargs="?", const=5, default=None, help="Generate an N-word passphrase (default 5)")
    n.add_argument("--note", default="")
    csub.add_parser("list", help="List local circles")
    sh = csub.add_parser("show", help="Show circle announcement to paste in chat")
    sh.add_argument("name")
    rot = csub.add_parser("rotate", help="Mint a successor circle and retire the old name")
    rot.add_argument("name")
    rot.add_argument("--dice", type=int, default=5)

    bak = sub.add_parser("backup", help="Encrypt the whole keyring to a token")
    bak.add_argument("-p", "--passphrase", default=None)
    rst = sub.add_parser("restore", help="Load a backup token into this keyring")
    rst.add_argument("token")
    rst.add_argument("-p", "--passphrase", default=None)

    s = sub.add_parser("signet", help="Manage your public-key identity")
    ssub = s.add_subparsers(dest="scmd", required=True)
    sn = ssub.add_parser("new", help="Create a signet")
    sn.add_argument("name")
    ssub.add_parser("list")
    ss = ssub.add_parser("show")
    ss.add_argument("name")
    su = ssub.add_parser("upgrade", help="Add an Ed25519 signing key (S2S) to an older signet")
    su.add_argument("name")

    sub.add_parser("fingerprint", help="Full public-key fingerprints of your signets and contacts")

    pub = sub.add_parser("publish", help="Print every public announcement you can paste")

    ct = sub.add_parser("contact", help="Other people's public signets")
    ctsub = ct.add_subparsers(dest="ctcmd", required=True)
    add = ctsub.add_parser("add")
    add.add_argument("alias")
    add.add_argument("key", help="S2+PK / S1+PK announcement or raw public key")
    ctsub.add_parser("list")

    seal = sub.add_parser("seal", help="Encrypt a message")
    seal.add_argument("message", nargs="?", help="Message text (or stdin)")
    seal.add_argument("-c", "--circle", help="Circle name")
    seal.add_argument("-to", "--to", help="Contact alias or short-id")
    seal.add_argument("-from", "--sender", default="",
                      help="Sender name. S2: sealed inside part 1 (authenticated, but any circle member "
                           "can claim any name). S1: loose ' #name' suffix, not authenticated")
    seal.add_argument("--wire", choices=["S1", "S2", "s1", "s2"], default=None,
                      help="Wire format to emit (default S2, or $SIGIL_WIRE). Use S1 for old peers")
    seal.add_argument("--from-signet", default="", help="Which local signet to send or sign as")
    seal.add_argument("--sign", action="store_true",
                      help="Circle only: S2S, sign the whole message with your signet's Ed25519 key")
    seal.add_argument("--ephemeral", action="store_true", help="Use a one-time key (S2E/S1E, forward secrecy)")
    seal.add_argument("--max-line", type=int, default=256, help="Channel character limit (Minecraft=256)")
    seal.add_argument(
        "--compact",
        dest="compact",
        action="store_true",
        default=True,
        help="Compress plaintext with codebook v2 (default)",
    )
    seal.add_argument(
        "--raw",
        dest="compact",
        action="store_false",
        help="Skip codebook compression",
    )

    pack = sub.add_parser("compact", help="Show codebook compression without sealing")
    pack.add_argument("message", nargs="?", help="Message text (or stdin)")

    op = sub.add_parser("open", help="Decrypt one or more SIGIL lines")
    op.add_argument("text", nargs="?", help="Ciphertext (or stdin)")

    sub.add_parser("info", help="Protocol summary and Minecraft capacity")
    sub.add_parser("selftest", help="Encrypt and decrypt a fixture against this copy")
    return p


def _prompt_secret(label: str) -> str:
    import getpass
    a = getpass.getpass(f"{label}: ")
    b = getpass.getpass(f"{label} (again): ")
    if a != b:
        raise SystemExit("Entries did not match.")
    if len(a) < 8:
        raise SystemExit("Use at least 8 characters. A diceware phrase is better.")
    return a


def cmd_circle(args: argparse.Namespace) -> None:
    if args.ccmd == "new":
        if args.dice:
            pw = dice_phrase(args.dice)
            print(f"Dice passphrase ({args.dice} words): {pw}")
            print("Read that aloud. It is not written anywhere except your keyring.")
        else:
            pw = args.passphrase or _prompt_secret("Circle passphrase")
        rec = circle_create(args.name, pw, args.note)
        spoken = speak_fingerprint(rec["fingerprint"])
        print(f"Circle '{rec['name']}' created.")
        print(f"  slug         {rec['slug']}")
        print(f"  fingerprint  {rec['fingerprint']}")
        print(f"  say aloud    {spoken}")
        print("Paste this once so friends know the circle exists:")
        print(announce_circle(rec))
        print(f"# say: {spoken}")
        print("Share the passphrase out-of-band (voice, whisper, paper). Never in public chat.")
    elif args.ccmd == "list":
        rows = list_circles()
        if not rows:
            print("No circles yet.")
            return
        for rec in rows:
            spoken = speak_fingerprint(rec["fingerprint"])
            print(f"  {rec['slug']:6}  {rec['name']:20}  fp={rec['fingerprint']}  {spoken}  {rec['created']}")
    elif args.ccmd == "show":
        rec = load_circle(args.name)
        print(announce_circle(rec))
        print(f"# say: {speak_fingerprint(rec['fingerprint'])}")
    elif args.ccmd == "rotate":
        old = load_circle(args.name)
        new_name = f"{old['name']}-r"
        n = 2
        while True:
            try:
                load_circle(f"{old['name']}-r{n}" if n > 2 else new_name)
            except SystemExit:
                break
            n += 1
            new_name = f"{old['name']}-r{n}"
        if n == 2:
            new_name = f"{old['name']}-r2"
        pw = dice_phrase(args.dice)
        rec = circle_create(new_name, pw, note=f"rotated from {old['name']}")
        print(f"Retired '{old['name']}' for new members. Old tokens still open with the old passphrase.")
        print(f"New circle '{rec['name']}'")
        print(f"  passphrase   {pw}")
        print(f"  fingerprint  {rec['fingerprint']}")
        print(f"  say aloud    {speak_fingerprint(rec['fingerprint'])}")
        print(announce_circle(rec))
        print("Tell the remaining group the new name + passphrase on voice, then stop using the old circle.")


def cmd_signet(args: argparse.Namespace) -> None:
    if args.scmd == "new":
        rec = signet_create(args.name)
        print(f"Signet '{rec['name']}' created. short-id {rec['short']}")
        print("Paste this public announcement anywhere:")
        print(announce_signet(rec))
        print("Keep the file in keys/ secret. Anyone with it can read mail to you and impersonate you.")
    elif args.scmd == "list":
        rows = list_signets()
        if not rows:
            print("No signets yet.")
            return
        for rec in rows:
            sign = f"sign={rec['sign_short']}" if rec.get("sign_pk") else "no signing key (sigil signet upgrade)"
            print(f"  {rec['short']:6}  {rec['name']:20}  {sign}  {rec['created']}")
    elif args.scmd == "show":
        rec = load_signet(args.name)
        print(announce_signet(rec))
    elif args.scmd == "upgrade":
        rec = signet_add_signing_key(args.name)
        print(f"Signet '{rec['name']}' can sign (S2S). New announcement:")
        print(announce_signet(rec))


def cmd_fingerprint(_: argparse.Namespace) -> None:
    rows = 0
    for rec in list_signets():
        rows += 1
        print(f"me       {rec['name']:16}  fp={fingerprint(b64d(rec['pk']))}"
              + (f"  sfp={fingerprint(b64d(rec['sign_pk']))}" if rec.get("sign_pk") else ""))
    seen = set()
    for entry in load_contacts().get("contacts", {}).values():
        if entry["pk"] in seen:
            continue
        seen.add(entry["pk"])
        rows += 1
        print(f"contact  {entry['alias']:16}  fp={fingerprint(b64d(entry['pk']))}"
              + (f"  sfp={fingerprint(b64d(entry['spk']))}" if entry.get("spk") else ""))
    if not rows:
        print("No signets or contacts.")


def cmd_publish(_: argparse.Namespace) -> None:
    any_out = False
    for rec in list_circles():
        print(announce_circle(rec))
        any_out = True
    for rec in list_signets():
        print(announce_signet(rec))
        any_out = True
    if not any_out:
        print("Nothing to publish. Create a circle or a signet first.")


def cmd_contact(args: argparse.Namespace) -> None:
    if args.ctcmd == "add":
        key = args.key.strip()
        if key.startswith("S1+PK") or key.startswith("S2+PK"):
            ann = parse_announcement(key)
            entry = remember_contact(args.alias, ann["pk"], ann["name"], ann.get("spk", ""))
        else:
            entry = remember_contact(args.alias, key, args.alias)
        print(f"Saved {entry['alias']}  short={entry['short']}"
              + (f"  sign={entry['sshort']}" if entry.get("spk") else "  (no signing key: cannot verify S2S)"))
    elif args.ctcmd == "list":
        book = load_contacts().get("contacts", {})
        seen = set()
        for entry in book.values():
            if entry["short"] in seen:
                continue
            seen.add(entry["short"])
            print(f"  {entry['short']:6}  {entry['alias']:16}  {entry.get('name_hint','')}")
        if not seen:
            print("No contacts.")


def cmd_backup(args: argparse.Namespace) -> None:
    pw = args.passphrase or _prompt_secret("Backup passphrase")
    print(wrap_backup(pw))


def cmd_restore(args: argparse.Namespace) -> None:
    pw = args.passphrase or _prompt_secret("Backup passphrase")
    blob = unwrap_backup(args.token, pw)
    for rec in blob.get("circles", []):
        save_json(circle_path(rec["name"]), rec)
        print(f"restored circle {rec['name']}")
    for rec in blob.get("signets", []):
        save_json(signet_path(rec["name"]), rec)
        print(f"restored signet {rec['name']}")
    contacts = blob.get("contacts")
    if contacts:
        save_json(contacts_path(), contacts)
        print("restored contacts")


def cmd_seal(args: argparse.Namespace) -> None:
    msg = args.message
    if not msg:
        msg = sys.stdin.read()
    if not msg:
        raise SystemExit("No message given.")
    if args.circle and args.to:
        raise SystemExit("Use either --circle or --to, not both.")
    wire = (args.wire or DEFAULT_WIRE).upper()
    if wire not in ("S1", "S2"):
        raise SystemExit(f"Unknown wire format '{wire}'. Use S2 (default) or S1.")
    if args.sign and (not args.circle or wire != "S2"):
        raise SystemExit("--sign needs --circle and the S2 wire (it emits S2S).")
    try:
        if args.circle and args.sign:
            signets = list_signets()
            if not signets:
                raise SystemExit("Create a local signet first: sigil signet new YourName")
            local = load_signet(args.from_signet) if args.from_signet else signets[0]
            lines = seal_circle_signed_s2(load_circle(args.circle), local, msg, sender=args.sender,
                                          max_line=args.max_line, compact=args.compact)
        elif args.circle:
            circle = load_circle(args.circle)
            if wire == "S2":
                lines = seal_circle_s2(circle, msg, sender=args.sender, max_line=args.max_line,
                                       compact=args.compact)
            else:
                lines = seal_circle(circle, msg, sender=args.sender or "anon", max_line=args.max_line,
                                    compact=args.compact)
        elif args.to:
            signets = list_signets()
            if not signets:
                raise SystemExit("Create a local signet first: sigil signet new YourName")
            local = load_signet(args.from_signet) if args.from_signet else signets[0]
            contact = find_contact(args.to)
            if wire == "S2":
                lines = seal_to_signet_s2(local, contact, msg, ephemeral=args.ephemeral,
                                          max_line=args.max_line, compact=args.compact, sender=args.sender)
            else:
                lines = seal_to_signet(local, contact, msg, ephemeral=args.ephemeral,
                                       max_line=args.max_line, compact=args.compact)
        else:
            raise SystemExit("Specify --circle NAME or --to CONTACT")
    except ValueError as e:
        raise SystemExit(str(e))
    for line in lines:
        print(line)
        if len(line) > args.max_line:
            print(f"# warning: line length {len(line)} exceeds --max-line {args.max_line}", file=sys.stderr)


def _open_meta(r: dict, tail: str) -> str:
    meta = f"[{r['mode']}"
    if r["mode"] in ("circle", "signed"):
        meta += f" {r['circle']}"
        try:
            fp = load_circle(r["circle"])["fingerprint"]
            meta += f" fp={fp} {speak_fingerprint(fp)}"
        except (Exception, SystemExit):
            pass
    else:
        meta += f" {r.get('from','?')} -> {r.get('to','?')}"
    if r.get("sender"):
        # S2 sender field: authenticated as "written by a key holder". In a
        # circle any member can claim any name; only S2K/S1K prove identity.
        note = {"circle": " (circle member claim)", "ephemeral": " (unverified claim)",
                "signed": " (claimed name; see signer)"}.get(r["mode"], "")
        meta += f" sender={r['sender']}{note}"
    return f"{meta} {tail}]"


def assemble_messages(opened: list[dict]) -> list[dict]:
    """
    Group opened parts into messages, in first-seen order. Each entry:
    {"complete": bool, "n": int, "version": 1|2, "parts": [results by index],
     "missing": [indexes], "text": stitched text or None}.
    S2 parts are grouped by their authenticated message id, so parts of two
    different messages never combine. A replayed duplicate part is ignored.
    S2S (mode "signed") messages are verified once complete and also carry
    {"signed": True, "verified", "signer", "signer_fp", "keyid", "error"};
    their "text" is None unless the signature verified under a known key.
    Each single-line S2S token is its own message.
    """
    groups: dict[tuple, dict] = {}
    for seq, r in enumerate(opened):
        i, n = 1, 1
        part = r.get("part") or "1/1"
        if "/" in part:
            a, b = part.split("/", 1)
            if a.isdigit() and b.isdigit():
                i, n = int(a), int(b)
        version = r.get("version", 1)
        key = (version, r.get("mode"), r.get("circle"), r.get("to"), r.get("from"), r.get("mid"), n)
        if r.get("mode") == "signed" and n == 1:
            key += (seq,)
        g = groups.setdefault(key, {"n": n, "version": version, "by_index": {}, "all": []})
        g["by_index"].setdefault(i, r)
        g["all"].append(r)
    out = []
    for g in groups.values():
        n, by_index = g["n"], g["by_index"]
        missing = [i for i in range(1, n + 1) if i not in by_index]
        complete = not missing and set(by_index) == set(range(1, n + 1))
        ordered = [by_index[i] for i in sorted(by_index)]
        text = None
        if complete:
            if g["version"] == 2:
                text = stitch_parts([(r["plaintext"], r["codebook"], r["join"]) for r in ordered])
            else:
                text = stitch_parts([(r["plaintext"], bool(r.get("codebook"))) for r in ordered])
        m = {"complete": complete, "n": n, "version": g["version"], "parts": ordered,
             "all": g["all"], "missing": missing, "text": text}
        if ordered and ordered[0].get("mode") == "signed":
            m["signed"] = True
            m.update({"verified": False, "signer": None, "signer_fp": None, "keyid": None, "error": None})
            if complete:
                m.update(s2s_verify(ordered))
                if not m["verified"]:
                    m["text"] = None
        out.append(m)
    return out


def cmd_open(args: argparse.Namespace) -> None:
    text = args.text if args.text else sys.stdin.read()
    if not text:
        raise SystemExit("No ciphertext given.")
    results = open_messages(text)
    opened = [r for r in results if r.get("ok")]
    failed = [r for r in results if not r.get("ok")]
    if not opened and not failed:
        raise SystemExit("Nothing to open.")
    messages = assemble_messages(opened)
    # S2S: print only verified messages, never unverified parts.
    for m in messages:
        if not m.get("signed"):
            continue
        if not m["complete"]:
            have = ",".join(r["part"].split("/")[0] for r in m["parts"])
            print(f"# incomplete S2S message {m['parts'][0]['mid']}: have part(s) {have} of {m['n']}",
                  file=sys.stderr)
        elif not m["verified"]:
            print(f"# S2S message NOT shown: {m['error']}", file=sys.stderr)
        else:
            meta = _open_meta(m["parts"][0], f"signer={m['signer']} sfp={m['signer_fp']} {m['n']} part(s)")
            print(meta)
            print(m["text"])
            append_transcript(meta, m["text"])
    messages = [m for m in messages if not m.get("signed")]
    # Complete multi-part messages first, then single lines and stray parts.
    for m in messages:
        if m["complete"] and m["n"] > 1:
            meta = _open_meta(m["parts"][0], f"{m['n']} parts")
            print(meta)
            print(m["text"])
            append_transcript(meta, m["text"])
    for m in messages:
        if m["complete"] and m["n"] > 1:
            continue
        if not m["complete"] and m["version"] == 2:
            have = ",".join(r["part"].split("/")[0] for r in m["parts"])
            print(f"# incomplete S2 message {m['parts'][0]['mid']}: have part(s) {have} of {m['n']}",
                  file=sys.stderr)
        for r in m["all"]:
            meta = _open_meta(r, r.get("part", "1/1"))
            print(meta)
            print(r["plaintext"])
            append_transcript(meta, r["plaintext"])
    for r in failed:
        print(f"# could not open: {r.get('error')}", file=sys.stderr)
    if failed and not opened:
        sys.exit(2)


def cmd_info(_: argparse.Namespace) -> None:
    print(
        textwrap.dedent(
            f"""
            SIGIL {__version__} — seals {DEFAULT_WIRE}, opens S2 and S1. Public algorithm, secret keys.

            Modes (S2 / S1)
              S2C S1C  circle     shared passphrase, best for a friend group on one server
              S2K S1K  signet     static P-256 ECDH, compact directed whisper
              S2E S1E  ephemeral  one-time P-256 key, forward secrecy, larger header
              S2S      signed     circle message + Ed25519 signature over the whole message

            S2 adds an authenticated frame header: codebook flag, exact
            rejoin flag, i/n, 48-bit message id (multi-part only), and an
            optional sender name sealed inside part 1. `seal --wire S1`
            (or SIGIL_WIRE=S1) emits S1 for old peers.

            Primitives
              Circle key   PBKDF2-HMAC-SHA256, {PBKDF2_ITERS} iterations
              Directed key ECDH P-256 + HKDF-SHA256
              Signature    Ed25519 (S2S), over every header and part plaintext
              Seal         AES-256-GCM, 96-bit random nonce, AAD binds context
              Encoding     unpadded URL-safe base64 (A-Za-z0-9-_)

            Minecraft chat budget (256 characters), raw UTF-8 bytes per line
                   one line   each part of a longer message
              S2C  {s2_capacity('C'):>5}      {s2_capacity('C', multi=True)}
              S2K  {s2_capacity('K'):>5}      {s2_capacity('K', multi=True)}
              S2E  {s2_capacity('E'):>5}      {s2_capacity('E', multi=True)}
              S2S  {s2_capacity('S'):>5}      {s2_capacity('C', multi=True)} (last part {s2_capacity('S', multi=True)}: 72 B keyid+signature)
              S1 carries a few bytes less per line (python3 tools/capacity.py).
            Longer messages split into i/n fragments (S2: at most {S2_MAX_PARTS}).
            A whisper spends part of the 256 on "/msg <name> ": pass --max-line.

            What observers see
              A short token like S2C.deep.AIyA...  They learn that a SIGIL
              message exists, which circle slug it belongs to, and nothing
              about the plaintext. They cannot forge a valid token without
              the key (GCM tag).

            Lexicon
              v2 sha256 {lexicon_hash()}

            What this is not
              Not a Minecraft mod. Not anonymous. Not post-quantum.
              Not a substitute for Signal when you control the channel.
              It is a way to use a channel you do NOT control.
            """
        ).strip()
    )


def main(argv: Optional[list[str]] = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.cmd == "circle":
        cmd_circle(args)
    elif args.cmd == "signet":
        cmd_signet(args)
    elif args.cmd == "fingerprint":
        cmd_fingerprint(args)
    elif args.cmd == "publish":
        cmd_publish(args)
    elif args.cmd == "contact":
        cmd_contact(args)
    elif args.cmd == "seal":
        cmd_seal(args)
    elif args.cmd == "open":
        cmd_open(args)
    elif args.cmd == "backup":
        cmd_backup(args)
    elif args.cmd == "restore":
        cmd_restore(args)
    elif args.cmd == "info":
        cmd_info(args)
    elif args.cmd == "compact":
        cmd_compact(args)
    elif args.cmd == "selftest":
        cmd_selftest()
    else:
        parser.print_help()


def cmd_compact(args: argparse.Namespace) -> None:
    msg = args.message if args.message else sys.stdin.read()
    if not msg:
        raise SystemExit("No message given.")
    raw = msg.encode("utf-8")
    packed = codebook.compress(msg)
    back = codebook.expand(packed)
    print(f"plain     {len(raw)} bytes")
    print(f"codebook  {len(packed)} bytes  ({100*len(packed)/max(1,len(raw)):.0f}%)  v2")
    print(f"words     {codebook.WORD_COUNT_V2}")
    if back.lower() != msg.lower() and back != msg:
        print("round-trip differs (usually case-fold on dictionary words):")
        print(back)


def cmd_selftest() -> None:
    """Round-trip without touching the user keyring."""
    import tempfile

    global HOME
    saved = HOME
    try:
        with tempfile.TemporaryDirectory() as td:
            HOME = Path(td)
            circle_create("deepcave", "molten copper 4")
            lines = seal_circle(load_circle("deepcave"), "portal at 1847 12 -320")
            got = open_line(lines[0])
            assert got["plaintext"] == "portal at 1847 12 -320", got
            steve = signet_create("Steve")
            alex = signet_create("Alex")
            remember_contact("Alex", alex["pk"], "Alex")
            remember_contact("Steve", steve["pk"], "Steve")
            klines = seal_to_signet(steve, find_contact("Alex"), "don't sell the elytra")
            kgot = open_line(klines[0])
            assert kgot["plaintext"] == "don't sell the elytra", kgot
            elines = seal_to_signet(steve, find_contact("Alex"), "one time", ephemeral=True)
            egot = open_line(elines[0])
            assert egot["plaintext"] == "one time", egot
            buried = open_line(f"check this tome {lines[0]} please")
            assert buried["plaintext"] == "portal at 1847 12 -320"
            zlines = seal_circle(
                load_circle("deepcave"),
                "nether roof stash at 0 128 0",
                compact=True,
            )
            assert ".z." in zlines[0], zlines[0]
            zgot = open_line(zlines[0])
            assert zgot["plaintext"] == "nether roof stash at 0 128 0", zgot
            spoken = speak_fingerprint(load_circle("deepcave")["fingerprint"])
            assert len(spoken.split()) == 2
            phrase = dice_phrase(5)
            assert len(phrase.split()) == 5
            # S2: circle raw + compact multi-part with a mid-word cut, sender, K, E.
            s2 = seal_circle_s2(load_circle("deepcave"), "portal at 1847 12 -320", sender="Steve")
            s2got = open_line(s2[0])
            assert s2got["plaintext"] == "portal at 1847 12 -320" and s2got["sender"] == "Steve", s2got
            long_msg = "/".join(["stash", "portal", "diamond", "nether", "roof"] * 30)
            zl = seal_circle_s2(load_circle("deepcave"), long_msg, compact=True)
            zr = [open_line(x) for x in zl]
            assert len(zl) > 1 and all(r["codebook"] for r in zr), zr
            assert stitch_parts([(r["plaintext"], r["codebook"], r["join"]) for r in zr]) == long_msg
            k2 = open_line(seal_to_signet_s2(steve, find_contact("Alex"), "don't sell the elytra")[0])
            assert k2["plaintext"] == "don't sell the elytra" and k2["version"] == 2, k2
            e2 = open_line(seal_to_signet_s2(steve, find_contact("Alex"), "one time", ephemeral=True)[0])
            assert e2["plaintext"] == "one time", e2
            # S2S: signed circle message, single and multi-part, verified; impersonation fails.
            remember_contact("Steve", steve["pk"], "Steve", steve["sign_pk"])
            deep = load_circle("deepcave")
            for text in ("portal at 1847 12 -320", "abcdefghij " * 40):
                sl = seal_circle_signed_s2(deep, steve, text.strip(), sender="Steve", compact=True)
                assert all(x.startswith("S2S.") for x in sl), sl
                msgs = assemble_messages([open_line(x) for x in sl])
                assert len(msgs) == 1 and msgs[0]["verified"] and msgs[0]["signer"] in ("Steve",), msgs[0]
                assert msgs[0]["text"].lower() == text.strip().lower(), msgs[0]["text"]
            mallory = signet_record("Mallory", ec.generate_private_key(ec.SECP256R1()),
                                    ed25519.Ed25519PrivateKey.generate())
            forged = assemble_messages([open_line(x) for x in seal_circle_signed_s2(deep, mallory, "I am Steve",
                                                                                    sender="Steve")])
            assert not forged[0]["verified"] and forged[0]["text"] is None, forged[0]
            token = wrap_backup("backup pass 99")
            assert token.startswith("S1B.")
            restored = unwrap_backup(token, "backup pass 99")
            assert restored["circles"][0]["name"] == "deepcave"
        print("selftest ok")
        print("  circle  S1C")
        print("  signet  S1K")
        print("  eph     S1E")
        print("  S2      S2C (raw, compact i/n, sender) / S2K / S2E")
        print("  S2S     signed circle (Ed25519), unknown signer refused")
        print("  chatter embedding")
        print("  codebook compact")
        print("  speak / dice / backup")
    finally:
        HOME = saved


if __name__ == "__main__":
    main()
