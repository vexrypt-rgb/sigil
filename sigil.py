#!/usr/bin/env python3
"""
SIGIL — Sealed In-the-open Glyphs for Informal Links
A public-facing encryption system for open chats and whispers
(Minecraft, Discord, IRC, SMS, carrier pigeon).

Protocol version: S1
This file is both the reference implementation and the CLI.
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
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

VERSION = "S1"
PROTOCOL = "SIGIL.v1"
PBKDF2_ITERS = 210_000
NONCE_LEN = 12
TAG_LEN = 16  # AES-GCM tag, appended by AESGCM.encrypt
P256_COMPRESSED_LEN = 33

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


def signet_create(name: str) -> dict:
    sk = ec.generate_private_key(ec.SECP256R1())
    pk = sk.public_key()
    pem = sk.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
    pk_b64 = b64e(_pk_bytes(pk))
    rec = {
        "kind": "signet",
        "name": name,
        "short": short_id(_pk_bytes(pk)),
        "pk": pk_b64,
        "sk_pem": pem,
        "curve": "P-256",
        "created": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    save_json(signet_path(name), rec)
    return rec


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


def remember_contact(alias: str, pk_b64: str, name_hint: str = "") -> dict:
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


def seal_circle(circle: dict, plaintext: str, sender: str = "", max_line: int = 256) -> list[str]:
    key = derive_circle_key(circle["name"], circle["passphrase"])
    slug = circle["slug"]
    sender = sender or "anon"
    parts = _chunk_plain(plaintext, max_payload_chars=max(32, max_line - 12 - len(slug)))
    lines = []
    total = len(parts)
    for i, part in enumerate(parts, start=1):
        nonce = os.urandom(NONCE_LEN)
        # AAD binds the circle and fragment index so a token cannot be
        # spliced into another circle or replayed as a different part.
        aad = f"{PROTOCOL}.C.{circle['name']}.{i}/{total}".encode("utf-8")
        ct = AESGCM(key).encrypt(nonce, part.encode("utf-8"), aad)
        blob = b64e(nonce + ct)
        if total == 1:
            line = f"{VERSION}C.{slug}.{blob}"
        else:
            line = f"{VERSION}C.{slug}.{i}/{total}.{blob}"
        if sender and sender != "anon":
            # Optional public comment — NOT secret, just a label in the open.
            line = f"{line} #{sender}"
        lines.append(line)
    return lines


def _try_open_circle_blob(circle: dict, blob: str, index: int, total: int) -> Optional[str]:
    key = derive_circle_key(circle["name"], circle["passphrase"])
    data = b64d(blob)
    if len(data) < NONCE_LEN + TAG_LEN:
        return None
    nonce, ct = data[:NONCE_LEN], data[NONCE_LEN:]
    aad = f"{PROTOCOL}.C.{circle['name']}.{index}/{total}".encode("utf-8")
    try:
        return AESGCM(key).decrypt(nonce, ct, aad).decode("utf-8")
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
) -> list[str]:
    their_pk = _pk_from_b64(contact["pk"])
    their_short = contact["short"]
    parts_budget = max(32, max_line - 16 - len(their_short))
    if ephemeral:
        parts_budget -= 50  # compressed eph pk lives in the line
    parts = _chunk_plain(plaintext, parts_budget)
    lines = []
    total = len(parts)
    for i, part in enumerate(parts, start=1):
        nonce = os.urandom(NONCE_LEN)
        if ephemeral:
            eph = ec.generate_private_key(ec.SECP256R1())
            eph_pk = _pk_bytes(eph.public_key())
            info = f"{PROTOCOL}.E.{their_short}.{i}/{total}".encode("utf-8")
            key = ecdh_key(eph, their_pk, info)
            aad = info
            ct = AESGCM(key).encrypt(nonce, part.encode("utf-8"), aad)
            blob = b64e(eph_pk + nonce + ct)
            prefix = f"{VERSION}E.{their_short}"
        else:
            my_sk = _sk_from_pem(local["sk_pem"])
            my_pk_b = _pk_bytes(my_sk.public_key())
            their_pk_b = _pk_bytes(their_pk)
            # Direction-bind so Alice→Bob and Bob→Alice keys differ.
            info = f"{PROTOCOL}.K.{local['short']}.{their_short}.{i}/{total}".encode("utf-8")
            # Include both public keys in HKDF info via the shorts + raw concat.
            key = ecdh_key(my_sk, their_pk, info + my_pk_b + their_pk_b)
            aad = info
            ct = AESGCM(key).encrypt(nonce, part.encode("utf-8"), aad)
            blob = b64e(nonce + ct)
            prefix = f"{VERSION}K.{their_short}.{local['short']}"
        if total == 1:
            lines.append(f"{prefix}.{blob}")
        else:
            lines.append(f"{prefix}.{i}/{total}.{blob}")
    return lines


def open_line(line: str) -> dict:
    """
    Attempt to decrypt a single SIGIL line against the local keyring.
    Returns a dict with plaintext plus metadata, or raises ValueError.
    """
    raw = line.strip()
    # Allow wrapping like: [Sigil] S1C.xxxx.yyyy
    for token in raw.replace(",", " ").split():
        if token.startswith("S1C.") or token.startswith("S1K.") or token.startswith("S1E."):
            raw = token
            break
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

    if kind == "C":
        if not mid:
            raise ValueError("Circle message missing slug.")
        slug = mid[0]
        last_err = None
        for circle in list_circles():
            if circle["slug"] != slug and circle["name"].lower() != slug:
                continue
            pt = _try_open_circle_blob(circle, blob, frag_i, frag_n)
            if pt is not None:
                return {
                    "ok": True,
                    "mode": "circle",
                    "circle": circle["name"],
                    "slug": circle["slug"],
                    "part": f"{frag_i}/{frag_n}",
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
        info = f"{PROTOCOL}.K.{from_short}.{to_short}.{frag_i}/{frag_n}".encode("utf-8")
        key = ecdh_key(my_sk, their_pk, info + their_pk_b + my_pk_b)
        data = b64d(blob)
        nonce, ct = data[:NONCE_LEN], data[NONCE_LEN:]
        pt = AESGCM(key).decrypt(nonce, ct, info).decode("utf-8")
        return {
            "ok": True,
            "mode": "signet",
            "to": local["name"],
            "from": contact.get("name_hint", from_short),
            "part": f"{frag_i}/{frag_n}",
            "plaintext": pt,
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
        info = f"{PROTOCOL}.E.{to_short}.{frag_i}/{frag_n}".encode("utf-8")
        key = ecdh_key(my_sk, eph_pk, info)
        pt = AESGCM(key).decrypt(nonce, ct, info).decode("utf-8")
        return {
            "ok": True,
            "mode": "ephemeral",
            "to": local["name"],
            "from": "ephemeral-sender",
            "part": f"{frag_i}/{frag_n}",
            "plaintext": pt,
        }

    raise ValueError(f"Unknown SIGIL kind '{kind}'.")


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
    return f"S1+PK.{signet['name'].replace('.', '_')}.{signet['short']}.{signet['pk']}"


def parse_announcement(line: str) -> dict:
    raw = line.strip()
    for token in raw.replace(",", " ").split():
        if token.startswith("S1+"):
            raw = token
            break
    parts = raw.split(".")
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
    n.add_argument("--note", default="")
    csub.add_parser("list", help="List local circles")
    sh = csub.add_parser("show", help="Show circle announcement to paste in chat")
    sh.add_argument("name")

    s = sub.add_parser("signet", help="Manage your public-key identity")
    ssub = s.add_subparsers(dest="scmd", required=True)
    sn = ssub.add_parser("new", help="Create a signet")
    sn.add_argument("name")
    ssub.add_parser("list")
    ss = ssub.add_parser("show")
    ss.add_argument("name")

    pub = sub.add_parser("publish", help="Print every public announcement you can paste")

    ct = sub.add_parser("contact", help="Other people's public signets")
    ctsub = ct.add_subparsers(dest="ctcmd", required=True)
    add = ctsub.add_parser("add")
    add.add_argument("alias")
    add.add_argument("key", help="S1+PK announcement or raw public key")
    ctsub.add_parser("list")

    seal = sub.add_parser("seal", help="Encrypt a message")
    seal.add_argument("message", nargs="?", help="Message text (or stdin)")
    seal.add_argument("-c", "--circle", help="Circle name")
    seal.add_argument("-to", "--to", help="Contact alias or short-id")
    seal.add_argument("-from", "--sender", default="", help="Alias bound into circle AAD")
    seal.add_argument("--from-signet", default="", help="Which local signet to send as (signet mode)")
    seal.add_argument("--ephemeral", action="store_true", help="Use a one-time key (S1E, forward secrecy)")
    seal.add_argument("--max-line", type=int, default=256, help="Channel character limit (Minecraft=256)")

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
        pw = args.passphrase or _prompt_secret("Circle passphrase")
        rec = circle_create(args.name, pw, args.note)
        print(f"Circle '{rec['name']}' created.")
        print(f"  slug         {rec['slug']}")
        print(f"  fingerprint  {rec['fingerprint']}")
        print("Paste this once so friends know the circle exists:")
        print(announce_circle(rec))
        print("Share the passphrase out-of-band (voice, whisper, paper). Never in public chat.")
    elif args.ccmd == "list":
        rows = list_circles()
        if not rows:
            print("No circles yet.")
            return
        for rec in rows:
            print(f"  {rec['slug']:6}  {rec['name']:20}  fp={rec['fingerprint']}  {rec['created']}")
    elif args.ccmd == "show":
        rec = load_circle(args.name)
        print(announce_circle(rec))


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
            print(f"  {rec['short']:6}  {rec['name']:20}  {rec['created']}")
    elif args.scmd == "show":
        rec = load_signet(args.name)
        print(announce_signet(rec))


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
        if key.startswith("S1+PK"):
            ann = parse_announcement(key)
            entry = remember_contact(args.alias, ann["pk"], ann["name"])
        else:
            entry = remember_contact(args.alias, key, args.alias)
        print(f"Saved {entry['alias']}  short={entry['short']}")
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


def cmd_seal(args: argparse.Namespace) -> None:
    msg = args.message
    if not msg:
        msg = sys.stdin.read()
    if not msg:
        raise SystemExit("No message given.")
    if args.circle and args.to:
        raise SystemExit("Use either --circle or --to, not both.")
    if args.circle:
        circle = load_circle(args.circle)
        lines = seal_circle(circle, msg, sender=args.sender or "anon", max_line=args.max_line)
    elif args.to:
        signets = list_signets()
        if not signets:
            raise SystemExit("Create a local signet first: sigil signet new YourName")
        local = load_signet(args.from_signet) if args.from_signet else signets[0]
        contact = find_contact(args.to)
        lines = seal_to_signet(local, contact, msg, ephemeral=args.ephemeral, max_line=args.max_line)
    else:
        raise SystemExit("Specify --circle NAME or --to CONTACT")
    for line in lines:
        print(line)
        if len(line) > args.max_line:
            print(f"# warning: line length {len(line)} exceeds --max-line {args.max_line}", file=sys.stderr)


def cmd_open(args: argparse.Namespace) -> None:
    text = args.text if args.text else sys.stdin.read()
    if not text:
        raise SystemExit("No ciphertext given.")
    results = open_messages(text)
    opened = [r for r in results if r.get("ok")]
    failed = [r for r in results if not r.get("ok")]
    if not opened and not failed:
        raise SystemExit("Nothing to open.")
    for r in opened:
        meta = f"[{r['mode']}"
        if r["mode"] == "circle":
            meta += f" {r['circle']}"
        else:
            meta += f" {r.get('from','?')} -> {r.get('to','?')}"
        meta += f" {r.get('part','1/1')}]"
        print(meta)
        print(r["plaintext"])
    for r in failed:
        print(f"# could not open: {r.get('error')}", file=sys.stderr)
    if failed and not opened:
        sys.exit(2)


def cmd_info(_: argparse.Namespace) -> None:
    print(
        textwrap.dedent(
            f"""
            SIGIL protocol {VERSION} — public algorithm, secret keys.

            Modes
              S1C  circle     shared passphrase, best for a friend group on one server
              S1K  signet     static P-256 ECDH, compact directed whisper
              S1E  ephemeral  one-time P-256 key, forward secrecy, larger header

            Primitives
              Circle key   PBKDF2-HMAC-SHA256, {PBKDF2_ITERS} iterations
              Directed key ECDH P-256 + HKDF-SHA256
              Seal         AES-256-GCM, 96-bit random nonce, AAD binds context
              Encoding     unpadded URL-safe base64 (A-Za-z0-9-_)

            Minecraft chat budget (256 characters, one line)
              S1C  ~{capacity('C')} bytes of plaintext
              S1K  ~{capacity('K')} bytes of plaintext
              S1E  ~{capacity('E')} bytes of plaintext
            Longer messages automatically split as i/n fragments.

            What observers see
              A short token like S1C.deep.v3k1...  They learn that a SIGIL
              message exists, which circle slug it belongs to, and nothing
              about the plaintext. They cannot forge a valid token without
              the key (GCM tag).

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
    elif args.cmd == "publish":
        cmd_publish(args)
    elif args.cmd == "contact":
        cmd_contact(args)
    elif args.cmd == "seal":
        cmd_seal(args)
    elif args.cmd == "open":
        cmd_open(args)
    elif args.cmd == "info":
        cmd_info(args)
    elif args.cmd == "selftest":
        cmd_selftest()
    else:
        parser.print_help()


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
        print("selftest ok")
        print("  circle  S1C")
        print("  signet  S1K")
        print("  eph     S1E")
        print("  chatter embedding")
    finally:
        HOME = saved


if __name__ == "__main__":
    main()
