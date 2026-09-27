# SIGIL

**Sealed In-the-open Glyphs for Informal Links** — version **0.5.0**

A public-facing encryption system for channels you do not control:
Minecraft public chat, Minecraft `/tell` whispers that staff can still log,
Discord, IRC, SMS, screenshots of a phone.

The algorithm is public. The keys are not. Anyone can see that a SIGIL
token went across the wire. Nobody without the matching key can read it
or forge a valid one.

Current default wire format is **S2** (0.4.0). **S2S** signed circle
messages landed in 0.5.0. S1 still opens. This is not a Minecraft mod:
you generate a token on your machine and paste it into chat.

Sister projects: [Ostinato](https://github.com/vexrypt-rgb/Ostinato)
(`#swarm` uses SIGIL on the wire) and
[TenorClef](https://github.com/vexrypt-rgb/TenorClef).

## Docs

- [Minecraft walkthrough](MINECRAFT.md)
- [Windows setup](SETUP-WINDOWS.md)
- [Changelog](CHANGELOG.md)
- [Contributing](CONTRIBUTING.md)
- [Tests and vectors](tests/README.md)

## Clone and work on it

```bash
git clone git@github.com:vexrypt-rgb/sigil.git
cd sigil
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
export SIGIL_HOME="$PWD/.sigil-home"
python3 sigil.py selftest
```

Windows: run `sigil.cmd` from this folder. Keys go to
`%USERPROFILE%\.sigil`. Double-click `sigil.bundle.html` to seal
without Python. Never commit a keyring.

You generate a token on your machine (CLI or the single-file browser
tool) and paste it into chat. The other person pastes it back into their
copy of the tool.

## Why this exists

Vanilla Minecraft chat is plaintext. Staff, the server console, replay
mods, chat-report pipelines, and everyone else in the dimension can read
it. Whispers (`/msg`) are only hidden from other players, not from the
server.

Existing client mods (Opaque Chat, No Chat Reports encryption, Whisper
Mod) solve this if every participant installs the same mod on the same
loader. SIGIL is for the case where you cannot assume that: mixed
clients, a friend on mobile, a message that has to survive being copied
through three apps.

## Design constraints that made it look like this

| Constraint | Consequence |
|---|---|
| Minecraft send limit is **256 characters** | Compact header + unpadded base64url, automatic `i/n` split |
| Servers filter odd punctuation | Alphabet is `A-Z a-z 0-9 - _` |
| No shared infrastructure | No key server. Circles are a passphrase. Signets are P-256 keys you announce once |
| Public algorithm | AES-256-GCM, PBKDF2-HMAC-SHA256, ECDH P-256, HKDF-SHA256 |
| Humans will paste badly | Parser accepts a token buried in other text |

## Two ways to use it

### 1. Circle — a named shared secret

Best default for a friend group on one server.

```
you (voice):  "circle deepcave, passphrase: molten copper 4"
you (chat):   S1+CIRCLE.deep.deepcave.fpk9wq
you (chat):   S2C.deep.AIyA7x...
them:         sigil open S2C.deep.AIyA7x...
```

Same circle name + same passphrase on two devices produces the same key.
The passphrase never goes in chat.

### 2. Signet — a public key you pin to a player

Best for directed whispers when you do not want a group passphrase.

```
you:   sigil signet new Steve
you:   S1+PK.Steve.r2ab.A6bC...     (paste once, anywhere)
them:  sigil contact add Steve S1+PK.Steve.r2ab.A6bC...
them:  sigil seal --to Steve "don't sell the elytra"
       S2K.r2ab.k9wq.AEbq...
```

`S2K` uses both static keys (compact). `S2E` uses a fresh ephemeral
sender key (forward secrecy, fatter header, less room for plaintext).

### 3. Signed circle — a circle message that proves who wrote it (0.5.0)

Best when a group shares one circle but readers must know *which member*
spoke (bots in a swarm, a lead giving orders).

```
you:   sigil signet new Steve          # 0.5.0 signets also hold an Ed25519 signing key
you:   S2+PK.Steve.r2ab.A6bC....d5wa...  (paste once; older signets: sigil signet upgrade Steve)
them:  sigil contact add Steve S2+PK.Steve.r2ab....
you:   sigil seal -c deepcave --sign "lead says: regroup at spawn"
       S2S.deep.AIyA...
them:  sigil open S2S.deep.AIyA...     # shown only if Steve's signature verifies
```

Everyone in the circle can read it. Only the holder of Steve's signing key
can produce it. See "S2S: signed circle messages" below.

The rest of this file is the wire-format spec (S2, S2S, S1), capacity tables,
cryptography, threat model, CLI, and test-vector notes. See also
[MINECRAFT.md](MINECRAFT.md), [CHANGELOG.md](CHANGELOG.md), and
[tests/README.md](tests/README.md).
