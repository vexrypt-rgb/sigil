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

The wire-format spec, capacity tables, cryptography, threat model, CLI,
and test-vector notes follow in this file and in [tests/README.md](tests/README.md).

## Vibe coding / AI use

Large parts of this repository were written or edited with AI assistants
(Claude, Grok, and similar). That is vibe coding: a person set the
direction; a model produced a lot of the text. A green CI run or a
commit message is not proof that a human understood every line.

Read the diff before you run or merge it. Do not treat this as audited
software. File bugs. Do not assume the model already considered your
case.
