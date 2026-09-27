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

The protocol spec (S2 / S2S / S1 grammar, keys, threats, CLI) is unchanged
in this pass. Keep reading below.
