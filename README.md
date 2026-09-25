# SIGIL

**Sealed In-the-open Glyphs for Informal Links**

A public-facing encryption system for channels you do not control:
Minecraft public chat, Minecraft `/tell` whispers that staff can still log,
Discord, IRC, SMS, screenshots of a phone.

The algorithm is public. The keys are not. Anyone can see that a SIGIL
token went across the wire. Nobody without the matching key can read it
or forge a valid one.

## Clone and work on it

```bash
git clone git@github.com:<you>/sigil.git
cd sigil
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
export SIGIL_HOME="$PWD/.sigil-home"
python3 sigil.py selftest
```

Replace `<you>/sigil` with your empty GitHub or GitLab repo. Keep
keyrings out of git: set `SIGIL_HOME` and never add `keys/` or
`.sigil-home/`. Details are in `CONTRIBUTING.md`.

This is not a Minecraft mod. You generate a token on your machine (CLI or
the single-file browser tool) and paste it into chat. The other person
pastes it back into their copy of the tool.

---

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
| Servers filter odd punctuation | Alphabet is `A–Z a–z 0–9 - _` |
| No shared infrastructure | No key server. Circles are a passphrase. Signets are P-256 keys you announce once |
| Public algorithm | AES-256-GCM, PBKDF2-HMAC-SHA256, ECDH P-256, HKDF-SHA256 |
| Humans will paste badly | Parser accepts a token buried in other text |

## Two ways to use it

### 1. Circle — a named shared secret

Best default for a friend group on one server.

```
you (voice):  "circle deepcave, passphrase: molten copper 4"
you (chat):   S1+CIRCLE.deep.deepcave.fpk9wq
you (chat):   S1C.deep.A7x91m...
them:         sigil open S1C.deep.A7x91m...
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
       S1K.r2ab.k9wq.Qlm0...
```

`S1K` uses both static keys (compact). `S1E` uses a fresh ephemeral
sender key (forward secrecy, fatter header, less room for plaintext).

## Wire format

```
S1C.<slug>.<payload>
S1C.<slug>.<i>/<n>.<payload>          # fragments of a long message

S1K.<to_short>.<from_short>.<payload>
S1E.<to_short>.<payload>              # payload starts with compressed P-256 point

S1+CIRCLE.<slug>.<name>.fp<fingerprint>
S1+PK.<name>.<short>.<compressed_pk>
```

`payload` = `nonce (12 bytes) || ciphertext || GCM tag (16 bytes)`
encoded as unpadded URL-safe base64.

Associated data (not secret, but authenticated):

```
circle:     SIGIL.v1.C.<circle_name>.<i>/<n>
signet:     SIGIL.v1.K.<from_short>.<to_short>.<i>/<n>
ephemeral:  SIGIL.v1.E.<to_short>.<i>/<n>
```

A token minted for `deepcave` part `1/1` will not decrypt under a
different circle name and cannot be presented as part `2/3`.

## Capacity in one Minecraft line (256 chars)

Approximate UTF-8 byte budgets:

| Mode | Header cost | Plaintext that fits |
|---|---|---|
| S1C  | ~12 chars | about 160 bytes |
| S1K  | ~16 chars | about 155 bytes |
| S1E  | ~10 chars + 33-byte eph key | about 110 bytes |

English sits near 1 byte/char. A coordinate drop, a stash warning, a
short plan — one line. A paragraph — two or three fragments.

## Cryptography, stated plainly

**Circle key**

```
salt = SHA-256("SIGIL.v1.circle.salt." || name)[0:16]
key  = PBKDF2-HMAC-SHA256(passphrase, salt, 210000 iterations, 32 bytes)
```

Salt is derived from the public name so two devices do not have to
sync a random salt file. Two circles that reuse a passphrase still
diverge because the name enters the salt.

**Directed key**

```
shared = ECDH-P256(my_static_or_ephemeral, their_static)
key    = HKDF-SHA256(ikm=shared, info=direction-binding, length=32)
```

Direction-binding includes both short-ids and both public keys so
Alice→Bob and Bob→Alice are different keys.

**Seal**

AES-256-GCM, 96-bit random nonce, 128-bit tag, AAD as above.
Nonce reuse under one key is astronomically unlikely (2^-96 per message)
and would be a local RNG failure, not a protocol one.

## What an observer actually learns

- That a SIGIL token was sent.
- The mode (`C` / `K` / `E`).
- The circle slug or the recipient short-id.
- The approximate size of the plaintext.

They do not learn the plaintext. They cannot produce a different
plaintext that still verifies. They cannot take an `S1C.deep.*` token
and have it open as `S1C.neth.*`.

SIGIL does **not** hide that you are using SIGIL. If the threat is
"staff must not even know we have a side channel," this is the wrong
tool — you want steganography, and steganography that survives Minecraft
chat filters is a different project.

## Threats this does not cover

- Someone who already has the circle passphrase (including a former
  member who kept it). Rotate the passphrase; there is no ratchet in
  circle mode.
- Compromise of your `keys/` directory or this browser's localStorage.
- Quantum adversaries (P-256 and AES-256-GCM-with-Grover are the usual
  caveats).
- Traffic analysis, player-name correlation, "why are those two
  always pasting S1C tokens after dark."
- Weak passphrases. `password1` is not a circle key. Use a diceware
  phrase.

## Tooling

### Python CLI

```
python3 sigil.py info
python3 sigil.py circle new deepcave
python3 sigil.py seal -c deepcave "portal at 1847 12 -320"
python3 sigil.py open S1C.deep....

python3 sigil.py signet new Steve
python3 sigil.py publish
python3 sigil.py contact add Alex S1+PK.Alex....
python3 sigil.py seal --to Alex "don't tell the admin"
python3 sigil.py seal --to Alex --ephemeral "one-time drop"
```

Keyring defaults to `./keys` next to the script, or `$SIGIL_HOME`.

Treat that folder like a password file.

### Browser tool

Open `sigil.html` locally. No server, no requests. Circles saved in
localStorage are enough for the common "friend group on this server"
case and interoperate with the CLI.

## Interop rules

- Circle name is case-preserving in AAD and case-insensitive as a lookup
  key. Use one spelling and stick to it (`deepcave`, not `DeepCave` on
  one side and `deepcave` on the other).
- Slug is the first four `[a-z0-9]` characters of the lowercased name,
  padded with `x`. `deepcave` → `deep`. Colliding slugs are resolved by
  trying every local circle with that slug; the GCM tag picks the winner.
- UTF-8 plaintext. Newlines survive if you seal from stdin.

## License of the idea

Use it. Fork it. The construction is deliberately boring on purpose:
published primitives, no novel block cipher, no "trust this custom
S-box." Unique here means *fit for open chat*, not *invented
cryptography*.
