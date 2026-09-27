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

Repo: https://github.com/vexrypt-rgb/sigil

Windows: run `sigil.cmd` from this folder. Keys go to
`%USERPROFILE%\.sigil`. Double-click `sigil.bundle.html` to seal
without Python. Never commit a keyring.

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

## Wire format S2 (default since 0.4.0)

S2 keeps the S1 primitives and keys (same circle key, same signets, same
keyrings) and changes only the framing. It adds four things:

- **Exact rejoin.** Each fragment says, authenticated, whether one space
  was consumed at its end. Compact multi-part messages rejoin exactly,
  including fragments cut mid-word. No heuristic.
- **Message id.** Every fragment of a multi-part message carries a random
  48-bit id, bound into the AAD with `i/n`. Parts of different messages
  cannot be spliced together.
- **Authenticated sender.** An optional sender name is sealed *inside* part 1,
  instead of a loose ` #name` suffix.
- **Strict flags.** Codebook use, `i/n`, message id and sender presence all
  sit in one header byte (plus part byte and id) that is part of the AAD.
  There is no lenient fallback like S1's `.z` retry.

### Token grammar

```
token      = "S2" mode "." route "." blob
mode       = "C" | "K" | "E" | "S"             ; S since 0.5.0
route      = slug                              ; modes C and S: 4 chars [a-z0-9]
           | to_short "." from_short           ; mode K: 4 chars each
           | to_short                          ; mode E
blob       = base64url, no padding, of frame   ; alphabet A-Z a-z 0-9 - _
frame      = header [eph] nonce ciphertext tag
header     = flags [part mid]                  ; part and mid present iff flags.M
flags      = 1 byte
               0x01 Z  body is a codebook v2 stream (else UTF-8)
               0x02 J  rejoin: exactly one U+0020 follows this part's text
               0x04 M  multi-part: part + mid follow
               0x08 S  plaintext starts with a sender field
               0xF0    reserved, MUST be 0 (reject otherwise)
part       = 1 byte: (i - 1) << 4 | (n - 1)    ; 2 <= n <= 16, 1 <= i <= n
mid        = 6 random bytes, identical in every part of one message
eph        = 33-byte compressed P-256 point     ; mode E only, fresh per part
nonce      = 12 random bytes
ciphertext, tag = AES-256-GCM(key, nonce, plaintext, aad), 16-byte tag
plaintext  = [slen sender] body                ; sender iff flags.S
slen       = 1 byte, 1..32 ; sender = slen bytes of UTF-8
body       = codebook v2 stream starting 0xC2 (iff Z) | UTF-8 text
```

Single-line messages have `M = 0` and no part byte and no id. The header is
then just the flags byte. There is nothing to splice, and `M` is in the AAD,
so a single-line frame and a fragment can never be swapped for each other.

Decoders MUST reject: reserved bits set; `M` with `n < 2` or `i > n`; `J` on
the last part (`i = n`, including single-line); `S` on a part other than 1;
a `Z` body that does not start with `0xC2`; a sender field with `slen` outside
1..32 or longer than the plaintext; invalid UTF-8.

### Keys, context and AAD

```
C:  key = PBKDF2-HMAC-SHA256(passphrase,
                             SHA-256("SIGIL.v1.circle.salt." || name)[0:16],
                             210000, 32)                     ; same key as S1
    ctx = "SIGIL.v2.C." || circle_name
S:  key = the circle key above
    ctx = "SIGIL.v2.S." || circle_name          ; never valid as C, and vice versa
K:  ctx = "SIGIL.v2.K." || from_short || "." || to_short
    key = HKDF-SHA256(ikm = ECDH(from_sk, to_pk), salt = none (32 zero bytes),
                      info = ctx || from_pk33 || to_pk33, L = 32)
E:  ctx = "SIGIL.v2.E." || to_short
    key = HKDF-SHA256(ikm = ECDH(eph_sk, to_pk), salt = none,
                      info = ctx || eph_pk33 || to_pk33, L = 32)

aad = header || UTF-8(ctx)                  ; header = the exact header bytes sent
```

`*_pk33` are compressed SEC1 points. The S2K key covers a whole direction and
does not change per part; each part still gets its own random nonce. An S1 AAD
starts with `S` (0x53). An S2 AAD starts with a flags byte of at most 0x0F. So
an S1 blob never verifies as S2, even under the same circle key.

### Rejoining

Open every line, drop duplicates, and group by (mode, route, `mid`, `n`). A
group is complete when it holds every `i` in 1..n. Then:

```
message = text_1 + (" " if J_1) + text_2 + (" " if J_2) + ... + text_n
```

where `text_i` is the body after the sender field, codebook-expanded if `Z`.
Only part 1 may carry the sender.

### What the sender field proves

In **S2C** the sender name proves only that *someone holding the circle
passphrase* wrote it. Any circle member can claim any name, and so can a
former member who kept the passphrase. It stops outsiders and chat relays
from editing or forging the name. It does not tell circle members apart.
Two modes give real per-sender authentication:

- **S2K (and S1K)**: the key is bound to the sender's static signet, pairwise.
  Only the two ends can produce the frame. Zero bytes of overhead, but
  one message per recipient.
- **S2S (0.5.0)**: circle confidentiality plus an Ed25519 signature by the
  sender's signet over the whole message. One message for the whole circle,
  72 bytes of overhead. Who signed is shown next to the text. The sealed
  sender name is still only a claim; trust the *signer*.

In **S2E** the name is an unverified claim, because anyone with the
recipient's public key can seal one.

### S2S: signed circle messages (0.5.0)

S2S is S2C plus a signature. The frames, flags, splitting and rejoin rules
are exactly S2C's, with mode `S` and context `SIGIL.v2.S.<circle_name>`. The
last part's plaintext ends with a fixed 72-byte trailer:

```
last-part plaintext = [slen sender] body || keyid || sig
keyid     = SHA-256(spk)[0:8]                  ; spk = 32-byte Ed25519 public key
sig       = Ed25519(sign_sk, signed_bytes)     ; RFC 8032, pure Ed25519, 64 bytes
signed_bytes =
      "SIGIL.v2.sig" 0x00
   || u16(len ctx) || ctx                      ; binds the circle
   || keyid
   || u8(n)                                    ; binds the part count
   || for i in 1..n:
        u8(len header_i) || header_i           ; flags, part byte, message id
     || u16(len pt_i)    || pt_i               ; exact part plaintext, trailer removed
                                               ; (sender field + body, packed if Z)
```

All lengths are big-endian. One signature covers every part, every header
(so `i/n`, `J`, `Z` and the 48-bit message id) and the circle. A single-line
message has no message id, and there is nothing to splice.

**Signing keys.** A 0.5.0 signet holds an Ed25519 key next to its P-256 key
(`sign_pk`, `sign_sk_pem` in `signet-*.json`). It is announced as

```
S2+PK.<name>.<short>.<pk33>.<spk32>          ; pk33 P-256 compressed, spk32 Ed25519, both base64url
```

`S1+PK` is still accepted (a contact without a signing key). The signing key
fingerprint is `base64url(SHA-256(spk))` (43 chars; `sigil fingerprint`,
`sigil signet list`). Compare it out of band like any other key.

**Sealer.** The sealer reserves 72 bytes in the last line. If the text fills
the last line, or the message fits one line but not with the trailer, the
sealer appends a trailer-only part (empty body, `Z = 0`). That part counts
toward the 16-part limit.

**Decoders MUST:** apply every S2C rule; reject a last part whose plaintext
is shorter than 72 bytes; rebuild `signed_bytes` from the parts they
actually opened; show the text only if the signature verifies under a
key whose key id matches and which the reader pinned for a named
contact (or their own signet); never show text from an incomplete S2S
message or from one with an unknown key id or a bad signature. The key id
is a hint for picking the key. It is not a trust decision.

**What S2S proves:** that the holder of that Ed25519 key wrote exactly this
message (all parts, in this order) for this circle. Circle members cannot
forge or alter it, and cannot reuse a part in another message. The
signature is transferable within the circle: anyone who can open it can show
others it was signed.

**What S2S does not prove:** freshness. A captured S2S message can be
pasted again (keep a replay window above SIGIL if that matters). A circle
member can also inject a garbage part with the same message id first. The
message then fails to verify (denial of service, never forgery). The
signer's name is visible only inside the circle; outsiders see an S2C-sized
token with mode `S`.

**Line cost.** The trailer is 72 bytes (96 base64 chars). One line holds 84 B
of text in chat (256) and 67 B in a whisper budget of 234, versus S2C's 156 /
139. A long message costs the trailer once, so it often needs one extra line
and never more than one. Measured with `python3 tools/capacity.py`:

| raw bytes | 40 | 67 | 84 | 120 | 200 | 300 | 600 |
|---|---|---|---|---|---|---|---|
| S2C / S2K lines, chat 256 | 1 | 1 | 1 | 1 | 2 | 3 | 5 |
| S2S lines, chat 256 | 1 | 1 | 1 | 2 | 2 | 3 | 5 |
| S2C / S2K lines, whisper 234 | 1 | 1 | 1 | 1 | 2 | 3 | 5 |
| S2S lines, whisper 234 | 1 | 1 | 2 | 2 | 3 | 3 | 6 |

The signature is per message, not per line. A broadcast to N readers costs
S2S one message; the S2K alternative costs N messages at zero overhead each.

### Sender-side rules (not wire format, but what `sigil.py` and `sigil.html` do)

- Fit each line exactly into `--max-line` (default 256). A frame of L bytes
  takes `ceil(4L/3)` characters.
- Compact mode cuts a fragment at a space where it can, consumes that
  space and sets `J`. Otherwise it cuts mid-word with `J = 0`.
- A part uses the codebook only if it shrinks *and* expands back to the
  same text up to letter case. Parts the codebook would reshape (double
  spaces, tokens over 16 bytes, `a,b`) go out raw. So S2 compact is exact
  except that dictionary words can come back lowercase.
- More than 16 parts is an error. Shorten the message, raise
  `--max-line`, or use `--wire S1`.

### Capacity (raw UTF-8 bytes per line, measured with `python3 tools/capacity.py`)

| | chat, 256 chars: one line | each part | whisper `/msg <16-char name> ` (234): one line | each part |
|---|---|---|---|---|
| S2C | 156 | 149 | 139 | 132 |
| S1C | 152 | 144 | 135 | 127 |
| S2K | 152 | 145 | 136 | 129 |
| S1K | 149 | 141 | 132 | 124 |
| S2E | 123 | 116 | 106 | 99 |
| S2S (last line; earlier parts = S2C) | 84 | 77 | 67 | 60 |
| S1E | 111 | 103 | 95 | 87 |

S2 carries more per line than S1 despite the new header. S1's chunker left
slack, and S2 computes its budget exactly and drops the visible `.z` and
`.i/n` fields. The 6-byte message id costs 8 characters, and only on
multi-part lines.

### Choosing the wire format

`sigil seal` emits S2. For peers on SIGIL 0.3 or older use
`sigil seal --wire S1 ...` or `export SIGIL_WIRE=S1`. `sigil open` and the
browser tool accept both. In the browser, pick "S1" under *Wire format*.

## Wire format S1 (still opened; `--wire S1` to emit)

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

See the S2 capacity table above (S1 figures included). English sits near 1 byte/char. A coordinate drop, a stash warning, a
short plan — one line. A paragraph — two or three fragments.

## Codebook compression (`--compact`)

Ciphertext cannot be dictionary-compressed: it already looks like
random bytes. Compression runs on **plaintext**, then AES-GCM seals
the packed bytes. S1 tokens that used the codebook carry a public `.z.`
flag; S2 sets the `Z` bit in the authenticated header.

```
python3 sigil.py compact "nether roof stash at 0 128 0"
python3 sigil.py seal -c deepcave "nether roof stash at 0 128 0"
# S2C.deep....     (codebook is on by default; --raw skips it)
```

v2 uses a 4096-entry frequency-ranked lexicon (`lexicon_v2.txt`):
Minecraft registry names and display names, multi-word phrases
(`nether roof`, `eye of ender`, `ruined portal`), and short operational
English. It is not a copy of any copyrighted aviation textbook.
Coords and counts are zigzag integers. The stream is bit-packed.

Typical stash chat lands around 20–40% of the original UTF-8 size
before the GCM wrapper. Dictionary words come back lowercase. v1
payloads still open; new seals emit v2.

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

AES-256-GCM, 96-bit random nonce, 128-bit tag, AAD as above (S2: header || context).
Nonce reuse under one key is astronomically unlikely (2^-96 per message)
and would be a local RNG failure, not a protocol one.

## What an observer actually learns

- That a SIGIL token was sent.
- The mode (`C` / `K` / `E` / `S`). For S2S they do not learn who signed;
  the key id and signature are inside the ciphertext.
- The circle slug or the recipient short-id.
- The approximate size of the plaintext.
- For S2 (from the unencrypted but authenticated header): whether the codebook
  was used, `i/n`, and which lines belong to the same message (the message id).
  The S2 sender name is inside the ciphertext and not visible.

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
  always pasting S2C tokens after dark."
- Replay. A captured token (or a whole multi-part message) can be pasted
  again later and still opens. Neither S1 nor S2 keeps state to catch this.
  S2S signatures do not change that.
- Impersonation inside a plain S2C circle: see "What the sender field proves".
  Use S2S or S2K when members must be told apart.
- Weak passphrases. `password1` is not a circle key. Use a diceware
  phrase.

## Tooling

### Python CLI

```
python3 sigil.py info
python3 sigil.py circle new deepcave
python3 sigil.py seal -c deepcave "portal at 1847 12 -320"
python3 sigil.py open S2C.deep....
python3 sigil.py seal -c deepcave --sender Steve "portal at 1847 12 -320"
python3 sigil.py seal -c deepcave --wire S1 "for a peer on 0.3"

python3 sigil.py signet new Steve
python3 sigil.py publish
python3 sigil.py contact add Alex S1+PK.Alex....
python3 sigil.py seal --to Alex "don't tell the admin"
python3 sigil.py seal --to Alex --ephemeral "one-time drop"

python3 sigil.py signet upgrade Steve        # add an Ed25519 key to a pre-0.5 signet
python3 sigil.py seal -c deepcave --sign "orders from Steve"   # S2S; --from-signet NAME to pick one
python3 sigil.py fingerprint                 # P-256 and Ed25519 fingerprints of your signets
```

`sigil open` prints an S2S message only after its signature verifies against
one of your signets or contacts. Otherwise it says why on stderr
(`S2S message NOT shown: ...`).

Keyring defaults to `./keys` next to the script, or `$SIGIL_HOME`.

Treat that folder like a password file.

### Browser tool

Open `sigil.html` locally. No server, no requests. Circles saved in
localStorage are enough for the common "friend group on this server"
case and interoperate with the CLI. Signets forged in a browser with
WebCrypto Ed25519 (current Chrome, Firefox and Safari) announce `S2+PK` and can
seal and verify S2S. Older browsers still get S1+PK signets.

## Interop rules

- Circle name is case-preserving in AAD and case-insensitive as a lookup
  key. Use one spelling and stick to it (`deepcave`, not `DeepCave` on
  one side and `deepcave` on the other).
- Slug is the first four `[a-z0-9]` characters of the lowercased name,
  padded with `x`. `deepcave` → `deep`. Colliding slugs are resolved by
  trying every local circle with that slug; the GCM tag picks the winner.
- UTF-8 plaintext. Newlines survive if you seal from stdin.

## Test vectors

`tests/vectors/s2k.json` (S2K) and `tests/vectors/s2s.json` (S2S) use four
deterministic signets (alice, bob, carol, mallory) whose private keys are
**published in the file on purpose. They are public test-only keys. Never
use them for anything.** They cover byte-exact seals (recorded nonces;
Ed25519 is deterministic, so the signatures are exact too), the signed
bytes, and negative cases: tampering, every-bit flips, wrong direction,
impersonation (unknown key, swapped key id), splice across messages,
dropped signature part, missing part.

`tests/vectors/s1c.json` and `tests/vectors/s2c.json` hold recorded circle
vectors for other implementations: positive (plain, unicode, codebook, `i/n`,
boundary lengths, S2 sender and mid-word rejoin), negative (tampering, wrong key,
relabelled fragments, S2 header flips, message-id splice), and for S2
message-level cases (splice, interleave, duplicate, missing part). They are
verified by `python3 -m unittest discover -s tests`, and the S2 file is also
opened by the browser code via Node (`node tests/js/sigil_node.cjs vectors
tests/vectors/s2c.json`). The passphrases in these files are **public
test-only values, not keys**. All three S2 files are also checked by the
browser code (`node tests/js/sigil_node.cjs vectors tests/vectors/s2s.json`).
See `tests/README.md`.

## License of the idea

Use it. Fork it. The construction is deliberately boring on purpose:
published primitives, no novel block cipher, no "trust this custom
S-box." Unique here means *fit for open chat*, not *invented
cryptography*.
