# SIGIL tests and cross-language vectors

```
python3 sigil.py selftest                     # round-trip smoke test (S1 + S2 incl. S2S)
python3 -m unittest discover -s tests -v      # vectors, S2/S2S round-trip/tamper, JS interop (needs node)
python3 tools/make_vectors.py --suite s2s     # regenerates a vector file (s1c | s2c | s2k | s2s | all)
node tests/js/sigil_node.cjs selftest         # browser S2 code under Node (Node 20+: Ed25519 in WebCrypto)
node tests/js/sigil_node.cjs vectors tests/vectors/s2c.json   # also s2k.json, s2s.json
```

| File | What |
|---|---|
| `test_vectors.py` | `vectors/s1c.json` and `vectors/s2c.json` |
| `test_open_stitch.py` | S1 `sigil open` stitching (raw exact, codebook heuristic) |
| `test_s2.py` | S2 C/K/E: 1/2/3+ parts, exact capacity, unicode, compact exact incl. mid-word cuts, sender, 16-part limit, sender/flag/`i/n` tamper, cross-message splice, S1 compatibility, CLI `--wire` |
| `test_signed_vectors.py` | `vectors/s2k.json` and `vectors/s2s.json`: open, verify, re-derive keys / signed bytes / signatures, re-seal byte-exact, negatives |
| `test_s2s.py` | S2S: round-trip (1/2/3+ parts, compact, unicode, sender), trailer placement, tamper (every bit of a message), circle-member edits, impersonation (unknown key, swapped key id, claimed sender), splice across messages, cross-circle, signet upgrade / `S2+PK`, CLI `--sign` / `open` never prints unverified text |
| `test_js_interop.py` | Python seals → `sigil_s2.js` opens, and back, for C/K/E and S2S (incl. an unknown signer that must not be shown). Runs all S2 vector files through the JS. Keys are generated per run and passed on stdin. Skipped without `node` |

## `vectors/s1c.json`: S1C circle vectors

> **PUBLIC TEST-ONLY KEY MATERIAL.** The circle passphrases in this file
> (`sigil-public-test-vector-passphrase-DO-NOT-USE`, …) are published on
> purpose so other implementations can test against the reference. They are
> **not keys**. Never use them for real messages. Real keyrings, passphrases,
> `keys/` and `.sigil-home/` must never be committed.

What it covers:

| Group | Vectors |
|---|---|
| Plain (raw UTF-8) | short, empty, longest single line at `max_line=256`, first length that splits into `i/n`, longest single line at `max_line=180`, 3-part message |
| Unicode | mixed multi-byte / emoji / RTL / combining mark, 4-byte emoji split across parts, embedded newline |
| Codebook `.z` | compact, compact requested but no gain (no `.z`), compact 3-part, lossy case/trailing-space behaviour |
| Keyring / parser | mixed-case circle name, slug collision (two circles share `sigi`), token buried in text, ` #sender` suffix, lenient `.z` added after sealing |
| Negative (must fail) | tampered tag / ciphertext / nonce, wrong passphrase, wrong name with same slug, fragment index or total relabelled, `.z` removed, unknown slug, truncated blob, no token |

How it is produced: `tools/make_vectors.py` calls the real
`sigil.seal_circle` (normal `os.urandom` nonces) and **records** the output.
No production code path is changed, and there is no nonce hook. The nonce is
public (first 12 bytes of every blob), so each part also lists `nonce_hex`, the
exact `aad` string and `payload_hex` (the bytes that went into AES-GCM). A port
can then re-seal a part and compare the token byte-for-byte. It can also open
every line and check `parts[].plaintext`.

Regenerating produces new random nonces and therefore a different file. That is
expected. Commit a file only after `python3 -m unittest discover -s tests` passes.

Notes for implementers (current S1 behaviour, recorded rather than changed):

- `open_line` retries the non-compact AAD when a `.z` token fails. As a result a raw token with
  `.z` inserted still opens (`lenient-z-flag-added`). Removing `.z` from a compact token does not.
- Codebook v2 is lossy: dictionary words come back lowercase and trailing whitespace is dropped.
  Compact multi-part messages therefore lose the space at each part boundary. `sigil open`'s
  stitcher (`stitch_parts`) compensates by inserting a space between alphanumeric boundaries,
  but only next to a codebook-decoded part. Raw parts, which the plain chunker splits mid-word,
  are joined byte-exact (`plain-multipart-3` round-trips).
- `i/n` is bound into the AAD, but no message id is. Parts of two different messages with the same
  `n` are not cryptographically tied together. (Fixed in S2.)
- The ` #sender` suffix is outside the token and is not authenticated. (S2 seals the sender.)

## `vectors/s2c.json`: S2C circle vectors

Same format and the same **public test-only** circles as `s1c.json`, with three differences.
Each part also records `flags`, `join`, `codebook`, `sender`, `header_hex`, `mid_hex` and the
exact `aad_hex`. There is a `joined` field (the rejoined message). And there is a `messages[]`
section: open all `lines`, assemble, and exactly the listed `complete` messages may come out
(cross-message splice, interleaved messages, duplicate part, missing part).

Negatives cover tag/ciphertext/nonce flips, a flipped byte of the sealed sender name, each
header flag flipped (S, Z both ways, J, reserved), `J` on the last part, the part byte
relabelled, a fragment rewritten as a single-line frame, another message's id written into a
part, wrong passphrase/name, an S1 blob presented as S2, an unknown slug and a truncated frame.

## Public test signets (`s2k.json`, `s2s.json`)

> **PUBLIC TEST-ONLY PRIVATE KEYS. DO NOT USE.** Both files publish full private keys for four
> signets (`alice`, `bob`, `carol`, `mallory`) so other implementations can check byte-exact
> output. They are derived deterministically from the labels
> `sigil-public-test-signet-<id>-DO-NOT-USE`:
>
> - P-256 `d = SHA-256(label || "-p256") mod (n - 1) + 1`
> - Ed25519 seed `= SHA-256(label || "-ed25519")`
>
> Anyone can recompute them. A message signed by one of them proves nothing.

Each signet entry has the stored record (`sk_pem`, `sign_sk_pem`, …), `sk_hex`, a P-256 JWK, the
Ed25519 seed and JWK, fingerprints, the S2S key id and the `S2+PK` announcement.

## `vectors/s2k.json`: S2K directed vectors

`directions[]` records, per direction, the context, the ECDH x-coordinate, the HKDF info and the
derived key. Positive vectors name `from`, `to` and an `opener` (own signets and contacts). Each part has
`header_hex`, `nonce_hex`, `aad_hex` and `payload_hex`, so a port can re-seal a part byte-exact.
Negatives: tampered tag and header, the route relabelled to claim another sender, a sender
unknown to the opener, reflection (A→B presented as B→A), the wrong recipient, a token not for
this opener, a relabelled fragment, and a truncated frame.

## `vectors/s2s.json`: S2S signed circle vectors

Positive vectors record `signed_bytes_hex`, `keyid_hex` and `sig_hex`. Ed25519 is deterministic,
so a port must reproduce the signature exactly. Per part they record `payload_hex` (without the
trailer), `sealed_plaintext_hex` (with it), `aad_hex` and `nonce_hex`. Cases: short, empty, the longest single
line in chat and whisper budgets, a trailer-only extra part, the trailer inside or spilling
out of the last part, 3 parts, unicode, compact, sender field, and a sender claim that differs
from the signer.

`messages[]` are message-level checks against the listed `verifier_keys`: a circle member
flipping the signature or editing the body (`bad-signature`), impersonation with an unknown key
(`unknown-signer`) or a swapped key id (`bad-signature`), a part spliced in from another message,
a dropped signature part, a missing part (`incomplete`), no verifier keys, and a duplicate
part that must be ignored. `negative[]` lines must not open at all (tag flip, S2S↔S2C relabel,
wrong passphrase, a last part too short for its trailer, unknown slug).

S2E has no vectors (its ephemeral key is random by design). `test_s2.py` and `test_js_interop.py`
cover it.
