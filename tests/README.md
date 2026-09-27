# SIGIL tests and cross-language vectors

```
python3 sigil.py selftest                 # round-trip smoke test (existing)
python3 -m unittest discover -s tests -v  # verifies tests/vectors/*.json
python3 tools/make_vectors.py             # regenerates tests/vectors/s1c.json
```

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
  `n` are not cryptographically tied together.
- The ` #sender` suffix is outside the token and is not authenticated.
