# Changelog

## 0.5.0

- **S2S signed circle messages** (`S2S.<slug>.<blob>`): S2C confidentiality plus an
  Ed25519 (RFC 8032) signature by the sender's signet over the whole message: every part's
  header and plaintext, the part count, the message id and the circle. The last part ends with
  a 72-byte trailer (`keyid(8) || sig(64)`). The sealer adds a trailer-only part if the text
  fills the last line. One line carries 84 B in chat and 67 B in a 234-char whisper
  (S2C: 156 / 139). A message costs at most one extra line. Spec: README "S2S: signed circle
  messages".
- Signets get an Ed25519 signing key (`sign_pk`, `sign_sk_pem`). They announce
  `S2+PK.<name>.<short>.<pk33>.<spk32>`. `S1+PK` is still accepted. `sigil signet upgrade NAME`
  adds a signing key to an older signet. `sigil fingerprint` prints P-256 and Ed25519
  fingerprints (`base64url(SHA-256(key))`).
- `sigil seal -c CIRCLE --sign [--from-signet NAME]`. `sigil open` shows an S2S message only
  after its signature verifies against one of your signets or contacts. Unverified or
  incomplete S2S messages are reported on stderr, and their text is never printed.
- Browser (`sigil.html`, `sigil_s2.js`): forge signets with Ed25519 where WebCrypto supports it,
  accept `S2+PK`, seal "Signed circle", verify S2S on open. Selftest includes S2S.
- Vectors: `tests/vectors/s2k.json` and `tests/vectors/s2s.json` with **public test-only
  DO-NOT-USE** deterministic signets (alice/bob/carol/mallory). They are byte-exact, including
  the signatures. Tests: `tests/test_s2s.py`, `tests/test_signed_vectors.py`, S2S interop in
  `tests/test_js_interop.py`. `tools/capacity.py` measures S2S.
- S2C, S2K, S2E and S1 are unchanged on the wire.

## 0.4.0

- **S2 wire format** (`S2C` / `S2K` / `S2E`), now the default for `sigil seal` and the browser
  tool. Same primitives and keys as S1. S2 adds an authenticated header with a codebook flag, an
  exact rejoin flag (compact fragments rejoin exactly, including mid-word cuts, with no
  heuristic), `i/n`, and a random 48-bit message id on multi-part messages, so parts of different
  messages cannot be spliced. An optional sender name is sealed inside part 1. In a circle any
  member can still claim any name; only signets prove the sender. Grammar in README
  "Wire format S2".
- S1 still opens everywhere. `sigil seal --wire S1` / `SIGIL_WIRE=S1` / the browser's
  *Wire format* selector emit S1 for older peers.
- S2 compact sends a part through the codebook only if it comes back identical up to letter
  case. Otherwise that part goes raw.
- `sigil open` groups S2 parts by message id, ignores replayed duplicate parts and reports
  incomplete messages.
- Browser: `sigil_s2.js` (seal + open S2) is included in `sigil.bundle.html`.
- `tools/capacity.py`: per-line capacity, S1 vs S2. S2C carries 156 B in one 256-char line
  (S1C 152).
- Tests: `tests/test_s2.py`, `tests/test_js_interop.py` (Node), `tests/vectors/s2c.json`
  (`tools/make_vectors.py --suite s2c`).
- Cross-language S1C test vectors: `tests/vectors/s1c.json` (public test-only
  passphrases), generator `tools/make_vectors.py`, check `tests/test_vectors.py`.
  No wire-format or crypto change.
- `sigil open`: raw (non-`.z`) fragments are stitched byte-exact. The space-restoring
  heuristic now applies only at boundaries next to a codebook-decoded part.
  No wire-format change.

## 0.3.0

- Spoken fingerprint on circle create / open (`# say: hopper gunpowder`).
- `sigil circle new --dice 5` generates a passphrase from the public lexicon.
- `sigil circle rotate` mints a successor circle when someone leaves.
- `sigil backup` / `sigil restore` wrap the keyring in AES-GCM.
- Open prints fingerprint + spoken words; appends `transcript.log`.
- `sigil info` prints lexicon v2 SHA-256.
- Browser signet and ephemeral modes; in-page selftest.
- `sigil.bundle.html` includes p256 + codebook.
- `tools/clip-seal.ps1` and `clip-open.ps1` for the Windows clipboard.

## 0.2.0

- Codebook v2, compact-by-default, fragment stitch, Windows launcher.

## 0.1.0

- S1C / S1K / S1E.
