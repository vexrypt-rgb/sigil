# Changelog

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
