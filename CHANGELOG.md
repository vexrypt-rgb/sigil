# Changelog

## Unreleased

- Cross-language S1C test vectors: `tests/vectors/s1c.json` (public test-only
  passphrases), generator `tools/make_vectors.py`, check `tests/test_vectors.py`.
  No wire-format or crypto change.

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
