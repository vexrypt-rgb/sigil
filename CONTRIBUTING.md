# Working on SIGIL

## Repo layout

```
sigil.py           reference implementation + CLI
sigil.cmd          Windows launcher
sigil.html         browser sealer (needs lexicon_v2.js, codebook_v2.js, p256.js, sigil_s2.js)
sigil_s2.js        S2 wire format for the browser (keep aligned with sigil.py)
sigil.bundle.html  same tool as one file — ship this
codebook.py        codebook v1 decode + v2 encode/decode
tools/make_vectors.py  records cross-language test vectors
tests/             vector check (unittest) + tests/vectors/*.json
lexicon_v2.txt     frozen 4096-entry public word list
README.md          protocol spec (S2 grammar: "Wire format S2")
tests/             unittest suites, cross-language vectors, Node driver for the JS
tools/             bundle_html.py, make_vectors.py, capacity.py
MINECRAFT.md       in-game playbook
```

The protocol lives in `README.md`. Change the wire format only with a
version bump (`S1` → `S2`) and keep `S1` readable.

## Local setup

```bash
git clone git@github.com:<you>/sigil.git
cd sigil
python3 -m venv .venv
source .venv/bin/activate    # Windows: .venv\Scripts\activate
pip install -r requirements.txt
export SIGIL_HOME="$PWD/.sigil-home"   # keep keys out of the tree
mkdir -p "$SIGIL_HOME"
python3 sigil.py selftest
```

Do not use the default `./keys` directory inside a working copy if you
might `git add` by habit. `SIGIL_HOME` exists for that.

## Rules for changes

1. `python3 sigil.py selftest` and `python3 -m unittest discover -s tests` must stay green.
   A wire-format change must come with regenerated vectors (`tools/make_vectors.py`).
   Rebuild `sigil.bundle.html` (`python3 tools/bundle_html.py`) after touching any `.js`
   or `sigil.html`.
2. Tokens produced by `sigil.py` must still open in `sigil.html`, and the
   other way around (`tests/test_js_interop.py` checks S2 C/K/E). S1 must stay
   readable.
3. Do not add a network call. The point of the tool is that it works
   on an air-gapped copy of the files.
4. Do not store passphrases, signet PEM, or contact books in git.
5. New encoding modes get a new prefix (`S2X...`), not a silent change
   to `S2C` / `S2K` / `S2E` (or S1). A new framing gets a new version (`S3`).

## Suggested first issues

- Browser signet mode that speaks compressed P-256 on the wire
- A `sigil pack` command that wraps fragments for `/msg`
- A wordlist cover encoding that still fits 256 characters
- A ratchet for circle mode (this is an S2 conversation)
