# Working on SIGIL

## Repo layout

```
sigil.py           reference implementation + CLI
sigil.cmd          Windows launcher
sigil.html         browser sealer (needs lexicon_v2.js + codebook_v2.js)
sigil.bundle.html  same tool as one file — ship this
codebook.py        codebook v1 decode + v2 encode/decode
tools/make_vectors.py  records cross-language test vectors
tests/             vector check (unittest) + tests/vectors/*.json
lexicon_v2.txt     frozen 4096-entry public word list
README.md          protocol spec
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
2. Circle tokens produced by `sigil.py` must still open in `sigil.html`,
   and the other way around, unless you are intentionally breaking S1.
3. Do not add a network call. The point of the tool is that it works
   on an air-gapped copy of the files.
4. Do not store passphrases, signet PEM, or contact books in git.
5. New encoding modes get a new prefix (`S1X...`), not a silent change
   to `S1C` / `S1K` / `S1E`.

## Suggested first issues

- Browser signet mode that speaks compressed P-256 on the wire
- A `sigil pack` command that wraps fragments for `/msg`
- A wordlist cover encoding that still fits 256 characters
- A ratchet for circle mode (this is an S2 conversation)
