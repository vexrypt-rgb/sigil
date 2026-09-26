#!/usr/bin/env python3
"""Build sigil.bundle.html — one file, no extra script tags."""
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
html = ROOT.joinpath("sigil.html").read_text(encoding="utf-8")
chunks = []
for name in ("lexicon_v2.js", "codebook_v2.js", "p256.js"):
    chunks.append("<script>\n" + ROOT.joinpath(name).read_text(encoding="utf-8") + "\n</script>\n")
    html = html.replace(f'<script src="{name}"></script>\n', "")
needle = "<script>\nconst PROTOCOL"
if needle not in html:
    raise SystemExit("sigil.html script marker not found")
html = html.replace(needle, "".join(chunks) + needle, 1)
out = ROOT.joinpath("sigil.bundle.html")
out.write_text(html, encoding="utf-8")
print(f"wrote {out} ({out.stat().st_size} bytes)")
