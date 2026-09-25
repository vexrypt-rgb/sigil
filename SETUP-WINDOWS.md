# Drop these files onto your existing repo

Your repo is already initialized at:

`C:\Users\redfa\Documents\MinecraftDev\sigil`

1. Download `sigil-repo-files.zip`.
2. Extract **into that folder** (not into a new nested `sigil` folder).
   You should end up with `.gitignore`, `LICENSE`, `sigil.py`, etc. side by side.
3. In PowerShell:

```powershell
cd C:\Users\redfa\Documents\MinecraftDev\sigil
git add .
git status
git commit -m "Initial public tree for SIGIL S1"
```

`git status` should list the source files as staged. It should not list
`keys\` or `.sigil-home\`.
