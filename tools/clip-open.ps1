$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$root = Split-Path -Parent $here
$text = Get-Clipboard -Raw
if (-not $text) { Write-Error "Clipboard is empty"; exit 1 }
& python "$root\sigil.py" open $text
