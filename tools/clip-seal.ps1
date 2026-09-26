param(
  [Parameter(Mandatory = $true)][string]$Circle
)
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$root = Split-Path -Parent $here
$text = Get-Clipboard -Raw
if (-not $text) { Write-Error "Clipboard is empty"; exit 1 }
$out = & python "$root\sigil.py" seal -c $Circle $text
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
Set-Clipboard -Value $out
Write-Output $out
