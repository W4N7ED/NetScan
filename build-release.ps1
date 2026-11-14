# Compile l'exécutable à publier, sans chemins de la machine de compilation.
# Par défaut, Rust inscrit dans l'exe les chemins complets des sources
# (C:\Users\<nom de session>\.cargo\...) ; on les remplace par des préfixes neutres.
$ErrorActionPreference = 'Stop'
$proj = $PSScriptRoot
$target = if ($env:CARGO_TARGET_DIR) { $env:CARGO_TARGET_DIR } else { Join-Path $proj 'target' }
$env:RUSTFLAGS = @(
    "--remap-path-prefix=$env:USERPROFILE\.cargo=cargo"
    "--remap-path-prefix=$env:USERPROFILE\.rustup=rustup"
    "--remap-path-prefix=$proj=netscan"
    "--remap-path-prefix=$target=target"
) -join ' '

Push-Location $proj
try { cargo build --release } finally { Pop-Location }
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

$exe = Join-Path $target 'release\NetScan.exe'
$text = [Text.Encoding]::ASCII.GetString([IO.File]::ReadAllBytes($exe))
$leaks = ([regex]::Matches($text, [regex]::Escape($env:USERPROFILE))).Count
if ($leaks -gt 0) { Write-Error "$leaks chemins personnels restent dans l'exécutable."; exit 1 }
Copy-Item $exe (Join-Path $proj 'NetScan.exe') -Force
"NetScan.exe prêt : $((Get-FileHash (Join-Path $proj 'NetScan.exe') -Algorithm SHA256).Hash.ToLower())"
