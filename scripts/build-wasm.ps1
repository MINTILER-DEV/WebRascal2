Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if (-not (Get-Command wasm-pack -ErrorAction SilentlyContinue)) {
  throw "wasm-pack is required. Install with: cargo install wasm-pack"
}

wasm-pack build .\crates\client-wasm --target web --out-dir ..\..\web\pkg --release
Write-Host "WASM build complete: web/pkg"

