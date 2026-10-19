# Fetch and unpack the Npcap SDK for the Windows build, verified by SHA-256.
#
#   pwsh scripts/npcap-sdk.ps1     # leaves .\npcap-sdk; sets LIB and NPCAP_SDK for later steps
#
# The hash, not the TLS connection, is what makes the download trustworthy:
# npcap.com's certificate lapsed on 2026-10-18 and took every Windows CI job
# down with it. So a TLS failure is retried without certificate validation,
# and the zip is used only if its SHA-256 matches. The hash below matches the
# pins conan-center-index (recipes/npcap) and bacnet-stack (SHA-1
# 8d5bb6f3adb813374402344a8d2a12b9cb725197) recorded independently.
$ErrorActionPreference = 'Stop'
$version = '1.13'
$sha256 = 'dad1f2bf1b02b787be08ca4862f99e39a876c1f274bac4ac0cedc9bbc58f94fd'
$url = "https://npcap.com/dist/npcap-sdk-$version.zip"
$zip = 'npcap-sdk.zip'

if (-not (Test-Path $zip)) {
    try {
        Invoke-WebRequest -Uri $url -OutFile $zip
    } catch {
        Write-Warning "Download over verified TLS failed ($($_.Exception.Message)); retrying without certificate validation. The SHA-256 check below still applies."
        Invoke-WebRequest -Uri $url -OutFile $zip -SkipCertificateCheck
    }
}
$got = (Get-FileHash $zip -Algorithm SHA256).Hash.ToLowerInvariant()
if ($got -ne $sha256) {
    Remove-Item $zip
    throw "npcap-sdk-$version.zip has SHA-256 $got, expected $sha256"
}
Expand-Archive -Path $zip -DestinationPath npcap-sdk -Force
$sdk = Join-Path (Get-Location) 'npcap-sdk'
$lib = Join-Path $sdk 'Lib\x64'
# LIB for the linker; NPCAP_SDK so build.rs uses this copy instead of
# downloading its own, unverified, from the same host.
if ($env:GITHUB_ENV) {
    "LIB=$lib" | Out-File -FilePath $env:GITHUB_ENV -Append -Encoding utf8
    "NPCAP_SDK=$sdk" | Out-File -FilePath $env:GITHUB_ENV -Append -Encoding utf8
}
Write-Output "Npcap SDK $version verified; LIB=$lib"
