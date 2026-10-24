# Run a built netwatch.exe on a Windows machine without Npcap, which is what a
# new user has before they install it.
#
#   pwsh scripts/windows-smoke.ps1 target\release\netwatch.exe
#
# The test suite runs test harnesses, never the binary that ships. main()
# answers `--version` and `doctor` before it loads wpcap.dll, so both must work
# with no Npcap at all:
#
# - `--version` prints Cargo.toml's version. A binary that imports wpcap.dll at
#   load time instead of delay-loading it (build.rs) dies with
#   STATUS_DLL_NOT_FOUND before main() and prints nothing (issue #47).
# - `doctor --json` parses, and its capture_library entry is npcap_missing with
#   the download link in next_check. Plain `doctor` must say the same in text.
#
# The machine is checked for Npcap first, so a runner image that starts
# shipping it fails here with that reason, not as a wrong doctor answer.
param(
    [Parameter(Mandatory)]
    [string] $Exe
)
$ErrorActionPreference = 'Stop'
# Exit codes are checked below, with messages that say what each one means.
$PSNativeCommandUseErrorActionPreference = $false
# netwatch writes UTF-8 (its manifest sets the code page); read it as UTF-8.
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)

$toml = Join-Path $PSScriptRoot '..\Cargo.toml'
$version = (Select-String -Path $toml -Pattern '^version = "([^"]+)"' |
    Select-Object -First 1).Matches[0].Groups[1].Value

$out = & $Exe --version
$code = $LASTEXITCODE
if ($code -eq -1073741515) {
    throw "$Exe --version: STATUS_DLL_NOT_FOUND (0xC0000135) before main(). Is wpcap.dll still delay-loaded (build.rs)?"
}
if ($code -ne 0) {
    throw "$Exe --version exited $code"
}
if ("$out".Trim() -ne "netwatch $version") {
    throw "$Exe --version printed '$out', expected 'netwatch $version' (Cargo.toml)"
}
Write-Output "--version: $out"

$system = [Environment]::SystemDirectory
foreach ($dll in (Join-Path $system 'Npcap\wpcap.dll'), (Join-Path $system 'wpcap.dll')) {
    if (Test-Path $dll) {
        throw "$dll exists: this machine has Npcap, and the doctor checks below expect one without it"
    }
}

$json = & $Exe doctor --json
$code = $LASTEXITCODE
if ($code -ne 0) {
    throw "$Exe doctor --json exited $code"
}
$report = ($json -join "`n") | ConvertFrom-Json
if ($report.schema_version -ne 1 -or $report.scope -ne 'static' -or $report.platform -ne 'windows') {
    throw "doctor --json: schema_version $($report.schema_version), scope '$($report.scope)', platform '$($report.platform)'; expected 1, 'static', 'windows'"
}
$entries = @($report.capabilities | Where-Object { $_.id -eq 'capture_library' })
if ($entries.Count -ne 1) {
    throw "doctor --json has $($entries.Count) capture_library entries, expected 1"
}
$lib = $entries[0]
if ($lib.state -ne 'unavailable' -or $lib.reason -ne 'npcap_missing') {
    throw "capture_library is $($lib.state) [$($lib.reason)], expected unavailable [npcap_missing]"
}
if ($lib.next_check -notlike '*https://npcap.com/#download*') {
    throw "capture_library next_check '$($lib.next_check)' does not give the Npcap download link"
}
Write-Output "doctor --json: capture_library $($lib.state) [$($lib.reason)]: $($lib.detail)"
Write-Output "  next: $($lib.next_check)"

$text = & $Exe doctor
$code = $LASTEXITCODE
if ($code -ne 0) {
    throw "$Exe doctor exited $code"
}
if (-not ($text -match '^capture_library: unavailable \[npcap_missing\]$')) {
    throw "doctor text has no 'capture_library: unavailable [npcap_missing]' line:`n$($text -join "`n")"
}
Write-Output 'doctor: capture_library line present'
