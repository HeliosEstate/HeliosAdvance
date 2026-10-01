# SPDX-FileCopyrightText: 2026 Pascal Fairchild
# SPDX-License-Identifier: AGPL-3.0-only
#Requires -Version 7
<#
Prints a fresh installation token for the loop's App. An installation token lives one hour
and a session can live longer, so every gh and git call mints or reuses one through this
script instead of holding one token for the session. Cached in HELIOS_STATE\token.json
until five minutes before it expires. Reads HELIOS_APP_ID, HELIOS_APP_INSTALLATION,
HELIOS_APP_KEY and HELIOS_STATE from the environment, set by loop.ps1.
#>
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
# The cache holds the expiry as Unix seconds. As text it came back from JSON as a local
# DateTime with the Z lost, read an hour late on this machine, and every gh call after the
# hour mark failed with bad credentials: the first run's failure, found again.
$cache = Join-Path $env:HELIOS_STATE "token.json"
$now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
if (Test-Path $cache) {
    $c = Get-Content $cache -Raw | ConvertFrom-Json
    if ([int64]$c.expires -gt $now + 300) { Write-Output $c.token; exit 0 }
}
function Base64Url([byte[]]$b) { [Convert]::ToBase64String($b).TrimEnd('=').Replace('+', '-').Replace('/', '_') }
$rsa = [System.Security.Cryptography.RSA]::Create()
$rsa.ImportFromPem((Get-Content $env:HELIOS_APP_KEY -Raw))
$header = Base64Url ([Text.Encoding]::UTF8.GetBytes('{"alg":"RS256","typ":"JWT"}'))
$payload = Base64Url ([Text.Encoding]::UTF8.GetBytes("{`"iat`":$($now - 60),`"exp`":$($now + 540),`"iss`":`"$($env:HELIOS_APP_ID)`"}"))
$sig = Base64Url ($rsa.SignData([Text.Encoding]::UTF8.GetBytes("$header.$payload"),
        [Security.Cryptography.HashAlgorithmName]::SHA256, [Security.Cryptography.RSASignaturePadding]::Pkcs1))
$r = Invoke-RestMethod -Method Post -Uri "https://api.github.com/app/installations/$($env:HELIOS_APP_INSTALLATION)/access_tokens" `
    -Headers @{ Authorization = "Bearer $header.$payload.$sig"; Accept = "application/vnd.github+json" }
@{ token = $r.token; expires = [DateTimeOffset]::new([datetime]$r.expires_at).ToUnixTimeSeconds() } | ConvertTo-Json -Compress | Set-Content $cache
Write-Output $r.token
