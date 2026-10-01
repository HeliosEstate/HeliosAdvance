# SPDX-FileCopyrightText: 2026 Pascal Fairchild
# SPDX-License-Identifier: AGPL-3.0-only
#Requires -Version 7
<#
The unattended loop: one ready issue per session, fresh context, in the loop's own clone,
committing as the organisation's App. Reads loop.local.json beside this script (gitignored;
loop.local.json.example is the shape). Run attended first:  .\loop.ps1 -Once
Dry run, everything but the session:  .\loop.ps1 -Once -DryRun
Stop a running loop before its next iteration:  New-Item <base>\state\stop-requested
Every session appends one JSON line to <base>\state\sessions.jsonl.

What it does not do, on purpose, until a run demands it: model tiers, escalation, retries,
usage-limit scheduling. A usage limit ends the loop with the message on screen.
#>
param(
    [switch]$Once,
    [switch]$DryRun,
    [int]$MaxIterations = 20,
    [int]$SessionMinutes = 120
)
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$config = Get-Content (Join-Path $PSScriptRoot "loop.local.json") -Raw | ConvertFrom-Json
$base = $config.base
$owner = $config.owner
$repo = $config.repo
$slug = $config.appSlug
$identity = "$slug[bot]"
# Each loop claims under its own name, so a second loop (another App, another name) can run
# beside this one; the claim is decided by label event order, below.
$claimLabel = "claimed:$slug"
$email = "$($config.appId)+$slug[bot]@users.noreply.github.com"
$clone = Join-Path $base $repo
$stateDir = Join-Path $base "state"
$stopFile = Join-Path $stateDir "stop-requested"
$sessionsLog = Join-Path $stateDir "sessions.jsonl"
$null = New-Item -ItemType Directory -Force $base, $stateDir

function Log([string]$m) { Write-Host "[loop $(Get-Date -Format HH:mm:ss)] $m" }

function Base64Url([byte[]]$b) { [Convert]::ToBase64String($b).TrimEnd('=').Replace('+', '-').Replace('/', '_') }

# A one-hour installation token from the App's key; the session only ever sees the token.
function New-InstallationToken {
    $rsa = [System.Security.Cryptography.RSA]::Create()
    $rsa.ImportFromPem((Get-Content $config.keyPath -Raw))
    $now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    $header = Base64Url ([Text.Encoding]::UTF8.GetBytes('{"alg":"RS256","typ":"JWT"}'))
    $payload = Base64Url ([Text.Encoding]::UTF8.GetBytes("{`"iat`":$($now - 60),`"exp`":$($now + 540),`"iss`":`"$($config.appId)`"}"))
    $sig = Base64Url ($rsa.SignData([Text.Encoding]::UTF8.GetBytes("$header.$payload"),
            [Security.Cryptography.HashAlgorithmName]::SHA256, [Security.Cryptography.RSASignaturePadding]::Pkcs1))
    (Invoke-RestMethod -Method Post -Uri "https://api.github.com/app/installations/$($config.installationId)/access_tokens" `
        -Headers @{ Authorization = "Bearer $header.$payload.$sig"; Accept = "application/vnd.github+json" }).token
}

function Invoke-Git { param([Parameter(ValueFromRemainingArguments)][string[]]$a)
    $out = & git.exe -C $clone @a 2>&1
    if ($LASTEXITCODE -ne 0) { throw "git $($a -join ' '): $out" }
    $out
}

# The clone is the bot's: its identity, and a credential helper that reads the token from
# the environment, so nothing is written to disk.
function Initialize-Clone {
    if (-not (Test-Path (Join-Path $clone ".git"))) {
        Log "cloning $owner/$repo"
        & git.exe clone --quiet "https://github.com/$owner/$repo.git" $clone 2>&1 | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "clone failed" }
    }
    Invoke-Git config user.name $identity | Out-Null
    Invoke-Git config user.email $email | Out-Null
    Invoke-Git config credential.helper '!f() { echo username=x-access-token; echo password=$GH_TOKEN; }; f' | Out-Null
    Invoke-Git fetch --quiet --prune origin | Out-Null
}

# The next issue: labelled ready, not claimed, lowest number. Picked by a query, never by
# reading prose.
function Get-NextIssue {
    $issues = gh issue list -R "$owner/$repo" --label ready --state open --json number,title,labels,body --limit 50 | ConvertFrom-Json
    $issues | Where-Object { -not ($_.labels | Where-Object { $_.name -like 'claimed:*' }) } | Sort-Object number | Select-Object -First 1
}

function Get-IssueBranch([int]$n, [string]$body) {
    $m = [regex]::Match($body, '`feature/issue-' + $n + '-[a-z0-9-]+`')
    if ($m.Success) { return $m.Value.Trim('`') }
    "feature/issue-$n"
}

function Write-SessionLine([hashtable]$h) {
    $h.at = (Get-Date).ToUniversalTime().ToString("o")
    ($h | ConvertTo-Json -Compress) | Add-Content $sessionsLog
}

function Invoke-Session([object]$issue) {
    $n = $issue.number
    $branch = Get-IssueBranch $n $issue.body
    Log "issue #${n} on $branch"
    gh issue edit $n -R "$owner/$repo" --add-label $claimLabel | Out-Null
    # Two loops can add their labels in the same second. The timeline is the referee: of
    # the claim labels now on the issue, the one whose latest "labeled" event is earliest
    # wins; the other removes its label and takes the next issue.
    $present = (gh issue view $n -R "$owner/$repo" --json labels --jq '[.labels[].name | select(startswith("claimed:"))]' | ConvertFrom-Json)
    if ($present.Count -gt 1) {
        $events = gh api "repos/$owner/$repo/issues/$n/timeline" --paginate `
            --jq '[.[] | select(.event=="labeled" and (.label.name|startswith("claimed:"))) | {n:.label.name, t:.created_at}] | group_by(.n) | map(max_by(.t))' | ConvertFrom-Json
        $winner = ($events | Where-Object { $_.n -in $present } | Sort-Object t | Select-Object -First 1).n
        if ($winner -and $winner -ne $claimLabel) {
            gh issue edit $n -R "$owner/$repo" --remove-label $claimLabel | Out-Null
            Log "issue #${n}: claimed first by $winner; moving on"
            return @{ outcome = "lost-claim" }
        }
    }
    try {
        if ((Invoke-Git ls-remote --heads origin $branch) -match $branch) {
            Invoke-Git checkout --quiet -B $branch "origin/$branch" | Out-Null
        } else {
            Invoke-Git checkout --quiet -B $branch origin/development | Out-Null
        }
        Remove-Item -Force -ErrorAction SilentlyContinue (Join-Path $clone ".helios-red"), (Join-Path $clone ".helios-stop-red")
        if (Test-Path (Join-Path $clone "oracle")) {
            Get-ChildItem (Join-Path $clone "oracle") -Directory | ForEach-Object {
                $tag = "heliosestate/$($_.Name)-oracle:0.1"
                Log "building $tag"
                docker build -q -t $tag $_.FullName | Out-Null
            }
        }
        $prompt = @"
You are a build session of the Helios Advance loop, unattended, on issue #$n, branch $branch, in this clone. HELIOS_LOOP=1: the hooks refuse what you may not edit, and a red check ends the turn.

1. Run: gh issue view $n. Read it whole. The approved tests are at the QA commit it names; they are locked; you never edit them. Build to the behaviour lines; touch only the Files it lists.
2. Run: bash check.sh. Red is the starting state; the failing tests are the work.
3. Post your plan as the issue's first comment, a task list, then proceed; do not wait.
4. Implement until bash check.sh is green. Commit as you go, each message saying why, and push after every green commit. Never add a module without its cost-benefit line in the PR body.
5. Open the PR to development with gh pr create, body in the shape CLAUDE.md gives: decisions, what changed, checks with their output, noticed-not-touched. Tick the plan's boxes with one-line comments on the issue as they land. Do not merge.
6. Out of road (locked tests still red after real attempts, a spec gap, a question): push what you have, comment on the issue with the failing output in full and the question, run gh issue edit $n --add-label human-action-required, and stop.
"@
        if ($DryRun) {
            Log "dry run: would launch the session with this prompt:"
            Write-Host $prompt
            return @{ outcome = "dry-run" }
        }
        $env:HELIOS_LOOP = "1"
        $env:GIT_AUTHOR_NAME = $identity; $env:GIT_AUTHOR_EMAIL = $email
        $env:GIT_COMMITTER_NAME = $identity; $env:GIT_COMMITTER_EMAIL = $email
        $log = Join-Path $stateDir "session-$n-$(Get-Date -Format yyyyMMdd-HHmmss).log"
        $claudeArgs = @("-p", "--model", $config.model, "--effort", $config.effort, "--output-format", "stream-json", "--verbose", "--dangerously-skip-permissions")
        $started = Get-Date
        Push-Location $clone
        try {
            $job = Start-Job -ScriptBlock {
                param($prompt, $claudeArgs, $clone, $log)
                Set-Location $clone
                $prompt | & claude @claudeArgs 2>&1 | ForEach-Object { "$_" } | Tee-Object -FilePath $log
            } -ArgumentList $prompt, $claudeArgs, $clone, $log
            if (-not (Wait-Job $job -Timeout ($SessionMinutes * 60))) {
                Stop-Job $job; Remove-Job $job -Force
                $outcome = "stalled"
            } else {
                $lines = Receive-Job $job; Remove-Job $job
                $outcome = "finished"
            }
        } finally { Pop-Location }
        $text = if (Test-Path $log) { Get-Content $log -Raw } else { "" }
        $cost = [regex]::Match($text, '"total_cost_usd"\s*:\s*([0-9.]+)').Groups[1].Value
        if ($text -match '(?i)usage limit|rate limit') { $outcome = "limit-hit" }
        if (Test-Path (Join-Path $clone ".helios-stop-red")) { $outcome = "stopped-red" }
        $pr = gh pr list -R "$owner/$repo" --head $branch --state open --json number --jq '.[0].number'
        Write-SessionLine @{ issue = $n; branch = $branch; outcome = $outcome; minutes = [math]::Round(((Get-Date) - $started).TotalMinutes, 1); cost = $cost; pr = $pr; model = $config.model; log = $log }
        Log "issue #${n}: $outcome$(if ($pr) { ", PR #$pr" }) ($cost USD)"
        if ($outcome -eq "stopped-red") {
            $tail = Get-Content (Join-Path $clone ".helios-stop-red") -Raw
            gh issue comment $n -R "$owner/$repo" --body "The session ended on a red check after three attempts. Last output:`n`n``````n$tail`n``````" | Out-Null
            gh issue edit $n -R "$owner/$repo" --add-label human-action-required | Out-Null
        }
        return @{ outcome = $outcome }
    } finally {
        gh issue edit $n -R "$owner/$repo" --remove-label $claimLabel | Out-Null
    }
}

# ---- main ----
$env:GH_TOKEN = New-InstallationToken
Initialize-Clone
$i = 0
while ($i -lt $MaxIterations) {
    if (Test-Path $stopFile) { Log "stop requested"; Remove-Item $stopFile; break }
    $issue = Get-NextIssue
    if (-not $issue) { Log "no ready, unclaimed issue"; break }
    $env:GH_TOKEN = New-InstallationToken
    $r = Invoke-Session $issue
    $i++
    if ($r.outcome -eq "lost-claim") { continue }
    if ($Once -or $r.outcome -in @("limit-hit", "stalled")) { break }
}
Log "done after $i session(s)"
