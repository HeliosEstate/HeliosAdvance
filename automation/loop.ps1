# SPDX-FileCopyrightText: 2026 Pascal Fairchild
# SPDX-License-Identifier: AGPL-3.0-only
#Requires -Version 7
<#
The unattended loop: one ready issue per session, fresh context, in the loop's own clone,
committing as the organisation's App. Reads loop.local.json beside this script (gitignored;
loop.local.json.example is the shape). Run attended first:  .\loop.ps1 -Once
Dry run, everything but the session:  .\loop.ps1 -Once -DryRun
Re-read a past session's log into a usage record, nothing else:  .\loop.ps1 -Replay <log>
Stop a running loop before its next iteration:  New-Item <base>\state\stop-requested
Every session appends one JSON line to <base>\state\sessions.jsonl.

What it does not do, on purpose, until a run demands it: model tiers, escalation, retries,
usage-limit scheduling. A usage limit ends the loop with the message on screen.
#>
param(
    [switch]$Once,
    [switch]$DryRun,
    [string]$Replay,
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
# The developer who owns this loop. Claimed issues are assigned to them, so a second
# developer's loop never takes an issue that is someone else's, and the board's column
# follows the claim; both are done as the developer, since the board and the assignment
# are theirs, not the bot's.
$assignee = $config.assignee
$project = $config.project
$email = "$($config.appId)+$slug[bot]@users.noreply.github.com"
$clone = Join-Path $base $repo
$stateDir = Join-Path $base "state"
$stopFile = Join-Path $stateDir "stop-requested"
$sessionsLog = Join-Path $stateDir "sessions.jsonl"
$null = New-Item -ItemType Directory -Force $base, $stateDir

function Log([string]$m) { Write-Host "[loop $(Get-Date -Format HH:mm:ss)] $m" }

# An installation token lives one hour and a session can live longer: the first run died
# at the hour mark, unable to comment or open its PR. So nothing holds a token. app-token.ps1
# mints or reuses one on every call; the session's gh is the shim in automation/bin, its git
# pushes go through the credential helper beside it, and the loop asks before its own calls.
$env:HELIOS_APP_ID = "$($config.appId)"
$env:HELIOS_APP_INSTALLATION = "$($config.installationId)"
$env:HELIOS_APP_KEY = $config.keyPath
$env:HELIOS_STATE = $stateDir
$env:HELIOS_AUTOMATION = $PSScriptRoot
$env:HELIOS_GH = (Get-Command gh.exe).Source
function Get-Token { pwsh -NoProfile -File (Join-Path $PSScriptRoot "app-token.ps1") }

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
    $helper = (Join-Path $PSScriptRoot 'bin' 'git-credential-app').Replace([char]92, '/')
    Invoke-Git config credential.helper "!'$helper'" | Out-Null
    Invoke-Git fetch --quiet --prune origin | Out-Null
}

# The next issue: labelled ready, not claimed, lowest number. Picked by a query, never by
# reading prose.
function Get-NextIssue {
    $issues = gh issue list -R "$owner/$repo" --label ready --state open --json number,title,labels,body,assignees --limit 50 | ConvertFrom-Json
    $issues | Where-Object { -not ($_.labels | Where-Object { $_.name -like 'claimed:*' }) } |
        Where-Object { -not ($_.assignees | Where-Object { $_.login -ne $assignee }) } |
        Sort-Object number | Select-Object -First 1
}

function Get-IssueBranch([int]$n, [string]$body) {
    $m = [regex]::Match($body, '`feature/issue-' + $n + '-[a-z0-9-]+`')
    if ($m.Success) { return $m.Value.Trim('`') }
    "feature/issue-$n"
}

# As the developer, not the App: the App's token is set aside for the one call.
function Invoke-AsDeveloper([scriptblock]$block) {
    $saved = $env:GH_TOKEN; $env:GH_TOKEN = $null
    try { & $block } finally { $env:GH_TOKEN = $saved }
}

# The board column, by name. Looked up by issue number each time; the board is small.
function Set-BoardStatus([int]$n, [string]$status) {
    if (-not $project) { return }
    Invoke-AsDeveloper {
        try {
            $projectId = gh project view $project --owner $owner --format json --jq .id
            $fields = gh project field-list $project --owner $owner --format json | ConvertFrom-Json
            $field = $fields.fields | Where-Object name -eq 'Status'
            $option = ($field.options | Where-Object name -eq $status).id
            $item = (gh project item-list $project --owner $owner --format json --limit 200 | ConvertFrom-Json).items |
                Where-Object { $_.content.number -eq $n } | Select-Object -First 1
            if ($item -and $option) { gh project item-edit --project-id $projectId --id $item.id --field-id $field.id --single-select-option-id $option | Out-Null }
        } catch { Log "board: $_" }
    }
}

# The session's stream-json log is the record of what it cost: the result line carries
# token counts, cost, turns and per-model usage; each assistant message carries the prompt it
# paid for, whose maximum is the peak context, which is what tells a bloated context from a
# long task; the rate-limit events carry the five-hour and seven-day utilisation, which on
# a subscription is the budget. Ported from the second attempt's loop, where these fields
# were what the cost-per-item analysis ran on.
function Get-Field($o, [string]$name) { if ($null -ne $o -and $o.PSObject.Properties[$name]) { $o.$name } else { $null } }

function Read-SessionLog([string]$path) {
    $r = @{ Result = $null; PeakContext = [int64]0; RateLimit = $null }
    if (-not (Test-Path $path)) { return $r }
    foreach ($line in Get-Content $path) {
        if (-not $line.StartsWith("{")) { continue }
        try { $m = $line | ConvertFrom-Json } catch { continue }
        switch (Get-Field $m type) {
            "assistant" {
                $u = Get-Field (Get-Field $m message) usage
                $c = [int64](Get-Field $u input_tokens) + [int64](Get-Field $u cache_read_input_tokens) + [int64](Get-Field $u cache_creation_input_tokens)
                if ($c -gt $r.PeakContext) { $r.PeakContext = $c }
            }
            "rate_limit_event" { $r.RateLimit = Get-Field $m rate_limit_info }
            "result" { $r.Result = $m }
        }
    }
    $r
}

# One JSON line per session, a complete figure each: summing lines never double-counts.
function New-UsageRecord([hashtable]$h, [string]$logPath) {
    $s = Read-SessionLog $logPath
    $res = $s.Result; $u = Get-Field $res usage
    $models = [ordered]@{}
    $mu = Get-Field $res modelUsage
    if ($mu) {
        foreach ($p in $mu.PSObject.Properties | Sort-Object Name) {
            $models[$p.Name] = [ordered]@{ in = [int64](Get-Field $p.Value inputTokens); out = [int64](Get-Field $p.Value outputTokens)
                                           cache_read = [int64](Get-Field $p.Value cacheReadInputTokens); cost = [math]::Round([double](Get-Field $p.Value costUSD), 4) }
        }
    }
    $w = Get-Field $s.RateLimit unifiedWindows
    $rec = [ordered]@{ at = (Get-Date).ToUniversalTime().ToString("o") }
    foreach ($k in $h.Keys) { $rec[$k] = $h[$k] }
    $rec.session_id = [string](Get-Field $res session_id)
    $rec.turns = [int](Get-Field $res num_turns)
    $rec.seconds = [int]([int64](Get-Field $res duration_ms) / 1000)
    $rec.in = [int64](Get-Field $u input_tokens); $rec.cache_write = [int64](Get-Field $u cache_creation_input_tokens)
    $rec.cache_read = [int64](Get-Field $u cache_read_input_tokens); $rec.out = [int64](Get-Field $u output_tokens)
    $rec.thinking = [int64](Get-Field (Get-Field $u output_tokens_details) thinking_tokens)
    $rec.peak_context = $s.PeakContext
    $rec.cost = [math]::Round([double](Get-Field $res total_cost_usd), 4)
    $rec.models = $models
    $rec.subagents = [int](Get-Field (Get-Field $res subagent_stats) spawned)
    $rec.five_hour = [double](Get-Field (Get-Field $w five_hour) utilization)
    $rec.seven_day = [double](Get-Field (Get-Field $w seven_day) utilization)
    $rec.log = $logPath
    $rec
}

function Write-SessionLine([hashtable]$h, [string]$logPath) {
    $rec = New-UsageRecord $h $logPath
    ($rec | ConvertTo-Json -Compress -Depth 4) | Add-Content $sessionsLog
    Log ("#{0}: {1}: {2} turns, {3}s, in={4} cache_read={5} out={6} peak={7}k cost=`${8} 5h={9}% 7d={10}%" -f $rec.issue, $rec.outcome, $rec.turns, $rec.seconds,
        ($rec.in + $rec.cache_write), $rec.cache_read, $rec.out, [int]($rec.peak_context / 1000), $rec.cost, [int]($rec.five_hour * 100), [int]($rec.seven_day * 100))
}

function Invoke-Session([object]$issue) {
    $n = $issue.number
    $branch = Get-IssueBranch $n $issue.body
    Log "issue #${n} on $branch"
    gh issue edit $n -R "$owner/$repo" --add-label $claimLabel | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "could not claim #${n}: does the label $claimLabel exist?" }
    # Two loops can add their labels in the same second. The timeline is the referee: of
    # the claim labels now on the issue, the one whose latest "labeled" event is earliest
    # wins; the other removes its label and takes the next issue.
    $present = @(gh issue view $n -R "$owner/$repo" --json labels --jq '[.labels[].name | select(startswith("claimed:"))]' | ConvertFrom-Json)
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
    if ($assignee) { gh issue edit $n -R "$owner/$repo" --add-assignee $assignee | Out-Null }
    Set-BoardStatus $n "In progress"
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
        $ahead = @(Invoke-Git log --oneline "origin/development..HEAD")
        $retry = if ($ahead.Count -gt 0) { "This branch already carries $($ahead.Count) commit(s) from an earlier session. Read git log and the issue's comments first and continue from there; do not start over.`n`n" } else { "" }
        $prompt = $retry + @"
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
            # The gh shim goes first on PATH for the session only; the loop's own gh calls
            # must keep resolving to gh.exe, or PowerShell tries to run the shim as a document.
            $shimDir = Join-Path $PSScriptRoot "bin"
            $job = Start-Job -ScriptBlock {
                param($prompt, $claudeArgs, $clone, $log, $shimDir)
                $env:PATH = $shimDir + [IO.Path]::PathSeparator + $env:PATH
                Set-Location $clone
                $prompt | & claude @claudeArgs 2>&1 | ForEach-Object { "$_" } | Tee-Object -FilePath $log
            } -ArgumentList $prompt, $claudeArgs, $clone, $log, $shimDir
            if (-not (Wait-Job $job -Timeout ($SessionMinutes * 60))) {
                Stop-Job $job; Remove-Job $job -Force
                $outcome = "stalled"
            } else {
                $lines = Receive-Job $job; Remove-Job $job
                $outcome = "finished"
            }
        } finally { Pop-Location }
        $env:GH_TOKEN = Get-Token
        $text = if (Test-Path $log) { Get-Content $log -Raw } else { "" }
        if ($text -match '(?i)usage limit|rate limit') { $outcome = "limit-hit" }
        if (Test-Path (Join-Path $clone ".helios-stop-red")) { $outcome = "stopped-red" }
        $pr = gh pr list -R "$owner/$repo" --head $branch --state open --json number --jq '.[0].number'
        Write-SessionLine @{ issue = $n; branch = $branch; outcome = $outcome; pr = $pr; model = $config.model; effort = $config.effort } $log
        if ($pr) { Set-BoardStatus $n "Review" }
        # A session that cannot speak for itself gets the loop to say why on the issue.
        $why = switch ($outcome) {
            "stopped-red" { "The session ended on a red check after three attempts. Last output:`n`n``````n$(Get-Content (Join-Path $clone '.helios-stop-red') -Raw)`n``````" }
            "stalled" { "The session was stopped after $SessionMinutes minutes without finishing. Its log is $log on the loop machine." }
            "limit-hit" { "The session hit a usage limit and was ended. The loop will be started again by hand after the reset." }
            default { $null }
        }
        if ($why) {
            gh issue comment $n -R "$owner/$repo" --body $why | Out-Null
            gh issue edit $n -R "$owner/$repo" --add-label human-action-required | Out-Null
        }
        return @{ outcome = $outcome }
    } finally {
        gh issue edit $n -R "$owner/$repo" --remove-label $claimLabel | Out-Null
    }
}

# ---- main ----
if ($Replay) {
    (New-UsageRecord @{ issue = 0; outcome = "replay"; model = $config.model; effort = $config.effort } $Replay | ConvertTo-Json -Depth 4)
    exit 0
}
$env:GH_TOKEN = Get-Token
Initialize-Clone
$i = 0
while ($i -lt $MaxIterations) {
    if (Test-Path $stopFile) { Log "stop requested"; Remove-Item $stopFile; break }
    $issue = Get-NextIssue
    if (-not $issue) { Log "no ready, unclaimed issue"; break }
    $env:GH_TOKEN = Get-Token
    $r = Invoke-Session $issue
    $i++
    if ($r.outcome -eq "lost-claim") { continue }
    if ($Once -or $r.outcome -in @("limit-hit", "stalled")) { break }
}
Log "done after $i session(s)"
