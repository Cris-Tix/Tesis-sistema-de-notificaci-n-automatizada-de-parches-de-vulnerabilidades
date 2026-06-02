<#
.SYNOPSIS
    Replaces the hardcoded Postgres credential id "1" in all workflow JSONs
    with the real UUID assigned by n8n.

.PARAMETER WorkflowDir
    Path to the workflows directory. Defaults to .\workflows next to the script.

.PARAMETER N8nContainer
    Docker container name for n8n. Auto-detected from running containers if omitted.

.PARAMETER PostgresCredentialId
    UUID to inject. Auto-queried from n8n's SQLite if omitted.

.EXAMPLE
    # Fully automatic
    .\fix-credential-ids.ps1

    # Provide UUID directly (skip SQLite query)
    .\fix-credential-ids.ps1 -PostgresCredentialId "abc12def-3456-7890-abcd-ef1234567890"
#>
param(
    [string]$WorkflowDir          = (Join-Path $PSScriptRoot "workflows"),
    [string]$N8nContainer         = "",
    [string]$PostgresCredentialId = ""
)

$ErrorActionPreference = "Stop"

# ── helpers ───────────────────────────────────────────────────────────────────

function Find-N8nContainer {
    $running = docker ps --format "{{.Names}}" 2>$null
    $match   = @($running) | Where-Object { $_ -match "n8n" } | Select-Object -First 1
    return $match
}

function Invoke-N8nSqlite {
    param([string]$Container, [string]$Sql)
    $out = docker exec $Container sqlite3 /home/node/.n8n/database.sqlite $Sql 2>&1
    if ($LASTEXITCODE -ne 0) { return $null }
    return $out
}

# ── 1. locate the n8n container ──────────────────────────────────────────────

if (-not $N8nContainer) {
    $N8nContainer = Find-N8nContainer
    if ($N8nContainer) {
        Write-Host "Auto-detected n8n container: $N8nContainer"
    } else {
        Write-Warning "No running container whose name contains 'n8n' was found."
        Write-Host   "Pass -N8nContainer explicitly, e.g.: .\fix-credential-ids.ps1 -N8nContainer proyecto-n8n-1"
    }
}

# ── 2. resolve the Postgres credential UUID ───────────────────────────────────

if (-not $PostgresCredentialId -and $N8nContainer) {
    Write-Host "Querying n8n SQLite for Postgres credentials..."

    $rows = Invoke-N8nSqlite $N8nContainer "SELECT id,name FROM credentials_entity WHERE type='postgres';"

    if ($rows) {
        $creds = @($rows) | Where-Object { $_ } | ForEach-Object {
            $parts = $_ -split '\|', 2
            [PSCustomObject]@{
                Id   = $parts[0].Trim()
                Name = if ($parts.Count -gt 1) { $parts[1].Trim() } else { '(unnamed)' }
            }
        }

        if ($creds.Count -eq 1) {
            $PostgresCredentialId = $creds[0].Id
            Write-Host "  Found: '$($creds[0].Name)'  →  $PostgresCredentialId"

        } elseif ($creds.Count -gt 1) {
            Write-Host "  Multiple Postgres credentials found:"
            for ($i = 0; $i -lt $creds.Count; $i++) {
                Write-Host "    [$i]  $($creds[$i].Id)  $($creds[$i].Name)"
            }
            $idx = [int](Read-Host "  Enter index to use")
            $PostgresCredentialId = $creds[$idx].Id

        } else {
            Write-Host "  No rows returned — credential type might differ."
        }
    } else {
        Write-Host "  SQLite query returned no output."
    }
}

if (-not $PostgresCredentialId) {
    Write-Host ""
    Write-Host "Could not auto-detect. Find the UUID with one of:"
    Write-Host "  docker exec <n8n-container> sqlite3 /home/node/.n8n/database.sqlite 'SELECT id,name FROM credentials_entity;'"
    Write-Host "  n8n UI → Settings → Credentials → open the credential → copy the ID from the URL"
    Write-Host ""
    $PostgresCredentialId = Read-Host "Paste Postgres credential UUID"
}

Write-Host ""
Write-Host "Injecting UUID: $PostgresCredentialId"
Write-Host ""

# ── 3. patch all workflow JSON files ──────────────────────────────────────────

# Targets the postgres credential block specifically:
#   "postgres": {
#     "id": "1",     ← only this is replaced
# Uses a capture group so everything before "1" is preserved verbatim.
$pattern     = '("postgres"\s*:\s*\{[\s\S]*?"id"\s*:\s*)"1"'
$replacement = '$1"' + $PostgresCredentialId + '"'
$utf8NoBom   = New-Object System.Text.UTF8Encoding $false

$files    = Get-ChildItem -Path $WorkflowDir -Filter "workflow-*.json" | Sort-Object Name
$nUpdated = 0

foreach ($f in $files) {
    $text    = [System.IO.File]::ReadAllText($f.FullName, [System.Text.Encoding]::UTF8)
    $patched = [regex]::Replace($text, $pattern, $replacement)

    if ($patched -ne $text) {
        [System.IO.File]::WriteAllText($f.FullName, $patched, $utf8NoBom)
        Write-Host "  [UPDATED] $($f.Name)"
        $nUpdated++
    } else {
        Write-Host "  [SKIP]    $($f.Name)  (no postgres id '1' found)"
    }
}

Write-Host ""
Write-Host "Done — $nUpdated file(s) updated."

if ($nUpdated -gt 0) {
    Write-Host ""
    Write-Host "Next steps:"
    Write-Host "  1. In n8n UI, delete each workflow and re-import the updated JSON"
    Write-Host "     (Settings → Import workflow, or drag-and-drop the file)"
    Write-Host "  2. If workflow-alerts uses an SMTP credential, repeat for id '2':"
    Write-Host "     docker exec $N8nContainer sqlite3 /home/node/.n8n/database.sqlite 'SELECT id,name FROM credentials_entity WHERE type=''smtp'';'"
}
