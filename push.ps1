$date = Get-Date -Format "yyyyMMdd"
$dateDisplay = Get-Date -Format "yyyy-MM-dd"

Write-Host ""
Write-Host "======================================" -ForegroundColor Cyan
Write-Host "  DHCPD GitHub Upload - $dateDisplay" -ForegroundColor Cyan
Write-Host "======================================" -ForegroundColor Cyan
Write-Host ""

# 1. Copy dhcpd.py to dated version
if (Test-Path "dhcpd.py") {
    Copy-Item "dhcpd.py" "dhcpd_$date.py" -Force
    Write-Host "[OK] dhcpd_$date.py created" -ForegroundColor Green
} else {
    Write-Host "[WARN] dhcpd.py not found" -ForegroundColor Yellow
}

# 2. Write release note?
Write-Host ""
$writeNote = Read-Host "Write release note? (y/n)"

if ($writeNote -eq "y" -or $writeNote -eq "Y") {

    if (-not (Test-Path "release_notes")) {
        New-Item -ItemType Directory -Path "release_notes" | Out-Null
    }

    $notePath = "release_notes\RELEASE_$date.md"

    Write-Host ""
    Write-Host "Enter changes (press Enter twice to finish):" -ForegroundColor Cyan
    $lines = @()
    while ($true) {
        $line = Read-Host "  "
        if ($line -eq "") { break }
        $lines += $line
    }

    $body = $lines -join "`r`n"
    $noteContent = "# Release Note - $dateDisplay`r`n`r`n## Changes`r`n`r`n$body`r`n`r`n---`r`n`r`nFile : dhcpd_$date.py`r`nDate : $dateDisplay`r`n"

    [System.IO.File]::WriteAllText(
        (Join-Path (Get-Location) $notePath),
        $noteContent,
        [System.Text.Encoding]::UTF8
    )

    Write-Host "[OK] release_notes\RELEASE_$date.md saved" -ForegroundColor Green
}

# 3. Commit message
Write-Host ""
$msg = Read-Host "Commit message"

# 4. Git push
Write-Host ""
git add .
git commit -m $msg
git push

Write-Host ""
Write-Host "======================================" -ForegroundColor Cyan
Write-Host "  Upload complete!" -ForegroundColor Green
Write-Host "  - dhcpd_$date.py" -ForegroundColor White
if ($writeNote -eq "y" -or $writeNote -eq "Y") {
    Write-Host "  - release_notes\RELEASE_$date.md" -ForegroundColor White
}
Write-Host "======================================" -ForegroundColor Cyan
Write-Host ""