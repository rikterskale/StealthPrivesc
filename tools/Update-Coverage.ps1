#requires -Version 5.1
[CmdletBinding()]
param([switch]$Check)
$ErrorActionPreference='Stop'
$catalog=@(Get-Content (Join-Path $PSScriptRoot '../data/checks.json') -Raw -Encoding UTF8|ConvertFrom-Json|ForEach-Object{$_})
if($catalog.Count-ne148-or@($catalog.Id|Sort-Object -Unique).Count-ne148){throw 'Invalid checklist catalog.'}
$lines=@('# Checklist coverage','','IDs preserve the supplied checklist. Implemented means the stated assessment is available; it does not mean every host is vulnerable, safe, accessible, or supported. Read the scope notes below and runtime Limitations. Bounds and missing permissions produce Partial results, never clean findings.','','| ID | Category | Scope | Coverage | Check and scope notes |','|---:|---|---|---|---|')
foreach($entry in $catalog){$title=$entry.Title.Replace('|','\|');$note=$entry.Limitation.Replace('|','\|');$lines+='| '+$entry.Id+' | '+$entry.Category+' | '+$entry.Scope+' | '+$entry.Coverage+' | '+$title+' '+$note+' |'}
$coveragePath = Join-Path $PSScriptRoot '../docs/COVERAGE.md'
if ($Check) {
    $expected = ($lines -join "`n") + "`n"
    $actual = (Get-Content -LiteralPath $coveragePath -Raw -Encoding UTF8).Replace("`r`n", "`n")
    if ($actual -cne $expected) { throw 'docs/COVERAGE.md is out of date. Run tools/Update-Coverage.ps1 and commit the result.' }
    Write-Host 'PASS: generated checklist coverage matches data/checks.json.'
} else {
    $lines | Set-Content -LiteralPath $coveragePath -Encoding UTF8
}
