#requires -Version 5.1
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$catalog=@(Get-Content (Join-Path $PSScriptRoot '../data/checks.json') -Raw|ConvertFrom-Json|ForEach-Object{$_})
if($catalog.Count-ne148-or@($catalog.Id|Sort-Object -Unique).Count-ne148){throw 'Invalid checklist catalog.'}
$lines=@('# Checklist coverage','','IDs preserve the supplied checklist. Implemented means the stated assessment is available; it does not mean every host is vulnerable, safe, accessible, or supported. Read the scope notes below and runtime Limitations. Bounds and missing permissions produce Partial results, never clean findings.','','| ID | Category | Scope | Coverage | Check and scope notes |','|---:|---|---|---|---|')
foreach($entry in $catalog){$title=$entry.Title.Replace('|','\|');$note=$entry.Limitation.Replace('|','\|');$lines+='| '+$entry.Id+' | '+$entry.Category+' | '+$entry.Scope+' | '+$entry.Coverage+' | '+$title+' '+$note+' |'}
$lines|Set-Content (Join-Path $PSScriptRoot '../docs/COVERAGE.md') -Encoding UTF8
