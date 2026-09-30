#requires -Version 7.0
$ErrorActionPreference='Stop'
$root=Join-Path ([IO.Path]::GetTempPath()) ('StealthPrivesc-reference-'+[Guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($root)
try {
    $path=Join-Path $root 'windows-updates.json'
    $oldDate='2020-01-01T00:00:00Z'
    @{SchemaVersion=1;RetrievedUtc=$oldDate;Months=@('2026-Jan');Entries=@(@{Cve='CVE-OLD';ProductId='old';FixedBuild='10.0.22631.1';Month='2026-Jan'})} | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $path
    # Exercise the actual updater with a fixed public-response fixture, offline.
    function Invoke-RestMethod {
        param([string]$Uri)
        if($Uri -ne 'https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/2026-Mar'){throw 'Unexpected network request in updater fixture.'}
        @{ProductTree=@{FullProductName=@(@{ProductID='new';Value='Windows Server 2019'})};Vulnerability=@(@{CVE='CVE-NEW';Title=@{Value='Fixture'};Remediations=@(@{Type=2;ProductID=@('new');FixedBuild='10.0.17763.2';Description=@{Value='fixture'}})})}
    }
    . (Join-Path $PSScriptRoot '../tools/Update-ReferenceData.ps1') -WindowsUpdates -Month '2026-Mar' -OutputDirectory $root
    $merged=Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
    if($merged.Entries.Count -ne 2 -or '2026-Jan' -notin $merged.Months -or '2026-Mar' -notin $merged.Months){throw 'Default refresh discarded historical source coverage.'}
    if([DateTimeOffset]$merged.MonthRetrievedUtc.'2026-Jan' -ne [DateTimeOffset]$oldDate){throw 'Historical retrieval age was incorrectly refreshed.'}
    . (Join-Path $PSScriptRoot '../tools/Update-ReferenceData.ps1') -WindowsUpdates -Month '2026-Mar' -OutputDirectory $root
    if(@((Get-Content -LiteralPath $path -Raw | ConvertFrom-Json).Entries).Count -ne 2){throw 'Refreshing a month duplicated its records.'}
    . (Join-Path $PSScriptRoot '../tools/Update-ReferenceData.ps1') -WindowsUpdates -Month '2026-Mar' -ReplaceWindowsSnapshot -OutputDirectory $root
    $replaced=Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
    if(@($replaced.Entries).Count -ne 1 -or @($replaced.Months).Count -ne 1 -or $replaced.Months[0] -ne '2026-Mar'){throw 'Explicit snapshot replacement did not honor selected coverage.'}
    Write-Host 'PASS: historical snapshot merge, retrieval-age preservation, idempotent refresh and explicit replacement.'
} finally {
    $resolved=[IO.Path]::GetFullPath($root);$base=[IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\','/')+[IO.Path]::DirectorySeparatorChar
    if(-not $resolved.StartsWith($base,[StringComparison]::OrdinalIgnoreCase) -or [IO.Path]::GetFileName($resolved) -notmatch '^StealthPrivesc-reference-[a-f0-9]{32}$'){throw 'Unsafe cleanup target.'}
    Remove-Item -LiteralPath $resolved -Recurse -Force
}
