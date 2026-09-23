#requires -Version 5.1
$ErrorActionPreference = 'Stop'
if ($env:OS -ne 'Windows_NT') {
    Write-Host 'NOT RUN: Test-Verification requires Windows. Run tools/Test-Project.ps1 on 64-bit Windows with PowerShell 5.1 and 7.'
    exit 2
}
Import-Module (Join-Path $PSScriptRoot '../src/StealthPrivesc.psd1') -Force
& (Get-Module StealthPrivesc) {
    $script:VerificationAssertions = 0
    function Assert-Verification([bool]$Value, [string]$Message) {
        if (-not $Value) { throw "FAIL: $Message" }
        $script:VerificationAssertions++
    }
    function Reset-VerificationCheck([int]$Id = 1) {
        $script:Current = [ordered]@{
            Id=$Id; Status='Completed'; Findings=New-Object 'System.Collections.Generic.List[object]'
            Limitations=New-Object 'System.Collections.Generic.List[string]'
            Verification=(New-CheckVerification $Id)
        }
    }
    $script:Context = @{
        Cache=@{}; MaxItems=10; MaxFileBytes=1024; CommandTimeoutSeconds=1
        IncludeSensitive=$true; IncludeDomain=$false; IncludeNetwork=$true
        SearchRoot=@("C:\O'Brien\report <script>", 'C:\literal $(throw ''injected'')')
        DriverDatabasePath='relative drivers.json'; VulnerabilityDatabasePath='relative updates.json'
    }
    Reset-VerificationCheck
    $verification = $script:Current.Verification
    Assert-Verification ($verification.RerunCommand -match '-CheckId 1 -IncludeNetwork -IncludeSensitive -MaxItems 10 -MaxFileBytes 1024 -CommandTimeoutSeconds 1') 'Rerun commands preserve scope and numeric limits.'
    Assert-Verification ($verification.RerunCommand -notmatch '-IncludeDomain') 'Rerun commands do not grant additional scope.'
    Assert-Verification ($verification.RerunCommand.Contains("-DriverDatabasePath 'relative drivers.json'")) 'Custom reference paths are preserved.'
    Assert-Verification ($verification.WorkingDirectory -eq (Get-Location).Path) 'Relative arguments retain their original working directory.'
    $tokens=$null; $errors=$null
    $ast=[Management.Automation.Language.Parser]::ParseInput($verification.RerunCommand,[ref]$tokens,[ref]$errors)
    Assert-Verification ($errors.Count -eq 0) 'The generated rerun command parses.'
    Assert-Verification (@($ast.FindAll({param($node) $node -is [Management.Automation.Language.SubExpressionAst]},$true)).Count -eq 0) 'Path text is literal, never executable.'
    foreach ($literal in @("C:\O'Brien", 'C:\$literal; $(throw 1)', ('smart'+[char]0x2019+'quote'))) {
        $quoted=ConvertTo-VerificationLiteral $literal
        $literalAst=[Management.Automation.Language.Parser]::ParseInput($quoted,[ref]$tokens,[ref]$errors)
        $values=@($literalAst.FindAll({param($node) $node -is [Management.Automation.Language.StringConstantExpressionAst]},$true))
        Assert-Verification ($errors.Count -eq 0 -and $values.Count -eq 1 -and $values[0].Value -ceq $literal) 'Path quoting must round-trip without evaluation.'
    }
    foreach ($check in Get-StealthPrivescCheck) {
        $references=@(Get-CheckSourceReferences -Collector (Get-CheckCollector $check.Id) -Id $check.Id)
        Assert-Verification ($references.Count -gt 0) "Check $($check.Id) must have command/API references."
        Assert-Verification (@($references | Where-Object { -not $_.Source.StartsWith('src/') -or $_.Line -lt 1 -or -not $_.Expression }).Count -eq 0) "Check $($check.Id) must have source locations."
    }
    $restricted=@(Get-CheckSourceReferences (Get-CheckCollector 3) 3)
    Assert-Verification (($restricted.Expression -join ' ') -match '::Sids\(11\)' -and ($restricted.Expression -join ' ') -notmatch '::Privileges\(') 'References exclude sibling switch cases.'
    $installer=@(Get-CheckSourceReferences (Get-CheckCollector 47) 47)
    Assert-Verification (($installer.Expression -join ' ') -notmatch 'Get-SmbServerConfiguration|Win32_DeviceGuard') 'References exclude unrelated constant-ID conditions.'
    Reset-VerificationCheck 11
    Get-Cached 'verification-fixture' { Add-CheckCommand PowerShell 'Get-CimInstance Win32_Service -ErrorAction Stop' -Detail 'Keep query context'; 'fixture data' } | Out-Null
    Assert-Verification ($script:Current.Verification.Commands[0].State -eq 'Attempted') 'First inventory collection is an attempt.'
    Reset-VerificationCheck 12
    $cached=Get-Cached 'verification-fixture' { throw 'Should not run' }
    $reused=$script:Current.Verification.Commands[0]
    Assert-Verification ($cached -eq 'fixture data' -and $reused.State -eq 'Reused' -and $reused.SourceCheckId -eq 11) 'Cached queries preserve origin and are not claimed as executed again.'
    Assert-Verification ($reused.Detail -match 'Keep query context') 'Cached queries retain target/context details.'
    Assert-Verification ($script:Context.Cache['verification-fixture'].Commands[0].State -eq 'Attempted') 'Cache replay does not mutate the original record.'
    Add-CheckCommand PowerShell 'same query'
    Add-CheckCommand PowerShell 'same query'
    Assert-Verification ($script:Current.Verification.Commands[1].Count -eq 2) 'Repeated queries are counted.'
    Reset-VerificationCheck
    1..1002 | ForEach-Object { Add-CheckCommand PowerShell "query $_" }
    Assert-Verification ($script:Current.Verification.Commands.Count -eq 1000 -and $script:Current.Verification.OmittedCommandCount -eq 2) 'Command recording is bounded and reports omissions.'
    $canary='NEVER_DISCLOSE_COMMAND_SECRET_9137'
    Assert-Verification ((Get-HelperVerificationArguments 'C:\Windows\System32\net.exe' 'accounts') -ceq 'accounts') 'Known fixed process arguments are retained.'
    Assert-Verification ((Get-HelperVerificationArguments 'C:\Windows\System32\net.exe' "accounts $canary") -notmatch $canary) 'An allowed executable does not allow arbitrary arguments.'
    Assert-Verification ((Get-HelperVerificationArguments 'powershell.exe' "-EncodedCommand $canary") -notmatch $canary) 'Encoded scripts are redacted.'
    Reset-VerificationCheck
    try { Invoke-ReadOnlyCommand (Join-Path $script:ModuleRoot 'missing-fixture.exe') $canary | Out-Null } catch { }
    Assert-Verification ($script:Current.Verification.Commands.Count -eq 1 -and $script:Current.Verification.Commands[0].State -eq 'Attempted') 'Failed process starts retain a record.'
    Assert-Verification (($script:Current.Verification | ConvertTo-Json -Depth 10) -notmatch $canary) 'Failed helper records do not leak arguments.'
    & {
        function Invoke-IdentityCheck { param([int]$Id) throw 'Fixture failure' }
        Reset-VerificationCheck
        try { Invoke-Check 1 } catch { }
        Assert-Verification ($script:Current.Verification.CollectorStarted -and $script:Current.Verification.Commands[0].Command -eq 'Invoke-IdentityCheck -Id 1') 'Collector errors keep the dispatcher invocation.'
    }
    $scratch=Join-Path ([IO.Path]::GetTempPath()) ('StealthPrivesc-verification-'+[Guid]::NewGuid().ToString('N'))
    try {
        $report=Invoke-StealthPrivesc -CheckId 1,3,7,47,67,70,100,132 -MaxItems 10 -OutputDirectory $scratch -PassThru
        Assert-Verification ($report.SchemaVersion -eq '1.5') 'Verification and correlation fields use the current schema.'
        foreach ($check in $report.Checks) {
            Assert-Verification ($check.Verification.RerunCommand -match "-CheckId $($check.Id) ") 'Every selected check has a rerun command.'
            if ($check.Id -in @(67,70,132)) {
                Assert-Verification ($check.Status -eq 'Skipped' -and -not $check.Verification.CollectorStarted -and $check.Verification.Commands.Count -eq 0) 'Gated checks have no claimed executions.'
            } else {
                Assert-Verification ($check.Verification.CollectorStarted -and $check.Verification.Commands[0].Kind -eq 'Collector') 'Every invoked collector is recorded, including checks without findings.'
            }
        }
        $account=$report.Checks | Where-Object Id -eq 7
        Assert-Verification (@($account.Verification.Commands | Where-Object { $_.Kind -eq 'Process' -and $_.Command.EndsWith("net.exe' accounts") }).Count -eq 1) 'The real account-policy helper is recorded as a usable PowerShell command.'
        $uac=$report.Checks | Where-Object Id -eq 100
        Assert-Verification (@($uac.Verification.Commands | Where-Object { $_.Kind -eq 'PowerShell' -and $_.Command -match 'CurrentVersion\\Policies\\System' }).Count -gt 0) 'Concrete registry query paths are recorded.'
        $html=Get-Content (Get-ChildItem -LiteralPath $scratch -Filter '*.html').FullName -Raw
        $json=Get-Content (Get-ChildItem -LiteralPath $scratch -Filter '*.json').FullName -Raw | ConvertFrom-Json
        Assert-Verification ($html -match 'Commands and verification' -and $html -match 'not an execution trace' -and $html -match 'No check commands were run') 'HTML distinguishes execution, reference code and skips.'
        Assert-Verification ($json.Checks.Count -eq 8 -and $json.Checks[0].Verification.Commands[0].Command -eq 'Invoke-IdentityCheck -Id 1') 'JSON retains structured details.'
        Reset-VerificationCheck
        Add-CheckCommand PowerShell '<script>alert(1)</script>' -Detail '<img src=x>'
        $script:Current.Verification.SourceReferences=@([pscustomobject]@{Expression='<script>source</script>';Source='<script>';Line=1})
        $escaped=ConvertTo-VerificationHtml $script:Current.Verification
        Assert-Verification ($escaped -notmatch '<script>|<img' -and $escaped -match '&lt;script&gt;') 'HTML verification fields escape untrusted text.'
        Write-Host "PASS: $script:VerificationAssertions verification assertions."
    } finally {
        $resolved=[IO.Path]::GetFullPath($scratch)
        $tempRoot=[IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\','/')+[IO.Path]::DirectorySeparatorChar
        if (-not $resolved.StartsWith($tempRoot,[StringComparison]::OrdinalIgnoreCase) -or [IO.Path]::GetFileName($resolved) -notmatch '^StealthPrivesc-verification-[a-f0-9]{32}$') { throw 'Unsafe verification cleanup path.' }
        if (Test-Path -LiteralPath $resolved) { Remove-Item -LiteralPath $resolved -Recurse -Force }
    }
}
