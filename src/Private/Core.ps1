function Add-Evidence {
    param([string]$Target, [string]$Observation, [object]$Evidence = @{}, [ValidateSet('Information','Low','Medium','High')][string]$Severity = 'Information', [string]$Remediation = '')
    if ($script:Current.Findings.Count -ge $script:Context.MaxItems) { Set-CheckPartial 'Finding limit reached; results are truncated.'; return }
    $script:Current.Findings.Add([pscustomobject]@{ Severity=$Severity; Target=$Target; Observation=$Observation; Evidence=$Evidence; Remediation=$Remediation })
}
function Set-CheckPartial {
    param([string]$Reason, [System.Management.Automation.ErrorRecord]$ErrorRecord)
    if ($script:Current.Status -eq 'Completed') { $script:Current.Status = 'Partial' }
    if (-not $script:Current.Limitations.Contains($Reason)) { $script:Current.Limitations.Add($Reason) }
    Add-CheckDiagnostic -Reason $Reason -ErrorRecord $ErrorRecord
}
function Set-CheckSkipped {
    param([string]$Reason, [string]$SkipReason = 'PrerequisiteMissing', [string]$RequiredSwitch = '')
    $script:Current.Status='Skipped'; $script:Current.Limitations.Add($Reason)
    Add-CheckDiagnostic -Reason $Reason -Level Warning -SkipReason $SkipReason -RequiredSwitch $RequiredSwitch
}
function Get-Cached {
    param([string]$Key, [scriptblock]$Factory)
    $cacheHit = $script:Context.Cache.ContainsKey($Key)
    if (-not $script:Context.Cache.ContainsKey($Key)) {
        $before=@($script:Current.Limitations)
        $diagnosticsBefore = if ($script:Current.Contains('Diagnostics')) { @($script:Current.Diagnostics | ForEach-Object { $_ }) } else { @() }
        $commandsBefore = if ($script:Current.Contains('Verification')) { @($script:Current.Verification.Commands | ForEach-Object { $_ | Select-Object * }) } else { @() }
        $omittedBefore = if ($script:Current.Contains('Verification')) { $script:Current.Verification.OmittedCommandCount } else { 0 }
        $data=@(& $Factory)
        $diagnostics = if ($script:Current.Contains('Diagnostics')) { @($script:Current.Diagnostics | Where-Object { $_ -notin $diagnosticsBefore }) } else { @() }
        $commands = if ($script:Current.Contains('Verification')) { @(foreach ($entry in $script:Current.Verification.Commands) {
            $previous = @($commandsBefore | Where-Object { $_.Kind -eq $entry.Kind -and $_.Command -ceq $entry.Command -and $_.State -eq $entry.State -and $_.SourceCheckId -eq $entry.SourceCheckId -and $_.Detail -ceq $entry.Detail })
            if (-not $previous.Count -or $entry.Count -gt $previous[0].Count) { $entry | Select-Object * }
        }) } else { @() }
        $omitted = if ($script:Current.Contains('Verification')) { $script:Current.Verification.OmittedCommandCount - $omittedBefore } else { 0 }
        $script:Context.Cache[$Key] = @{Data=$data;Limitations=@($script:Current.Limitations|Where-Object{$_ -notin $before});Diagnostics=$diagnostics;Commands=$commands;OmittedCommands=$omitted}
    }
    if ($cacheHit -and $script:Context.Cache[$Key].ContainsKey('Commands')) {
        foreach ($entry in $script:Context.Cache[$Key].Commands) {
            Add-CheckCommand -Kind $entry.Kind -Command $entry.Command -State Reused -SourceCheckId $entry.SourceCheckId -Detail "Reused cached inventory: $Key. The query was not rerun for this check. $($entry.Detail)"
        }
        if ($script:Current.Contains('Verification')) { $script:Current.Verification.OmittedCommandCount += $script:Context.Cache[$Key].OmittedCommands }
    }
    foreach($limitation in $script:Context.Cache[$Key].Limitations){
        if ($script:Current.Status -eq 'Completed') { $script:Current.Status = 'Partial' }
        if (-not $script:Current.Limitations.Contains($limitation)) { $script:Current.Limitations.Add($limitation) }
    }
    foreach ($cached in $script:Context.Cache[$Key].Diagnostics) {
        if (-not $script:Current.Contains('Diagnostics')) { $script:Current['Diagnostics'] = New-Object 'System.Collections.Generic.List[object]' }
        if (@($script:Current.Diagnostics | Where-Object { $_.Summary -eq $cached.Summary -and $_.Code -eq $cached.Code }).Count) { continue }
        $copy = $cached.PSObject.Copy()
        $copy.TimestampUtc = [DateTime]::UtcNow.ToString('o')
        $copy.CheckId = if ($script:Current.Contains('Id')) { $script:Current.Id } else { $null }
        $copy.CheckTitle = if ($script:Current.Contains('Title')) { $script:Current.Title } else { '' }
        $copy.RetryCommand = if ($null -ne $copy.CheckId -and $cached.RetryCommand) { $cached.RetryCommand -replace '-CheckId \d+', "-CheckId $($copy.CheckId)" } else { $null }
        $script:Current.Diagnostics.Add($copy)
        Write-DiagnosticLog $copy
        Write-Verbose (Format-AssessmentDiagnostic $copy)
    }
    $script:Context.Cache[$Key].Data
}
function Get-Services { Get-Cached 'Services' { Add-CheckCommand PowerShell 'Get-CimInstance Win32_Service -ErrorAction Stop'; Get-CimInstance Win32_Service -ErrorAction Stop | Select-Object Name,DisplayName,PathName,StartName,StartMode,State,ProcessId } }
function Get-Tasks { Get-Cached 'Tasks' { Add-CheckCommand PowerShell 'Get-ScheduledTask -ErrorAction Stop'; Get-ScheduledTask -ErrorAction Stop } }
function Get-Applications {
    Get-Cached 'Applications' {
        foreach ($root in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall','HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall')) {
            foreach ($key in @(Get-RegistryChildren $root)) {
                Add-CheckCommand PowerShell ('Get-ItemProperty -LiteralPath ' + (ConvertTo-VerificationLiteral $key.PSPath) + ' -ErrorAction Stop')
                $v = Get-ItemProperty -LiteralPath $key.PSPath -ErrorAction Stop
                if ($v.PSObject.Properties['DisplayName']) {
                    [pscustomobject]@{ Name=$v.DisplayName; Version=$(if($v.PSObject.Properties['DisplayVersion']){$v.DisplayVersion}); Publisher=$(if($v.PSObject.Properties['Publisher']){$v.Publisher}); Location=$(if($v.PSObject.Properties['InstallLocation']){$v.InstallLocation}) }
                }
            }
        }
    }
}
function Get-RegistryChildren {
    param([string]$Path)
    if($script:RegistryVisited -ge $script:Context.MaxItems){Set-CheckPartial 'Registry enumeration item limit reached.';return}
    try {
        $remaining=$script:Context.MaxItems-$script:RegistryVisited
        Add-CheckCommand PowerShell ('Get-ChildItem -LiteralPath ' + (ConvertTo-VerificationLiteral $Path) + " -ErrorAction Stop | Select-Object -First $($remaining+1)")
        $children=@(Get-ChildItem -LiteralPath $Path -ErrorAction Stop | Select-Object -First ($remaining+1))
        if($children.Count-gt$remaining){Set-CheckPartial 'Registry enumeration item limit reached.'}
        $script:RegistryVisited += [Math]::Min($children.Count,$remaining)
        $children|Select-Object -First $remaining
    }
    catch [System.Management.Automation.ItemNotFoundException] { @() }
    catch { Set-CheckPartial "Cannot enumerate registry key: $Path" -ErrorRecord $_; @() }
}
function Read-Registry {
    param([string]$Path, [string]$Name)
    try {
        Add-CheckCommand PowerShell ('Get-Item -LiteralPath ' + (ConvertTo-VerificationLiteral $Path) + ' -ErrorAction Stop')
        $key = Get-Item -LiteralPath $Path -ErrorAction Stop
        try {
            Add-CheckCommand NativeApi ('$key.GetValueNames()') -Detail ('Registry key: ' + $Path)
            if ($Name -notin $key.GetValueNames()) { return [pscustomobject]@{ State='Absent'; Value=$null } }
            Add-CheckCommand NativeApi ('$key.GetValue(' + (ConvertTo-VerificationLiteral $Name) + ',$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)') -Detail ('Registry key: ' + $Path + '. Set $key with the preceding Get-Item; close it after inspection. Values are not logged.')
            [pscustomobject]@{ State='Present'; Value=$key.GetValue($Name,$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames) }
        } finally { $key.Close() }
    } catch [System.Management.Automation.ItemNotFoundException] { [pscustomobject]@{ State='Absent'; Value=$null } }
    catch { Set-CheckPartial "Cannot read registry value: $Path [$Name]" -ErrorRecord $_; [pscustomobject]@{ State='Unknown'; Value=$null } }
}
function Add-RegistryEvidence {
    param([string]$Path, [string[]]$Names, [string[]]$SensitiveNames = @())
    foreach ($name in $Names) {
        $r=Read-Registry $Path $name
        $value=$r.Value
        if ($name -in $SensitiveNames -or $name -match '(?i)^(Password|DefaultPassword|PasswordViewOnly)$|secret|token|credential' -or $name -in @('AutoConfigURL','ProxyServer')) { $value=$(if($r.State -eq 'Present'){'[REDACTED]'}) }
        Add-Evidence "$Path\$name" 'Registry configuration; absent values may use OS defaults.' @{ State=$r.State; Value=$value }
    }
}
function Get-Limited {
    param([object[]]$Items)
    if ($Items.Count -gt $script:Context.MaxItems) { Set-CheckPartial 'Item limit reached; results are truncated.' }
    $Items | Select-Object -First $script:Context.MaxItems
}
function Get-BoundedFiles {
    param([string[]]$Roots, [int]$Depth=3, [string]$Pattern='.*', [switch]$Directories)
    $queue=New-Object 'System.Collections.Generic.Queue[object]'
    foreach($root in $Roots) { if($root -and (Test-AllowedLocalPath $root)){ $queue.Enqueue(@($root,0)) } }
    $visited=0
    while($queue.Count -and $visited -lt $script:Context.MaxItems) {
        $entry=$queue.Dequeue()
        try {
            Add-CheckCommand PowerShell ('Get-Item -LiteralPath ' + (ConvertTo-VerificationLiteral $entry[0]) + ' -Force -ErrorAction Stop')
            $rootItem=Get-Item -LiteralPath $entry[0] -Force -ErrorAction Stop
            if($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint){Set-CheckPartial 'Reparse-point traversal skipped.';continue}
            Add-CheckCommand PowerShell ('Get-ChildItem -LiteralPath ' + (ConvertTo-VerificationLiteral $entry[0]) + " -Force -ErrorAction Stop | Select-Object -First $($script:Context.MaxItems+1)")
            $children=@(Get-ChildItem -LiteralPath $entry[0] -Force -ErrorAction Stop | Select-Object -First ($script:Context.MaxItems + 1))
        } catch [System.Management.Automation.ItemNotFoundException] { continue }
        catch { Set-CheckPartial "Cannot enumerate directory: $($entry[0])" -ErrorRecord $_; continue }
        foreach($item in $children) {
            $visited++
            if($visited -gt $script:Context.MaxItems){ break }
            if($item.Attributes -band [IO.FileAttributes]::ReparsePoint){ continue }
            if(($Directories -or -not $item.PSIsContainer) -and $item.Name -match $Pattern){ $item }
            if($item.PSIsContainer -and $entry[1] -lt $Depth){ $queue.Enqueue(@($item.FullName,($entry[1]+1))) }
        }
    }
    if($queue.Count -or $visited -ge $script:Context.MaxItems){ Set-CheckPartial 'Filesystem traversal item limit reached.' }
}
function Get-ExecutablePath {
    param([string]$Command)
    if([string]::IsNullOrWhiteSpace($Command)){ return $null }
    $expanded=[Environment]::ExpandEnvironmentVariables($Command.Trim())
    if($expanded -match '^"([^"]+)"'){ return $Matches[1] }
    if($expanded -match '^(.*?\.(?:exe|com|sys|bat|cmd|ps1|vbs|dll))(?=\s|$)'){ return $Matches[1] }
    return ($expanded -split '\s+',2)[0]
}
function Get-UnquotedCandidates {
    param([string]$Command)
    if(-not $Command -or $Command.TrimStart().StartsWith('"')){ return }
    $path=Get-ExecutablePath $Command
    if(-not $path -or $path -notmatch '\s' -or -not [IO.Path]::IsPathRooted($path)){ return }
    foreach($match in [regex]::Matches($path,'\s+')) {
        $candidate=$path.Substring(0,$match.Index)
        if(-not $candidate.EndsWith('.exe',[StringComparison]::OrdinalIgnoreCase)){ $candidate += '.exe' }
        $candidate
    }
}
function Test-PathAccess {
    param([string]$Path, [switch]$Registry)
    try {
        if(-not $Registry -and -not (Test-AllowedLocalPath $Path)){return $null}
        Add-CheckCommand PowerShell ('Get-Acl -LiteralPath ' + (ConvertTo-VerificationLiteral $Path) + ' -ErrorAction Stop')
        $acl=Get-Acl -LiteralPath $Path -ErrorAction Stop
        $descriptor=$acl.GetSecurityDescriptorBinaryForm()
        $rights=if($Registry){ @{SetValue=2;CreateSubKey=4;WriteDacl=0x40000;WriteOwner=0x80000} } else { @{WriteDataOrAddFile=2;AppendOrAddDirectory=4;Delete=0x10000;WriteDacl=0x40000;WriteOwner=0x80000} }
        $allowed=@()
        foreach($right in $rights.Keys){
            Add-CheckCommand NativeApi ('[StealthPrivesc.Native]::CheckAccess($descriptor,[uint32]' + $rights[$right] + ',[bool]$' + ([bool]$Registry).ToString().ToLowerInvariant() + ')') -Detail ('Target: ' + $Path + '. $descriptor is the binary form of the preceding ACL; requires the module native type.')
            $access=[StealthPrivesc.Native]::CheckAccess($descriptor,[uint32]$rights[$right],[bool]$Registry)
            if($access.Error){ Set-CheckPartial "AccessCheck failed for $Path (Win32 $($access.Error))." }
            elseif($access.Allowed){ $allowed+=$right }
        }
        [pscustomobject]@{ Path=$Path; Rights=$allowed; Owner=$acl.Owner; Method='Windows AccessCheck (DACL); mandatory integrity, locks and execution context require validation.' }
    } catch [System.Management.Automation.ItemNotFoundException] { $null }
    catch { Set-CheckPartial "Cannot assess ACL: $Path" -ErrorRecord $_; $null }
}
function Add-WritablePath {
    param([string]$Path, [string]$Reason, [switch]$Registry)
    if(-not $Path){ return }
    if(-not $Registry -and -not [IO.Path]::IsPathRooted($Path)){ Set-CheckPartial "Relative target needs working-directory resolution: $Path"; return }
    $access=Test-PathAccess $Path -Registry:$Registry
    if($access -and $access.Rights.Count){
        $severity=if($script:Context.Elevated){'Information'}else{'Medium'}
        Add-Evidence $Path $Reason $access $severity 'Review the ACL and remove unnecessary write/control rights. Validate the execution account and trigger before treating this as an escalation path.'
    }
}
function Add-ExecutableAccess {
    param([string]$Command, [string]$Reason)
    $path=Get-ExecutablePath $Command
    if(-not $path){return}
    Add-WritablePath $path $Reason
    if([IO.Path]::IsPathRooted($path)){ Add-WritablePath ([IO.Path]::GetDirectoryName($path)) "$Reason (parent directory candidate; replacement semantics require validation)." }
}
function Invoke-ReadOnlyCommand {
    param([string]$FileName, [string]$Arguments)
    $recordedArguments = Get-HelperVerificationArguments $FileName $Arguments
    Add-CheckCommand Process (('& ' + (ConvertTo-VerificationLiteral $FileName) + ' ' + $recordedArguments).TrimEnd()) -Detail 'ProcessStartInfo invocation with UseShellExecute=false, displayed in PowerShell syntax for manual use. Arguments are verbatim only for known fixed queries; other payloads are redacted. A start failure, nonzero exit or timeout is reported in Diagnostics.'
    $info=New-Object Diagnostics.ProcessStartInfo
    $info.FileName=$FileName; $info.Arguments=$Arguments; $info.UseShellExecute=$false; $info.CreateNoWindow=$true
    $info.RedirectStandardOutput=$true; $info.RedirectStandardError=$true
    $process=New-Object Diagnostics.Process
    $process.StartInfo=$info
    try {
        [void]$process.Start()
        $stdout=$process.StandardOutput.ReadToEndAsync(); $stderr=$process.StandardError.ReadToEndAsync()
        if(-not $process.WaitForExit($script:Context.CommandTimeoutSeconds*1000)){
            $failure = [TimeoutException]::new('Read-only helper exceeded its time limit.')
            $failure.Data['StealthPrivesc.TimeoutSeconds'] = [int]$script:Context.CommandTimeoutSeconds
            # Preserve the timeout diagnosis if the process exits while being killed.
            try { $process.Kill() } catch [InvalidOperationException] { }
            throw $failure
        }
        if($process.ExitCode -ne 0){
            $failure = [InvalidOperationException]::new('Read-only helper returned a nonzero exit code.')
            $failure.Data['StealthPrivesc.ExitCode'] = [int]$process.ExitCode
            throw $failure
        }
        $stdout.GetAwaiter().GetResult()
    } finally { $process.Dispose() }
}
function Find-SecretMarkers {
    param([string]$Path)
    try {
        if(-not (Test-AllowedLocalPath $Path)){return}
        $file=Get-Item -LiteralPath $Path -Force -ErrorAction Stop
        if($file.PSIsContainer -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint)){return}
        if($file.Length -gt $script:Context.MaxFileBytes){ Set-CheckPartial 'Some files exceeded MaxFileBytes and were not read.'; return }
        # Content and matched values never enter the report.
        $content=[IO.File]::ReadAllText($file.FullName)
        $patterns=[ordered]@{
            PasswordAssignment='(?i)(?:password|passwd|pwd|cpassword)\s*["'']?\s*[:=]|<Password>|<Value>.*</Value>\s*</Password>'
            TokenAssignment='(?i)(?:api[_-]?key|access[_-]?token|client[_-]?secret|secret[_-]?access[_-]?key)\s*["'']?\s*[:=]'
            PrivateKey='-----BEGIN (?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----'
            ConnectionString='(?i)(?:connectionString|AccountKey|SharedAccessSignature)\s*='
        }
        $markers=@($patterns.Keys | Where-Object { [regex]::IsMatch($content,$patterns[$_]) })
        if($markers.Count){ Add-Evidence $file.FullName 'Possible secret-bearing content; values redacted, heuristic requires review.' @{Markers=$markers;Values='[REDACTED]';Bytes=$file.Length} 'Medium' 'Remove embedded secrets, restrict access and rotate exposed credentials after confirming exposure.' }
    } catch [System.Management.Automation.ItemNotFoundException] { }
    catch { Set-CheckPartial "Cannot inspect file: $Path" -ErrorRecord $_ }
}
function Add-Artifact {
    param([string]$Path,[string]$Kind,[switch]$Inspect)
    try {
        if(-not (Test-AllowedLocalPath $Path)){return}
        $item=Get-Item -LiteralPath $Path -Force -ErrorAction Stop
        Add-Evidence $item.FullName "$Kind artifact present; presence alone does not prove credential exposure." @{IsDirectory=$item.PSIsContainer;LastWriteUtc=$item.LastWriteTimeUtc.ToString('o');Values='[REDACTED]'}
        if($Inspect -and -not $item.PSIsContainer){ Find-SecretMarkers $item.FullName }
    } catch [System.Management.Automation.ItemNotFoundException] { }
    catch { Set-CheckPartial "Cannot inspect artifact: $Path" -ErrorRecord $_ }
}
function Test-AllowedLocalPath {
    param([string]$Path)
    # Local Win32 extended/device paths are not UNC shares. Extended UNC stays gated.
    if($Path-match'^\\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy\d+\\'){return $true}
    if($Path-match'^\\\\\?\\[A-Za-z]:\\'){$Path=$Path.Substring(4)}
    # Network/domain opt-ins also govern UNC targets embedded in local configuration.
    if($script:Context.IncludeNetwork -or $script:Context.IncludeDomain){return $true}
    if($Path -match '^[\\/]{2}' -or $Path -match '^[^:]+::[\\/]{2}'){
        Set-CheckPartial 'Network filesystem target skipped; use -IncludeNetwork or -IncludeDomain.';return $false
    }
    if($Path-match'^[A-Za-z]:'){
        try{$drive=New-Object IO.DriveInfo($Path.Substring(0,3));if($drive.DriveType-eq[IO.DriveType]::Network){Set-CheckPartial 'Mapped network-drive target skipped.';return $false}}catch{}
    }
    return $true
}
function Export-Assessment {
    param([object]$Report,[string]$Directory,[hashtable]$Paths)
    if (-not $Paths) { $Paths = Initialize-AssessmentOutput -Directory $Directory }
    $jsonPath=$Paths.Json
    $htmlPath=$Paths.Html
    $Report | ConvertTo-Json -Depth 16 | Set-Content -LiteralPath $jsonPath -Encoding UTF8
    $html=New-Object Text.StringBuilder
    [void]$html.Append('<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Windows exposure assessment</title><style>body{font:16px system-ui;max-width:1100px;margin:40px auto;padding:0 24px;background:#101820;color:#e5edf3}h1,h2{color:#82d4d4}article{border:1px solid #38505c;padding:16px;margin:16px 0}pre{white-space:pre-wrap;overflow-wrap:anywhere}small{color:#b9cbd5}.High,.Medium{border-left:4px solid #ffbd69}summary{cursor:pointer}table{border-collapse:collapse}td,th{padding:8px;border:1px solid #38505c}</style><h1>Windows exposure assessment</h1>')
    [void]$html.Append('<p>'+[Net.WebUtility]::HtmlEncode($Report.Notice)+'</p><p>'+[Net.WebUtility]::HtmlEncode("$($Report.Computer) | $($Report.User) | Elevated: $($Report.Elevated) | $($Report.StartedUtc)")+'</p>')
    [void]$html.Append('<section aria-labelledby="status-summary"><h2 id="status-summary">Check status summary</h2><table><thead><tr><th scope="col">Status</th><th scope="col">Count</th></tr></thead><tbody>')
    foreach($status in @('Completed','Partial','Skipped','Unsupported','Error')){
        $count=$Report.Summary[$status]
        if($null-eq$count){$count=0}
        [void]$html.Append('<tr><th scope="row">'+[Net.WebUtility]::HtmlEncode($status)+'</th><td>'+[Net.WebUtility]::HtmlEncode([string]$count)+'</td></tr>')
    }
    [void]$html.Append('</tbody></table></section>')
    $analysis = Get-AttackPathValue $Report 'AttackPathAnalysis'
    if ($analysis) { [void]$html.Append((ConvertTo-AttackPathHtml $analysis)) }
    $hasSkipSummary = if ($Report -is [Collections.IDictionary]) { $Report.Contains('SkippedChecks') } else { [bool]$Report.PSObject.Properties['SkippedChecks'] }
    if ($hasSkipSummary) {
        $skippedChecks = @($Report.SkippedChecks)
        [void]$html.Append('<section aria-labelledby="skipped-checks"><h2 id="skipped-checks">Skipped checks: ' + @($skippedChecks).Count + '</h2>')
        if (@($skippedChecks).Count -eq 0) { [void]$html.Append('<p>No selected checks were marked as skipped. Review run errors, partial and unsupported results separately.</p>') }
        foreach ($skipped in $skippedChecks) {
            [void]$html.Append('<h3>' + [Net.WebUtility]::HtmlEncode("$($skipped.CheckId). $($skipped.Title)") + '</h3><p><strong>Why it did not run:</strong> ' + [Net.WebUtility]::HtmlEncode($skipped.Explanation) + '</p><ol>')
            foreach ($action in $skipped.SuggestedActions) { [void]$html.Append('<li>' + [Net.WebUtility]::HtmlEncode($action) + '</li>') }
            [void]$html.Append('</ol><p><strong>Retry selector:</strong> <code>' + [Net.WebUtility]::HtmlEncode($skipped.RetryCommand) + '</code> (keep your original paths and output options).</p><p>' + [Net.WebUtility]::HtmlEncode($skipped.Verification) + '</p>')
        }
        [void]$html.Append('</section>')
    }
    $runDiagnostics = if ($Report -is [Collections.IDictionary]) { $Report['Diagnostics'] } elseif ($Report.PSObject.Properties['Diagnostics']) { $Report.Diagnostics }
    if ($runDiagnostics) {
        [void]$html.Append('<h2>Run troubleshooting</h2>' + ((ConvertTo-DiagnosticHtml @($runDiagnostics | ForEach-Object { $_ })) -join ''))
    }
    foreach($check in $Report.Checks){
        [void]$html.Append('<article><h2>'+[Net.WebUtility]::HtmlEncode("$($check.Id). $($check.Title)")+'</h2><p>'+[Net.WebUtility]::HtmlEncode("$($check.Status) / $($check.Coverage) | $($check.Findings.Count) evidence items")+'</p>')
        foreach($limitation in $check.Limitations){[void]$html.Append('<p><small>'+[Net.WebUtility]::HtmlEncode($limitation)+'</small></p>')}
        if ($check.PSObject.Properties['Verification']) {
            [void]$html.Append((ConvertTo-VerificationHtml $check.Verification))
        }
        if ($check.PSObject.Properties['Diagnostics']) {
            [void]$html.Append(((ConvertTo-DiagnosticHtml @($check.Diagnostics | ForEach-Object { $_ })) -join ''))
        }
        $findingIndex = 0
        foreach($finding in $check.Findings){
            [void]$html.Append('<details id="check-'+[int]$check.Id+'-finding-'+$findingIndex+'" class="'+$finding.Severity+'"><summary>'+[Net.WebUtility]::HtmlEncode("[$($finding.Severity)] $($finding.Target): $($finding.Observation)")+'</summary><pre>'+[Net.WebUtility]::HtmlEncode(($finding.Evidence | ConvertTo-Json -Depth 12))+'</pre><p>'+[Net.WebUtility]::HtmlEncode($finding.Remediation)+'</p></details>')
            $findingIndex++
        }
        [void]$html.Append('</article>')
    }
    [void]$html.Append('</html>')
    [IO.File]::WriteAllText($htmlPath,$html.ToString())
    Write-Host "Reports: $jsonPath and $htmlPath"
    Write-Host "Troubleshooting log: $($Paths.Log)"
}
function Read-SafeXml {
    param([string]$Path)
    $settings=New-Object Xml.XmlReaderSettings
    $settings.DtdProcessing=[Xml.DtdProcessing]::Prohibit
    $settings.XmlResolver=$null
    $settings.MaxCharactersInDocument=$script:Context.MaxFileBytes
    $reader=[Xml.XmlReader]::Create($Path,$settings)
    try{$document=New-Object Xml.XmlDocument;$document.XmlResolver=$null;$document.Load($reader);return ,$document}
    finally{$reader.Dispose()}
}
