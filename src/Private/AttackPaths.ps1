# This engine consumes report data only. It must never probe the host or execute
# report strings; a correlated path is a candidate, not a demonstrated exploit.
function Get-AttackPathValue {
    param([object]$Object, [string]$Name)
    if ($null -eq $Object) { return $null }
    if ($Object -is [Collections.IDictionary]) { return $Object[$Name] }
    $property = $Object.PSObject.Properties[$Name]
    if ($property) { return $property.Value }
    return $null
}

function Test-AttackPathSystemAccount {
    param([object]$Account)
    [string]$Account -in @('SYSTEM','LocalSystem','NT AUTHORITY\SYSTEM','S-1-5-18')
}

function ConvertTo-AttackPathFileKey {
    param([object]$Path)
    if ($Path -isnot [string] -or -not $Path) { return $null }
    $value = $Path.Replace('/','\') -replace '^(Microsoft\.PowerShell\.Core\\)?FileSystem::',''
    if ($value.StartsWith('\\?\UNC\',[StringComparison]::OrdinalIgnoreCase)) { $value = '\\' + $value.Substring(8) }
    elseif ($value.StartsWith('\\?\')) { $value = $value.Substring(4) }
    # Never resolve relative paths, environment variables, wildcards, symlinks or
    # short names against the machine performing this offline analysis.
    if ($value -notmatch '^(?:[a-zA-Z]:\\|\\\\[^\\]+\\[^\\]+\\)' -or $value -match '[%*?\x00]|(^|\\)\.{1,2}(\\|$)') { return $null }
    if ($value.Length -gt 3) { $value = $value.TrimEnd('\') }
    $value.ToLowerInvariant()
}

function Get-AttackPathParentKey {
    param([string]$Path)
    $position = $Path.LastIndexOf('\')
    if ($position -eq 2 -and $Path[1] -eq ':') { return $Path.Substring(0,3) }
    if ($position -gt 2) { return $Path.Substring(0,$position) }
    return $null
}

function Get-AttackPathRules {
    @(
        [pscustomobject]@{Id='ServiceConfiguration'; Title='SYSTEM service configuration control'; Checks=@(11,12); AccessChecks=@(12)}
        [pscustomobject]@{Id='ServiceRegistry'; Title='SYSTEM service registry control'; Checks=@(11,14); AccessChecks=@(14)}
        [pscustomobject]@{Id='ServiceImage'; Title='Writable SYSTEM service executable'; Checks=@(11,16); AccessChecks=@(16)}
        [pscustomobject]@{Id='ServiceUnquotedPath'; Title='Writable unquoted SYSTEM service path'; Checks=@(11,17); AccessChecks=@(17)}
        [pscustomobject]@{Id='TaskDefinition'; Title='Enabled SYSTEM task definition control'; Checks=@(22,24); AccessChecks=@(24)}
        [pscustomobject]@{Id='TaskImage'; Title='Writable enabled SYSTEM task executable'; Checks=@(22,23); AccessChecks=@(23)}
    )
}

function Add-AttackPathIndexEntry {
    param([hashtable]$Index, [string]$Key, [object]$Entry)
    if (-not $Key) { return }
    if (-not $Index.ContainsKey($Key)) { $Index[$Key] = New-Object 'System.Collections.Generic.List[object]' }
    $Index[$Key].Add($Entry)
}

function New-AttackPathCandidate {
    param([object]$Report, [object]$Rule, [object]$Inventory, [object[]]$Controls, [object[]]$Supporting,
        [string]$Resource, [string]$Relation, [bool]$Indirect, [bool]$InputTruncated)
    $refs = @(@($Inventory) + @($Controls) + @($Supporting) | Where-Object { $null -ne $_ } | Sort-Object CheckId,FindingIndex -Unique)
    $sourceChecks = @($refs | Select-Object -ExpandProperty CheckId -Unique)
    $incomplete = $InputTruncated -or @($refs | Where-Object CheckStatus -ne 'Completed').Count -gt 0 -or (Get-AttackPathValue $Report 'RunStatus') -ne 'Completed'
    $elevated = Get-AttackPathValue $Report 'Elevated'
    $assessment = if ($elevated -is [bool] -and -not $elevated) { 'PotentialPrivilegeEscalation' } elseif ($elevated -eq $true) { 'PrivilegedAuditExposure' } else { 'UnknownStartingPrivilege' }
    $confidence = if ($incomplete -or $assessment -eq 'UnknownStartingPrivilege') { 'Limited' } elseif ($Indirect) { 'Conditional' } else { 'Corroborated' }
    $priority = if ($assessment -eq 'PrivilegedAuditExposure') { 'Information' } elseif ($confidence -eq 'Corroborated') { 'High' } else { 'Medium' }
    $isTask = $Rule.Id.StartsWith('Task')
    $prerequisites = New-Object 'System.Collections.Generic.List[string]'
    $prerequisites.Add('Confirm that the account, object and permissions still match this snapshot, including integrity policy and other runtime access restrictions.')
    if ($Indirect) { $prerequisites.Add('Directory creation rights or ownership/DACL control do not establish direct file replacement or object modification; validate the precise access needed.') }
    if ($isTask) {
        $trigger = 'The task was reported enabled; timing, conditions and permission to invoke it are unverified.'
        $prerequisites.Add('Validate the task trigger, scheduler authorization, logon restrictions and application-control policy before treating execution as reachable.')
    } else {
        $rights = @($Supporting | Where-Object CheckId -eq 20 | ForEach-Object { Get-AttackPathValue $_.Evidence 'Right' } | Sort-Object -Unique)
        $trigger = if ($rights.Count) { 'Observed service control rights: ' + ($rights -join ', ') + '. No transition was performed.' } else { 'Service activation or restart capability was not established by the available evidence.' }
        $prerequisites.Add('Validate service activation/reload behavior and application-control policy; a control permission does not establish that modified content will execute.')
        if ($Rule.Id -eq 'ServiceUnquotedPath') { $prerequisites.Add('Validate executable search order and earlier existing candidates; an ambiguous prefix alone does not prove interception.') }
    }
    if ($incomplete) { $prerequisites.Add('Supporting collection or the overall run was incomplete; review source check diagnostics and enumeration limits.') }
    if ($assessment -eq 'PrivilegedAuditExposure') { $prerequisites.Add('The scan already used an elevated token. Reassess as the intended low-privilege identity before claiming escalation.') }
    $identity = [string](Get-AttackPathValue $Report 'UserSid')
    if (-not $identity) { $identity = [string](Get-AttackPathValue $Report 'User') }
    $key = $Rule.Id + '|' + $Inventory.Target.ToLowerInvariant() + '|' + $Resource.ToLowerInvariant()
    $hash = [Security.Cryptography.SHA256]::Create()
    try { $id = 'path-' + ([BitConverter]::ToString($hash.ComputeHash([Text.Encoding]::UTF8.GetBytes($key))).Replace('-','').Substring(0,16).ToLowerInvariant()) }
    finally { $hash.Dispose() }
    $evidenceRefs = @(foreach ($ref in $refs) {
        [pscustomobject]@{CheckId=$ref.CheckId; FindingIndex=$ref.FindingIndex; CheckStatus=$ref.CheckStatus; Target=$ref.Target; Anchor="check-$($ref.CheckId)-finding-$($ref.FindingIndex)"}
    })
    $reruns = @(foreach ($checkId in $sourceChecks) {
        $source = @($refs | Where-Object CheckId -eq $checkId)[0]
        if ($source.RerunCommand) { [pscustomobject]@{CheckId=$checkId; Command=$source.RerunCommand; WorkingDirectory=$source.WorkingDirectory} }
    })
    [pscustomobject]@{
        Id=$id; RuleId=$Rule.Id; Title=$Rule.Title; Priority=$priority; Confidence=$confidence
        Assessment=$assessment; Status='Candidate'; Target=$Inventory.Target; Resource=$Resource
        StartingPrincipal=$identity; Goal='Potential execution in the SYSTEM context'
        Steps=@(
            [pscustomobject]@{Order=1; Description='The scanning token has recorded control over the matched resource.'; Evidence=@($Controls | ForEach-Object { "check-$($_.CheckId)-finding-$($_.FindingIndex)" })}
            [pscustomobject]@{Order=2; Description=$Relation; Evidence=@("check-$($Inventory.CheckId)-finding-$($Inventory.FindingIndex)") + @($Supporting | Where-Object CheckId -ne 20 | ForEach-Object { "check-$($_.CheckId)-finding-$($_.FindingIndex)" })}
            [pscustomobject]@{Order=3; Description=$trigger; Evidence=@($Supporting | Where-Object CheckId -eq 20 | ForEach-Object { "check-$($_.CheckId)-finding-$($_.FindingIndex)" })}
        )
        Prerequisites=$prerequisites.ToArray(); EvidenceReferences=$evidenceRefs; VerificationCommands=$reruns
        Remediation=$(if ($isTask) { 'Restrict write/control rights on the task definition and its executable paths; review the need for the SYSTEM principal.' } else { 'Restrict service, registry and executable-path control to intended administrators; review the service account and quote executable paths.' })
    }
}

function Get-StealthPrivescAttackPathAnalysis {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Report, [ValidateRange(1,10000)][int]$MaxPaths=200,
        [ValidateRange(1,1000000)][int]$MaxEvidence=100000)
    $ErrorActionPreference = 'Stop'
    $rules = @(Get-AttackPathRules)
    $byCheck = @{}; $checks = @{}; $files = @{}; $named = @{}; $registry = @{}
    $scanned = 0; $inputTruncated = $false
    foreach ($check in @(Get-AttackPathValue $Report 'Checks')) {
        $id = [int](Get-AttackPathValue $check 'Id')
        if ($checks.ContainsKey($id)) { throw 'Attack-path analysis requires unique check IDs.' }
        $checks[$id] = $check
        if ((Get-AttackPathValue $check 'Status') -notin @('Completed','Partial','Error')) { continue }
        $index = 0
        foreach ($finding in @(Get-AttackPathValue $check 'Findings')) {
            if ($null -eq $finding) { $index++; continue }
            if ($scanned -ge $MaxEvidence) { $inputTruncated = $true; break }
            $scanned++
            $verification = Get-AttackPathValue $check 'Verification'
            $entry = [pscustomobject]@{
                CheckId=$id; FindingIndex=$index; CheckStatus=[string](Get-AttackPathValue $check 'Status')
                Target=[string](Get-AttackPathValue $finding 'Target'); Evidence=(Get-AttackPathValue $finding 'Evidence')
                RerunCommand=[string](Get-AttackPathValue $verification 'RerunCommand'); WorkingDirectory=[string](Get-AttackPathValue $verification 'WorkingDirectory')
            }
            $index++
            Add-AttackPathIndexEntry $byCheck ([string]$id) $entry
            Add-AttackPathIndexEntry $named ("$id|" + $entry.Target.ToLowerInvariant()) $entry
            if ($id -eq 14) {
                $registryPath = [string](Get-AttackPathValue $entry.Evidence 'Path')
                $registryPath = $registryPath.ToLowerInvariant() -replace '^(microsoft\.powershell\.core\\)?registry::hkey_local_machine','hklm:'
                Add-AttackPathIndexEntry $registry $registryPath.TrimEnd('\') $entry
            }
            if ($id -in @(16,17,23)) {
                $path = ConvertTo-AttackPathFileKey (Get-AttackPathValue $entry.Evidence 'Path')
                $rights = @(Get-AttackPathValue $entry.Evidence 'Rights')
                if ($path -and @($rights | Where-Object { $_ -in @('WriteDataOrAddFile','WriteDacl','WriteOwner') }).Count) { Add-AttackPathIndexEntry $files ("$id|$path") $entry }
            }
        }
    }
    $candidates = @{}
    $candidateBudget = [Math]::Max(2000,$MaxPaths)
    $discoveryLimited = $false
    $coverage = New-Object 'System.Collections.Generic.List[object]'
    foreach ($rule in $rules) {
        $missing = @($rule.Checks | Where-Object { -not $checks.ContainsKey($_) -or (Get-AttackPathValue $checks[$_] 'Status') -in @('Skipped','Unsupported') })
        $partial = @($rule.Checks | Where-Object { $checks.ContainsKey($_) -and (Get-AttackPathValue $checks[$_] 'Status') -ne 'Completed' })
        $ruleCoverage = [pscustomobject]@{RuleId=$rule.Id; Title=$rule.Title; RequiredChecks=$rule.Checks; MissingChecks=$missing; IncompleteChecks=$partial; Status=$(if ($missing.Count) {'MissingInputs'} elseif ($partial.Count -or $inputTruncated) {'LimitedInputs'} else {'Evaluated'})}
        $coverage.Add($ruleCoverage)
        if ($missing.Count) { continue }
        if ($discoveryLimited) { $ruleCoverage.Status = 'NotEvaluatedLimit'; continue }
        $inventoryId = if ($rule.Id.StartsWith('Task')) { 22 } else { 11 }
        foreach ($inventory in @($byCheck[[string]$inventoryId] | ForEach-Object { $_ })) {
            if ($discoveryLimited) { break }
            if (-not $inventory -or -not $inventory.Target) { continue }
            # Conflicting/duplicate inventories are ambiguous; do not invent a join.
            if ($named["$inventoryId|$($inventory.Target.ToLowerInvariant())"].Count -ne 1) { continue }
            if (-not (Test-AttackPathSystemAccount (Get-AttackPathValue $inventory.Evidence 'Account'))) { continue }
            $state = [string](Get-AttackPathValue $inventory.Evidence 'State')
            if ($inventoryId -eq 11) {
                if ((Get-AttackPathValue $inventory.Evidence 'StartMode') -eq 'Disabled') { continue }
            } else {
                $settings = Get-AttackPathValue $inventory.Evidence 'Settings'
                if ($state -eq 'Disabled' -or (Get-AttackPathValue $settings 'Enabled') -ne $true) { continue }
            }
            $supporting = @()
            if ($inventoryId -eq 11) {
                $supporting = @($named["20|$($inventory.Target.ToLowerInvariant())"] | Where-Object { $_ -and (Get-AttackPathValue $_.Evidence 'Right') -in @('Start','Stop') -and (Get-AttackPathValue $_.Evidence 'State') -eq $state })
            }
            $matches = New-Object 'System.Collections.Generic.List[object]'
            if ($rule.Id -eq 'ServiceConfiguration') {
                $controls = @($named["12|$($inventory.Target.ToLowerInvariant())"] | Where-Object { $_ -and (Test-AttackPathSystemAccount (Get-AttackPathValue $_.Evidence 'Account')) -and (Get-AttackPathValue $_.Evidence 'Right') -in @('ChangeConfig','WriteDacl','WriteOwner') })
                if ($controls.Count) { $matches.Add(@{Controls=$controls; Resource=$inventory.Target; Indirect=('ChangeConfig' -notin @($controls | ForEach-Object { Get-AttackPathValue $_.Evidence 'Right' })); Supporting=$supporting; Relation='The exact service name maps the control rights to a service configured to run as SYSTEM.'}) }
            } elseif ($rule.Id -eq 'ServiceRegistry') {
                $key = 'hklm:\system\currentcontrolset\services\' + $inventory.Target.ToLowerInvariant()
                $controls = @($registry[$key] | Where-Object {
                    $_ -and @(Get-AttackPathValue $_.Evidence 'Rights' | Where-Object { $_ -in @('SetValue','WriteDacl','WriteOwner') }).Count -gt 0
                })
                if ($controls.Count) { $matches.Add(@{Controls=$controls; Resource=$key; Indirect=$true; Supporting=$supporting; Relation='The writable registry key exactly identifies the SYSTEM service; consumption of changed configuration still needs validation.'}) }
            } elseif ($rule.Id -eq 'TaskDefinition') {
                $controls = @($named["24|$($inventory.Target.ToLowerInvariant())"] | Where-Object {
                    $context = Get-AttackPathValue (Get-AttackPathValue $_ 'Evidence') 'Context'
                    $_ -and (Test-AttackPathSystemAccount (Get-AttackPathValue $context 'Account')) -and (Get-AttackPathValue $context 'Enabled') -eq $true -and (Get-AttackPathValue $_.Evidence 'Right') -in @('UpdateTask','WriteDacl','WriteOwner')
                })
                if ($controls.Count) { $matches.Add(@{Controls=$controls; Resource=$inventory.Target; Indirect=$true; Supporting=@(); Relation='The task identity matches an enabled task running as SYSTEM; descriptor access does not by itself prove scheduler update authorization.'}) }
            } else {
                $executables = @()
                if ($inventoryId -eq 11) { $executables = @([pscustomobject]@{Path=(Get-AttackPathValue $inventory.Evidence 'Executable'); Supporting=$supporting}) }
                else {
                    $executables = @(foreach ($action in @(Get-AttackPathValue $inventory.Evidence 'Actions')) {
                        if ((Get-AttackPathValue $action 'Type') -eq 'Execute') { [pscustomobject]@{Path=(Get-AttackPathValue (Get-AttackPathValue $action 'Command') 'Executable'); Supporting=@()} }
                    })
                }
                if ($rule.Id -eq 'ServiceUnquotedPath') {
                    $serviceExecutable = ConvertTo-AttackPathFileKey (Get-AttackPathValue $inventory.Evidence 'Executable')
                    $executables = @(foreach ($prefix in @($named["17|$($inventory.Target.ToLowerInvariant())"] | ForEach-Object { $_ })) {
                        if ($prefix -and $serviceExecutable -and (Test-AttackPathSystemAccount (Get-AttackPathValue $prefix.Evidence 'Account')) -and (ConvertTo-AttackPathFileKey (Get-AttackPathValue $prefix.Evidence 'Executable')) -eq $serviceExecutable) {
                            [pscustomobject]@{Path=(Get-AttackPathValue $prefix.Evidence 'InterceptionCandidate'); Supporting=@($supporting)+@($prefix)}
                        }
                    })
                }
                foreach ($executable in $executables) {
                    $path = ConvertTo-AttackPathFileKey $executable.Path
                    if (-not $path) { continue }
                    $parent = Get-AttackPathParentKey $path
                    foreach ($resource in @($path,$parent) | Where-Object { $_ } | Select-Object -Unique) {
                        $controls = @($files["$($rule.AccessChecks[0])|$resource"] | Where-Object { $null -ne $_ })
                        if (-not $controls.Count) { continue }
                        $rights = @($controls | ForEach-Object { Get-AttackPathValue $_.Evidence 'Rights' })
                        $indirect = $resource -ne $path -or 'WriteDataOrAddFile' -notin $rights -or $rule.Id -eq 'ServiceUnquotedPath'
                        $relation = if ($rule.Id -eq 'ServiceUnquotedPath') { "The service's recorded ambiguous executable prefix matches this controlled path: $path." } else { "The SYSTEM execution object's recorded executable matches this file or its immediate parent: $path." }
                        $matches.Add(@{Controls=$controls; Resource=$resource; Indirect=$indirect; Supporting=$executable.Supporting; Relation=$relation})
                    }
                }
            }
            foreach ($match in $matches) {
                if ($candidates.Count -ge $candidateBudget) { $discoveryLimited = $true; $ruleCoverage.Status = 'LimitedByBudget'; break }
                $candidate = New-AttackPathCandidate -Report $Report -Rule $rule -Inventory $inventory -InputTruncated $inputTruncated @match
                if (-not $candidates.ContainsKey($candidate.Id)) { $candidates[$candidate.Id] = $candidate }
            }
        }
    }
    $priorityOrder = @{High=0; Medium=1; Information=2}
    $ordered = @($candidates.Values | Sort-Object @{Expression={$priorityOrder[$_.Priority]}},RuleId,Target,Resource,Id)
    $limited = $inputTruncated -or $discoveryLimited -or $ordered.Count -gt $MaxPaths -or @($coverage | Where-Object Status -ne 'Evaluated').Count -gt 0 -or (Get-AttackPathValue $Report 'RunStatus') -ne 'Completed'
    [pscustomobject]@{
        EngineVersion='1.0'; Status=$(if ($limited) {'Partial'} else {'Completed'})
        Paths=@($ordered | Select-Object -First $MaxPaths); TotalCandidates=$ordered.Count
        MaxPaths=$MaxPaths; OmittedPaths=[Math]::Max(0,$ordered.Count-$MaxPaths)
        CandidateBudget=$candidateBudget; DiscoveryTruncated=$discoveryLimited
        EvidenceExamined=$scanned; EvidenceTruncated=$inputTruncated; RuleCoverage=$coverage.ToArray()
        Limitations=@('Candidate correlations only; no changes, trigger actions or exploitation are performed.', 'Rules currently cover SYSTEM services and enabled SYSTEM scheduled tasks. Other checks remain standalone evidence.', 'Only exact object names and absolute executable/immediate-parent paths are joined. Relative paths, environment variables, aliases, loader behavior and credential relationships are not inferred.', 'An empty path list is not a clean bill of health. Inspect rule coverage, scan limits and supporting check diagnostics.')
    }
}

function ConvertTo-AttackPathHtml {
    param([object]$Analysis)
    $html = New-Object Text.StringBuilder
    [void]$html.Append('<section aria-labelledby="attack-paths"><h2 id="attack-paths">Attack path candidates</h2><p>' + [Net.WebUtility]::HtmlEncode("Analysis: $($Analysis.Status) | Candidates: $($Analysis.TotalCandidates) | Omitted paths: $($Analysis.OmittedPaths)") + '</p>')
    if ((Get-AttackPathValue $Analysis 'EvidenceTruncated') -or (Get-AttackPathValue $Analysis 'DiscoveryTruncated')) { [void]$html.Append('<p><strong>Analysis limit reached.</strong> Some evidence or candidate combinations were not examined. Counts describe only the candidates discovered within the budget.</p>') }
    foreach ($note in $Analysis.Limitations) { [void]$html.Append('<p><small>' + [Net.WebUtility]::HtmlEncode($note) + '</small></p>') }
    if (-not @($Analysis.Paths).Count) { [void]$html.Append('<p>No candidate chains were established from the available evidence.</p>') }
    foreach ($path in $Analysis.Paths) {
        [void]$html.Append('<details><summary>' + [Net.WebUtility]::HtmlEncode("[$($path.Priority) / $($path.Confidence)] $($path.Title): $($path.Target)") + '</summary><p>' + [Net.WebUtility]::HtmlEncode("$($path.Assessment) | Resource: $($path.Resource) | $($path.Goal)") + '</p><ol>')
        foreach ($step in $path.Steps) { [void]$html.Append('<li>' + [Net.WebUtility]::HtmlEncode($step.Description) + '</li>') }
        [void]$html.Append('</ol><h4>Supporting evidence</h4><ul>')
        foreach ($reference in $path.EvidenceReferences) { [void]$html.Append('<li><a href="#' + [Net.WebUtility]::HtmlEncode($reference.Anchor) + '">' + [Net.WebUtility]::HtmlEncode("Check $($reference.CheckId), finding $($reference.FindingIndex): $($reference.Target) [$($reference.CheckStatus)]") + '</a></li>') }
        [void]$html.Append('</ul><h4>Unresolved prerequisites</h4><ul>')
        foreach ($item in $path.Prerequisites) { [void]$html.Append('<li>' + [Net.WebUtility]::HtmlEncode($item) + '</li>') }
        [void]$html.Append('</ul><h4>Verify supporting checks</h4>')
        foreach ($command in $path.VerificationCommands) { [void]$html.Append('<p>' + [Net.WebUtility]::HtmlEncode("Check $($command.CheckId) | Working directory: $($command.WorkingDirectory)") + '</p><pre>' + [Net.WebUtility]::HtmlEncode($command.Command) + '</pre>') }
        [void]$html.Append('<p>' + [Net.WebUtility]::HtmlEncode($path.Remediation) + '</p></details>')
    }
    [void]$html.Append('<details><summary>Correlation rule coverage</summary><table><thead><tr><th>Rule</th><th>Status</th><th>Required checks</th><th>Missing checks</th><th>Incomplete checks</th></tr></thead><tbody>')
    foreach ($rule in $Analysis.RuleCoverage) {
        [void]$html.Append('<tr>')
        foreach ($value in @($rule.Title,$rule.Status,($rule.RequiredChecks -join ', '),($rule.MissingChecks -join ', '),($rule.IncompleteChecks -join ', '))) { [void]$html.Append('<td>' + [Net.WebUtility]::HtmlEncode([string]$value) + '</td>') }
        [void]$html.Append('</tr>')
    }
    [void]$html.Append('</tbody></table></details></section>')
    $html.ToString()
}
