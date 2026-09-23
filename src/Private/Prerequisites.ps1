# Generate validation instructions from typed metadata. Never evaluate commands
# or copy executable text from an imported report into a new instruction.
function Expand-PrerequisiteCommand {
    param([string]$Template, [hashtable]$Literals)
    # A single replacement pass prevents placeholder-looking target names from
    # being expanded again. Every dynamic value must already be a PS literal.
    [regex]::Replace($Template, '__([A-Z_]+)__', [Text.RegularExpressions.MatchEvaluator]{
        param($match)
        if (-not $Literals.ContainsKey($match.Groups[1].Value)) { throw 'Unknown prerequisite command placeholder.' }
        [string]$Literals[$match.Groups[1].Value]
    })
}

function New-PrerequisiteCommand {
    param([string]$Purpose, [string]$Command, [string]$ExpectedResult,
        [string]$RunContext='Run on the assessed Windows computer as the identity being assessed, using 64-bit PowerShell 5.1 or 7.')
    [pscustomobject]@{Purpose=$Purpose; Command=$Command.Trim(); ExpectedResult=$ExpectedResult; RunContext=$RunContext; Mode='ReadOnly'}
}

function New-PrerequisiteScanCommand {
    param([object]$Report, [int[]]$CheckId)
    $ids = @($CheckId | Sort-Object -Unique)
    $command = '$validation = & ''.\Invoke-StealthPrivesc.ps1'' -CheckId ' + ($ids -join ',') + ' -PassThru'
    $scope = Get-AttackPathValue $Report 'Scope'
    foreach ($flag in @('Network','Domain','Sensitive')) {
        $enabled = Get-AttackPathValue $scope $flag
        if ($enabled -is [bool] -and $enabled) { $command += " -Include$flag" }
    }
    foreach ($bound in @(@{Name='MaxItems';Min=10;Max=100000},@{Name='MaxFileBytes';Min=1024;Max=10485760},@{Name='CommandTimeoutSeconds';Min=1;Max=300})) {
        $value = Get-AttackPathValue $scope $bound.Name
        # JSON can deserialize numbers as Int64. Reject executable/string values.
        if (($value -is [int] -or $value -is [long]) -and $value -ge $bound.Min -and $value -le $bound.Max) { $command += " -$($bound.Name) $value" }
    }
    $command += "`n" + '$validation.Checks | Format-List Id,Status,Limitations,Diagnostics,Findings'
    New-PrerequisiteCommand 'Refresh the relevant scanner evidence' $command 'Check Status and Diagnostics first, then locate this exact object in Findings. Completed alone does not establish that the object was included or that the candidate is reachable.' 'Run from this scanner checkout on the assessed computer as the intended assessment identity. Numeric limits and explicit opt-ins are retained when present in the report; these focused checks use fixed service/task locations. Review original custom reference/search paths separately.'
}

function New-AttackPathPrerequisiteActions {
    param([object]$Report, [object]$Rule, [object]$Inventory, [object[]]$Supporting,
        [string]$Resource, [bool]$Indirect, [bool]$Incomplete, [string]$Assessment)
    $targetLiteral = ConvertTo-VerificationLiteral $Inventory.Target
    $literals = @{TARGET=$targetLiteral; RESOURCE=(ConvertTo-VerificationLiteral $Resource)}
    $isTask = $Rule.Id.StartsWith('Task')
    $contextCommand = New-PrerequisiteCommand 'Confirm token identity, groups, privileges and integrity level' @'
& "$env:SystemRoot\System32\whoami.exe" /all
if ($LASTEXITCODE -ne 0) { throw 'whoami could not query this token.' }
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
try {
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    [pscustomobject]@{User=$identity.Name; SID=$identity.User.Value; Elevated=$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator); PowerShell=$PSVersionTable.PSVersion.ToString(); Is64Bit=[Environment]::Is64BitProcess}
} finally { $identity.Dispose() }
'@ ('Compare the SID, elevation, architecture and integrity level with the scan. Recorded principal: ' + [string](Get-AttackPathValue $Report 'UserSid') + '. A different token requires a separate assessment.')
    $scanCommand = New-PrerequisiteScanCommand $Report $Rule.Checks
    [pscustomobject]@{
        Id='CurrentContext'; Status='Unresolved'
        Description='Confirm that the account, object and permissions still match this snapshot, including integrity policy and other runtime access restrictions.'
        Commands=@($contextCommand,$scanCommand)
        ResolutionCriteria='The intended token matches, the exact object is present, and its account and required control rights are still observed.'
        RemainingUncertainty='DACL access does not settle file locks, mandatory integrity restrictions or runtime behavior. Keep any untested restriction unresolved.'
    }

    if ($Indirect) {
        if ($Rule.Id -eq 'ServiceConfiguration') {
            $accessTemplate = @'
$serviceName = __TARGET__
if ($serviceName -match '[\x00-\x1f"]') { throw 'This name cannot be represented safely for sc.exe; use the scanner check command.' }
& "$env:SystemRoot\System32\sc.exe" sdshow $serviceName
if ($LASTEXITCODE -ne 0) { throw 'Service security descriptor query failed; access remains unknown.' }
'@
            $accessExpected = 'Review the service security descriptor alongside check 12. Ownership/DACL control is different from an observed ChangeConfig right.'
        } elseif ($Rule.Id -eq 'TaskDefinition') {
            $split = $Inventory.Target.LastIndexOf('\')
            $folder = if ($split -ge 0) { $Inventory.Target.Substring(0,$split+1) } else { '\' }
            $name = if ($split -ge 0) { $Inventory.Target.Substring($split+1) } else { $Inventory.Target }
            $literals.FOLDER = ConvertTo-VerificationLiteral $folder
            $literals.TASK_NAME = ConvertTo-VerificationLiteral $name
            $accessTemplate = @'
$scheduler = New-Object -ComObject Schedule.Service
$folder = $null; $task = $null
try {
    $scheduler.Connect()
    $folder = $scheduler.GetFolder(__FOLDER__)
    $task = $folder.GetTask(__TASK_NAME__)
    $task.GetSecurityDescriptor(7)
} finally {
    if ($task) { [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($task) }
    if ($folder) { [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($folder) }
    [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($scheduler)
}
'@
            $accessExpected = 'Review the exact registered task descriptor alongside check 24. A returned descriptor or UpdateTask DACL result does not prove scheduler update authorization.'
        } else {
            $accessTemplate = @'
Get-Acl -LiteralPath __RESOURCE__ -ErrorAction Stop | Format-List Path,Owner,AccessToString,Sddl
'@
            $accessExpected = if ($Rule.Id -eq 'ServiceRegistry') { 'Confirm rights on this exact service key. SetValue, WriteDacl and WriteOwner represent different capabilities; registry access does not establish when the service consumes configuration.' } else { 'Identify whether the controlled object is a file or directory and compare its rights with the scanner finding. Creating a new directory entry does not establish replacement of an existing file.' }
            if ($Rule.Id -ne 'ServiceRegistry') { $accessTemplate = 'Get-Item -LiteralPath __RESOURCE__ -Force -ErrorAction Stop | Format-List FullName,PSIsContainer,Attributes' + "`n" + $accessTemplate }
        }
        [pscustomobject]@{
            Id='ExactControl'; Status='Unresolved'
            Description='Directory creation rights or ownership/DACL control do not establish direct file replacement or object modification; validate the precise access needed.'
            Commands=@((New-PrerequisiteCommand 'Inspect the exact controlled object and its ACL' (Expand-PrerequisiteCommand $accessTemplate $literals) $accessExpected))
            ResolutionCriteria='Distinguish the actual resource type and granted rights from the operation the candidate assumes.'
            RemainingUncertainty='These commands inspect metadata. They do not attempt a write, change ownership or permissions, or validate replacement/update semantics by modifying the object.'
        }
    }

    $policyCommand = New-PrerequisiteCommand 'Inspect effective application-control policy' @'
Get-Service -ErrorAction Stop | Where-Object Name -eq 'AppIDSvc' | Select-Object Name,Status
try { Get-AppLockerPolicy -Effective -Xml -ErrorAction Stop }
catch { Write-Warning 'Effective AppLocker policy is unavailable; enforcement remains unknown.' }
$ciTool = Join-Path $env:SystemRoot 'System32\CiTool.exe'
if (Test-Path -LiteralPath $ciTool -PathType Leaf) {
    & $ciTool -lp -json
    if ($LASTEXITCODE -ne 0) { throw 'Code Integrity policy query failed; enforcement remains unknown.' }
} else { Write-Warning 'CiTool is unavailable; Code Integrity enforcement remains unknown.' }
'@ 'Review applicable enforced AppLocker rule collections and active Code Integrity policies. Missing commands, access denial, audit-only rules or an empty response must not be interpreted as execution permission.'
    if ($isTask) {
        $triggerTemplate = @'
$taskIdentity = __TARGET__
$tasks = @(Get-ScheduledTask -ErrorAction Stop | Where-Object { ($_.TaskPath + $_.TaskName) -eq $taskIdentity })
if ($tasks.Count -ne 1) { throw 'Expected exactly one matching task; refresh the inventory.' }
$task = $tasks[0]
$task | Select-Object TaskPath,TaskName,State
$task.Principal | Select-Object UserId,GroupId,RunLevel,LogonType
$task.Settings | Select-Object Enabled,AllowDemandStart,DisallowStartIfOnBatteries,StopIfGoingOnBatteries,RunOnlyIfIdle,RunOnlyIfNetworkAvailable,StartWhenAvailable
$task.Triggers | Select-Object Enabled,StartBoundary,EndBoundary,ExecutionTimeLimit
$task | Get-ScheduledTaskInfo -ErrorAction Stop | Select-Object LastRunTime,LastTaskResult,NextRunTime,NumberOfMissedRuns
'@
        [pscustomobject]@{
            Id='TaskExecution'; Status='Unresolved'
            Description='Validate the task trigger, scheduler authorization, logon restrictions and application-control policy before treating execution as reachable.'
            Commands=@((New-PrerequisiteCommand 'Inspect task timing, conditions, principal and recent result' (Expand-PrerequisiteCommand $triggerTemplate $literals) 'Confirm the exact enabled task, its SYSTEM principal, applicable triggers and conditions. LastTaskResult describes a past run; AllowDemandStart is a setting, not proof the current user may invoke the task.'),$policyCommand)
            ResolutionCriteria='Establish which trigger/conditions apply and review scheduler authorization, principal logon requirements and applicable enforcement rules.'
            RemainingUncertainty='A metadata query does not test logon success, permission to run/update the task, or whether new content would execute. Runtime authorization requires separate review; this command does not start a task.'
        }
    } else {
        $triggerTemplate = @'
$serviceName = __TARGET__
Get-CimInstance -ClassName Win32_Service -ErrorAction Stop | Where-Object Name -eq $serviceName | Select-Object Name,StartName,State,StartMode,AcceptStop,AcceptPause,ProcessId
Get-Service -ErrorAction Stop | Where-Object Name -eq $serviceName | Select-Object Name,Status,CanStop,CanPauseAndContinue,ServicesDependedOn,DependentServices
if ($serviceName -match '[\x00-\x1f"]') { throw 'This name cannot be represented safely for sc.exe; inspect trigger configuration through the service owner.' }
& "$env:SystemRoot\System32\sc.exe" qtriggerinfo $serviceName
if ($LASTEXITCODE -ne 0) { throw 'Service trigger query failed; activation remains unknown.' }
'@
        [pscustomobject]@{
            Id='ServiceExecution'; Status='Unresolved'
            Description='Validate service activation/reload behavior and application-control policy; a control permission does not establish that modified content will execute.'
            Commands=@((New-PrerequisiteCommand 'Inspect service state, dependencies and configured triggers' (Expand-PrerequisiteCommand $triggerTemplate $literals) 'Find this exact service and inspect its start mode, dependencies and trigger conditions. CanStop/AcceptStop describe supported controls, not the scanning user permission.'),(New-PrerequisiteScanCommand $Report @(11,20)),$policyCommand)
            ResolutionCriteria='Establish an applicable service activation condition, distinguish Start/Stop permissions from service capabilities, and review enforcement policy.'
            RemainingUncertainty='Application-specific reload behavior, protected-service restrictions and actual execution remain untested. These commands do not start, stop or restart a service.'
        }
        if ($Rule.Id -eq 'ServiceUnquotedPath') {
            # Use the recorded absolute executable, not analyst-machine expansion.
            $executable = [string](Get-AttackPathValue $Inventory.Evidence 'Executable')
            $prefixes = New-Object 'System.Collections.Generic.List[string]'
            foreach ($space in [regex]::Matches($executable,'\s+')) {
                $prefix = $executable.Substring(0,$space.Index)
                if (-not $prefix.EndsWith('.exe',[StringComparison]::OrdinalIgnoreCase)) { $prefix += '.exe' }
                $prefixes.Add($prefix)
            }
            $prefixes.Add($executable)
            $literals.PATHS = (@($prefixes | ForEach-Object { ConvertTo-VerificationLiteral $_ })) -join ','
            $prefixTemplate = @'
$candidatePaths = @(__PATHS__)
foreach ($candidatePath in $candidatePaths) {
    try {
        $item = Get-Item -LiteralPath $candidatePath -Force -ErrorAction Stop
        [pscustomobject]@{Path=$candidatePath; State='Present'; IsDirectory=$item.PSIsContainer; Attributes=$item.Attributes}
    } catch [System.Management.Automation.ItemNotFoundException] {
        [pscustomobject]@{Path=$candidatePath; State='Missing'; IsDirectory=$null; Attributes=$null}
    } catch {
        [pscustomobject]@{Path=$candidatePath; State='Unknown'; IsDirectory=$null; Attributes=$null}
    }
}
'@
            [pscustomobject]@{
                Id='ExecutableSearchOrder'; Status='Unresolved'
                Description='Validate executable search order and earlier existing candidates; an ambiguous prefix alone does not prove interception.'
                Commands=@((New-PrerequisiteCommand 'Inspect ambiguous prefixes in recorded path order' (Expand-PrerequisiteCommand $prefixTemplate $literals) 'Inspect earlier prefixes before the controlled candidate. Present files may affect resolution; Unknown means access/query failure, not absence. The last item is the intended executable.'),(New-PrerequisiteScanCommand $Report @(11,17)))
                ResolutionCriteria='Confirm the service path remains unquoted, identify earlier candidates, and compare the controlled path with the current executable configuration.'
                RemainingUncertainty='File presence alone does not prove loader selection, executable suitability, or reachability. No candidate is created or launched.'
            }
        }
    }
    if ($Incomplete) {
        $ids = @($Rule.Checks) + @($Supporting | Where-Object { $_ } | ForEach-Object CheckId)
        [pscustomobject]@{
            Id='CollectionCompleteness'; Status='Unresolved'
            Description='Supporting collection or the overall run was incomplete; review source check diagnostics and enumeration limits.'
            Commands=@((New-PrerequisiteScanCommand $Report $ids))
            ResolutionCriteria='Review each diagnostic, then rerun the focused checks after addressing its specific read-access, dependency or limit issue. Confirm the exact object and required evidence are present.'
            RemainingUncertainty='The command retains valid original numeric limits and enabled scopes. Repeated limits may require an explicit adjustment; a focused scan does not supply missing dependencies or permissions. Offline analysis truncation may also require a higher MaxEvidence.'
        }
    }
    if ($Assessment -in @('PrivilegedAuditExposure','UnknownStartingPrivilege')) {
        [pscustomobject]@{
            Id='StartingPrivilege'; Status='Unresolved'
            Description=$(if ($Assessment -eq 'PrivilegedAuditExposure') {'The scan already used an elevated token. Reassess as the intended low-privilege identity before claiming escalation.'} else {'The original starting privilege is unknown. Establish the intended identity and elevation before interpreting this candidate.'})
            Commands=@($contextCommand,$scanCommand)
            ResolutionCriteria='Run these commands in an existing non-elevated PowerShell session as the intended assessment user. Confirm its SID and Elevated=False, then compare a fresh focused scan.'
            RemainingUncertainty='The commands inspect the current token; they do not change identity or remove elevation from an existing process. Findings from different identities must be kept separate.'
        }
    }
}

function ConvertTo-PrerequisiteActionsHtml {
    param([object[]]$Actions)
    $html = New-Object Text.StringBuilder
    [void]$html.Append('<p>Run these validation commands manually on the assessed computer. They have not been executed by the correlation engine. Review the expected evidence and remaining uncertainty before resolving an item.</p><ol>')
    foreach ($action in $Actions) {
        [void]$html.Append('<li><p><strong>' + [Net.WebUtility]::HtmlEncode($action.Description) + '</strong> [' + [Net.WebUtility]::HtmlEncode($action.Status) + ']</p>')
        foreach ($command in $action.Commands) {
            [void]$html.Append('<p><strong>' + [Net.WebUtility]::HtmlEncode($command.Purpose) + '</strong></p><p><small>' + [Net.WebUtility]::HtmlEncode($command.RunContext) + '</small></p><pre>' + [Net.WebUtility]::HtmlEncode($command.Command) + '</pre><p><strong>Look for:</strong> ' + [Net.WebUtility]::HtmlEncode($command.ExpectedResult) + '</p>')
        }
        [void]$html.Append('<p><strong>Resolution criteria:</strong> ' + [Net.WebUtility]::HtmlEncode($action.ResolutionCriteria) + '</p><p><strong>Still requires review:</strong> ' + [Net.WebUtility]::HtmlEncode($action.RemainingUncertainty) + '</p></li>')
    }
    [void]$html.Append('</ol>')
    $html.ToString()
}
