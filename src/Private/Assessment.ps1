# Planning and counters describe collection, never suppress Windows telemetry.
function Get-NativeSupportDefinition {
    param([string]$Name)
    $names = @('Native','NativeInspection','NativeObjects','NativeHandles','NativeServices','NativeSessions','NativeSecrets','NativeSqlite','NativeSspi','NativeVault','NativeWifi','NativeNss','Console')
    if ($Name -notin $names) { throw 'Unknown native support component.' }
    [pscustomobject]@{ Name=$Name; TypeName="StealthPrivesc.$Name"; Source=$(if ($Name -eq 'Console') { 'NativeConsole.cs' } else { "$Name.cs" }) }
}

function Get-AssessmentPlan {
    [CmdletBinding()]
    param([int[]]$CheckId, [string[]]$Category, [switch]$IncludeNetwork, [switch]$IncludeDomain, [switch]$IncludeSensitive)
    $checks = @(foreach ($check in Get-StealthPrivescCheck -CheckId $CheckId -Category $Category) {
        $collector = Get-CheckCollector $check.Id
        $references = @(Get-CheckSourceReferences -Collector $collector -Id $check.Id)
        $types = @($references | ForEach-Object {
            foreach ($match in [regex]::Matches($_.Expression, '\[StealthPrivesc\.(\w+)\]')) {
                if ($match.Groups[1].Value -in @('Native','NativeInspection','NativeObjects','NativeHandles','NativeServices','NativeSessions','NativeSecrets','NativeSqlite','NativeSspi','NativeVault','NativeWifi','NativeNss','Console')) { $match.Groups[1].Value }
            }
        } | Sort-Object -Unique)
        $helpers = @()
        foreach ($reference in $references) {
            if ($reference.Expression -match 'Invoke-ReadOnlyCommand\s+[^\r\n]*?System32\\([\w]+\.exe)') { $helpers += $Matches[1] }
        }
        if ($check.Id -in @(6,60,74,98,147)) { $helpers += 'powershell.exe' }
        if ($check.Id -in @(43,44,45)) { $helpers += $(if ($PSVersionTable.PSEdition -eq 'Desktop') { 'powershell.exe' } else { 'pwsh.exe' }) }
        if ($check.Id -eq 98) { $types = @($types | Where-Object { $_ -ne 'NativeSessions' }) }
        if ($check.Id -eq 136) { $types = @($types | Where-Object { $_ -ne 'NativeSecrets' }) }
        if (@($references | Where-Object Expression -match 'Invoke-ReadOnlyCommand|Invoke-IsolatedNativeQuery').Count -or $helpers.Count) { $types += 'Console' }
        $enabled = $check.Coverage -ne 'Unsupported' -and ($check.Scope -eq 'Local' -or ($check.Scope -eq 'Domain' -and $IncludeDomain) -or ($check.Scope -eq 'Network' -and $IncludeNetwork) -or ($check.Scope -eq 'Sensitive' -and $IncludeSensitive))
        $network = @()
        if ($enabled -and $IncludeNetwork -and $check.Id -eq 63) { $network += 'HTTPS services.nvd.nist.gov (package names/versions; up to ten queries)' }
        if ($enabled -and $check.Id -eq 132) { $network += 'Configured DNS resolver: www.microsoft.com' }
        if ($enabled -and $IncludeNetwork -and $check.Id -eq 148) { $network += 'HTTP 169.254.169.254 (Azure/AWS/Google metadata)' }
        if ($enabled -and $IncludeDomain -and ($check.Scope -eq 'Domain' -or $check.Id -eq 147)) { $network += 'Joined domain: directory/SYSVOL/DC registry as applicable' }
        $fileAccess = @($references | Where-Object Expression -match 'Get-BoundedFiles|Get-Item|Get-Content|Read-Assessment|Read-SafeXml|Get-Acl|Read-Registry|Get-Registry|Get-ReferenceDocument|ProfileDatabase' | Select-Object Source,Line,Expression)
        [pscustomobject]@{
            Id=$check.Id; Title=$check.Title; Category=$check.Category; Scope=$check.Scope; Enabled=[bool]$enabled
            Collector=$collector; NativeTypes=@($types | Sort-Object -Unique); HelperProcesses=@($helpers | Sort-Object -Unique)
            PotentialNetworkDestinations=$network; ResourceExpressions=$fileAccess
        }
    })
    [pscustomobject]@{
        PlanVersion='1.0'; Checks=$checks
        RequiredNativeTypes=@($checks | Where-Object Enabled | ForEach-Object NativeTypes | Sort-Object -Unique)
        PotentialHelperProcesses=@($checks | Where-Object Enabled | ForEach-Object HelperProcesses | Sort-Object -Unique)
        PotentialNetworkDestinations=@($checks | Where-Object Enabled | ForEach-Object PotentialNetworkDestinations | Sort-Object -Unique)
        Notes=@('Static preview: collectors and native APIs are not executed; host configuration is not read.', 'Resources and helper launches are conditional. Expressions are source references, not resolved paths or a complete execution trace.', 'UNC targets and implicit Windows principal/name resolution can depend on host configuration. Existing scope gates still apply.')
    }
}

function Initialize-RequiredNativeSupport {
    param([string[]]$Name)
    foreach ($component in @($Name | Sort-Object -Unique)) {
        $definition = Get-NativeSupportDefinition $component
        if ($definition.TypeName -as [type]) { continue }
        $directory = $null
        $contextVariable = Get-Variable Context -Scope Script -ErrorAction SilentlyContinue
        if ($contextVariable -and $contextVariable.Value.ContainsKey('NativeAssemblyDirectory')) { $directory = $contextVariable.Value.NativeAssemblyDirectory }
        if ($directory) {
            $runtime = if ($PSVersionTable.PSEdition -eq 'Desktop') { 'Desktop' } else { 'Core' }
            $architecture = if ([Environment]::Is64BitProcess) { 'x64' } else { 'x86' }
            $assembly = Join-Path $directory "$runtime/$architecture/$component.dll"
            # Deny writes/deletion while verifying and capturing the same file.
            # Load captured bytes so the DLL is not locked for the session lifetime.
            $stream=[IO.File]::Open($assembly,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
            $memory=$null
            try {
                if($stream.Length-gt10485760){throw [IO.InvalidDataException]::new('Native assembly exceeds its size limit.')}
                $signature = Get-AuthenticodeSignature -LiteralPath $assembly -ErrorAction Stop
                if ($signature.Status -ne 'Valid' -or -not $signature.SignerCertificate) { throw [Security.SecurityException]::new('Native assembly must have a valid trusted Authenticode signature.') }
                $memory=[IO.MemoryStream]::new()
                Add-AssessmentCounter FileReadAttempts
                $stream.CopyTo($memory)
                Add-AssessmentCounter FileBytesRead $stream.Position
                [void][Reflection.Assembly]::Load($memory.ToArray())
            } finally { if($memory){$memory.Dispose()};$stream.Dispose() }
        } else {
            $options = @{Path=(Join-Path $script:ModuleRoot $definition.Source); ErrorAction='Stop'}
            if ($component -eq 'NativeWifi' -and $PSVersionTable.PSEdition -eq 'Desktop') { $options.ReferencedAssemblies = @('System.Xml.dll') }
            Add-Type @options
        }
        if (-not ($definition.TypeName -as [type])) { throw [TypeLoadException]::new('Native assembly did not provide the expected component type.') }
        Add-AssessmentCounter NativeLoads
    }
}

function Initialize-AssessmentFootprint {
    $script:AssessmentCounters = @{}
    $script:AssessmentCheckCounters = @{}
    $script:AssessmentCounterStarted = [DateTime]::UtcNow.ToString('o')
    $script:HelperProcessBaseline = if ('StealthPrivesc.Console' -as [type]) { [StealthPrivesc.Console]::StartedProcesses } else { 0 }
}

function Add-AssessmentCounter {
    param([ValidateSet('QueryAttempts','ReusedQueries','CacheHits','CacheMisses','ProcessQueries','ModuleQueries','AclQueries','RegistryReads','FileReadAttempts','FileBytesRead','OutputWrites','OutputBytesWritten','NetworkRequests','NativeLoads','HelperLaunchAttempts','HelperOutputCharacters','FindingBytes')][string]$Name, [long]$Count=1)
    $counterVariable = Get-Variable AssessmentCounters -Scope Script -ErrorAction SilentlyContinue
    if (-not $counterVariable -or $Count -lt 0) { return }
    if (-not $script:AssessmentCounters.ContainsKey($Name)) { $script:AssessmentCounters[$Name] = [long]0 }
    $script:AssessmentCounters[$Name] += $Count
    $currentVariable = Get-Variable Current -Scope Script -ErrorAction SilentlyContinue
    $id = if ($currentVariable -and $currentVariable.Value -and $currentVariable.Value.Contains('Id')) { [string]$currentVariable.Value.Id } else { 'Run' }
    if (-not $script:AssessmentCheckCounters.ContainsKey($id)) { $script:AssessmentCheckCounters[$id] = @{} }
    $counters = $script:AssessmentCheckCounters[$id]
    if (-not $counters.ContainsKey($Name)) { $counters[$Name] = [long]0 }
    $counters[$Name] += $Count
}

function Measure-AssessmentFootprint {
    [CmdletBinding()]
    param()
    $counterVariable = Get-Variable AssessmentCounters -Scope Script -ErrorAction SilentlyContinue
    if (-not $counterVariable) { throw 'No assessment measurement is available in this module session.' }
    $counters = $script:AssessmentCounters.Clone()
    $counters.HelperLaunches = if ('StealthPrivesc.Console' -as [type]) { [StealthPrivesc.Console]::StartedProcesses - $script:HelperProcessBaseline } else { 0 }
    [pscustomobject]@{
        StartedUtc=$script:AssessmentCounterStarted; CapturedUtc=[DateTime]::UtcNow.ToString('o'); Counters=$counters
        ByCheck=@(foreach ($key in $script:AssessmentCheckCounters.Keys | Sort-Object) { [pscustomobject]@{CheckId=$key;Counters=$script:AssessmentCheckCounters[$key].Clone()} })
        Limitations=@('Instrumented operations only, not an OS-wide trace. Unwrapped APIs, SQLite/native-internal reads, compiler I/O, DNS/principal resolution and helper-internal I/O are not counted.', 'Query and helper launch attempts can fail. HelperLaunches counts successfully started direct child processes.', 'Saved report snapshots precede their own final export. Call Measure-AssessmentFootprint after a run to include completed export writes.', 'Counters contain no query results, command arguments or secret values.')
    }
}

function Assert-CollectorBudget {
    $contextVariable = Get-Variable Context -Scope Script -ErrorAction SilentlyContinue
    if (-not $contextVariable -or -not $contextVariable.Value.ContainsKey('CollectorBudget') -or -not $contextVariable.Value.CollectorBudget) { return }
    $budget = $script:Context.CollectorBudget
    if ($budget.Clock.Elapsed.TotalSeconds -ge $budget.Seconds) {
        $failure = [TimeoutException]::new('Collector exceeded its collection time budget.')
        $failure.Data['StealthPrivesc.TimeoutSeconds'] = $budget.Seconds
        $failure.Data['StealthPrivesc.BudgetExceeded'] = $true
        $failure.Data['StealthPrivesc.BudgetKind'] = 'CollectorTime'
        throw $failure
    }
}

function Test-CollectorBudgetException {
    param([Exception]$Exception)
    for ($depth=0; $Exception -and $depth -lt 8; $depth++) {
        if ($Exception.Data['StealthPrivesc.BudgetExceeded'] -eq $true) { return $true }
        $Exception=$Exception.InnerException
    }
    return $false
}

function Get-CollectorHelperTimeout {
    Assert-CollectorBudget
    $seconds = $script:Context.CommandTimeoutSeconds
    if ($script:Context.ContainsKey('CollectorBudget') -and $script:Context.CollectorBudget) {
        $remaining = $script:Context.CollectorBudget.Seconds - $script:Context.CollectorBudget.Clock.Elapsed.TotalSeconds
        $seconds = [Math]::Min($seconds, [Math]::Max(1, [int][Math]::Floor($remaining)))
    }
    [int]$seconds
}

function Invoke-BudgetedCollector {
    [CmdletBinding(DefaultParameterSetName='Collector')]
    param(
        [Parameter(Mandatory,ParameterSetName='Collector')][scriptblock]$Collector,
        [Parameter(Mandatory,ParameterSetName='Helper')][string]$Payload,
        [Parameter(ParameterSetName='Helper')][string]$HostPath,
        [ValidateRange(1,3600)][int]$TimeoutSeconds=60,
        [ValidateRange(1024,8388608)][int]$MaximumOutputCharacters=8388608
    )
    if ($PSCmdlet.ParameterSetName -eq 'Helper') {
        $seconds = [Math]::Min($TimeoutSeconds, (Get-CollectorHelperTimeout))
        Invoke-ReadOnlyCommand -Payload $Payload -HostPath $HostPath -TimeoutSeconds $seconds -MaximumOutputCharacters $MaximumOutputCharacters
        return
    }
    $previous = if ($script:Context.ContainsKey('CollectorBudget')) { $script:Context.CollectorBudget } else { $null }
    $script:Context.CollectorBudget = @{Clock=[Diagnostics.Stopwatch]::StartNew();Seconds=$TimeoutSeconds;MaximumOutputCharacters=$MaximumOutputCharacters;FindingCharacters=[long]2}
    try { & $Collector; Assert-CollectorBudget }
    finally { $script:Context.CollectorBudget = $previous }
}

function Get-CachedHostInventory {
    param([ValidateSet('Processes','ProcessOwner','Modules','Acl','RegistryValue')][string]$Kind, [string]$Key, [scriptblock]$Factory)
    Assert-CollectorBudget
    if ($script:Context.Cache.Count -ge [Math]::Min(50000,[Math]::Max(100,$script:Context.MaxItems*20)) -and -not $script:Context.Cache.ContainsKey("Host/$Kind/$Key")) { & $Factory; return }
    Get-Cached -Key ("Host/$Kind/$Key") -Factory $Factory
}

function Get-AssessmentProcesses {
    param([int]$ProcessId=0)
    Get-CachedHostInventory Processes ([string]$ProcessId) {
        Add-AssessmentCounter ProcessQueries
        $options = @{ClassName='Win32_Process';OperationTimeoutSec=$script:Context.CommandTimeoutSeconds;ErrorAction='Stop'}
        if ($ProcessId) { $options.Filter = "ProcessId=$ProcessId" }
        Add-CheckCommand PowerShell ("Get-CimInstance Win32_Process -OperationTimeoutSec $($script:Context.CommandTimeoutSeconds)" + $(if ($ProcessId) { " -Filter 'ProcessId=$ProcessId'" }) + " | Select-Object -First $($script:Context.MaxItems+1)")
        Get-Limited @(Get-CimInstance @options | Select-Object -First ($script:Context.MaxItems+1))
    }
}

function Get-AssessmentProcessOwner {
    param([object]$Process)
    Get-CachedHostInventory ProcessOwner ([string]$Process.ProcessId) {
        Add-CheckCommand PowerShell 'Invoke-CimMethod -InputObject $process -MethodName GetOwnerSid -ErrorAction Stop' -Detail "Process ID: $($Process.ProcessId)"
        Invoke-CimMethod -InputObject $Process -MethodName GetOwnerSid -ErrorAction Stop
    }
}

function Get-AssessmentProcessModules {
    param([int]$ProcessId)
    Get-CachedHostInventory Modules ([string]$ProcessId) {
        Add-AssessmentCounter ModuleQueries
        Add-CheckCommand PowerShell "(Get-Process -Id $ProcessId -ErrorAction Stop).Modules"
        Get-Limited @((Get-Process -Id $ProcessId -ErrorAction Stop).Modules | Select-Object FileName,ModuleName)
    }
}

function Read-AssessmentBytes {
    param([string]$Path, [ValidateRange(0,104857600)][long]$MaximumBytes=0)
    Assert-CollectorBudget
    if (-not $MaximumBytes) { $MaximumBytes=$script:Context.MaxFileBytes }
    Add-AssessmentCounter FileReadAttempts
    $stream=[IO.File]::Open($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
    $memory=[IO.MemoryStream]::new()
    try {
        $buffer=New-Object byte[] 8192
        while($true){
            Assert-CollectorBudget
            $count=$stream.Read($buffer,0,[int][Math]::Min($buffer.Length,$MaximumBytes-$memory.Length+1))
            if(-not$count){break}
            if($memory.Length+$count-gt$MaximumBytes){
                $failure=[IO.InvalidDataException]::new('File exceeded the collector read budget.')
                $failure.Data['StealthPrivesc.BudgetExceeded']=$true
                $failure.Data['StealthPrivesc.BudgetKind']='FileBytes'
                throw $failure
            }
            $memory.Write($buffer,0,$count)
        }
        return ,$memory.ToArray()
    } finally { Add-AssessmentCounter FileBytesRead $stream.Position; $stream.Dispose(); $memory.Dispose() }
}

function Read-AssessmentText {
    param([string]$Path, [ValidateRange(0,104857600)][long]$MaximumBytes=0)
    $bytes=Read-AssessmentBytes -Path $Path -MaximumBytes $MaximumBytes
    $memory=[IO.MemoryStream]::new($bytes,$false)
    $reader=[IO.StreamReader]::new($memory,[Text.Encoding]::UTF8,$true)
    try { $reader.ReadToEnd() }
    finally { $reader.Dispose() }
}

function Write-AssessmentText {
    param([string]$Path, [string]$Text, [switch]$Append)
    $encoding = [Text.UTF8Encoding]::new($false)
    if ($Append) { [IO.File]::AppendAllText($Path,$Text,$encoding) } else { [IO.File]::WriteAllText($Path,$Text,$encoding) }
    Add-AssessmentCounter OutputWrites
    Add-AssessmentCounter OutputBytesWritten ($encoding.GetByteCount($Text))
}
