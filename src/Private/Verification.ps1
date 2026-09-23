# Verification records are explicit metadata, never a transcript of query output.
function ConvertTo-VerificationLiteral {
    param([AllowEmptyString()][string]$Value)
    # PowerShell also recognizes typographic single quotes as quote characters.
    "'" + ($Value -replace "['\u2018\u2019]", '$0$0') + "'"
}

function New-CheckVerification {
    param([int]$Id)
    $entryPoint = [IO.Path]::GetFullPath((Join-Path $script:ModuleRoot '../Invoke-StealthPrivesc.ps1'))
    $command = '& ' + (ConvertTo-VerificationLiteral $entryPoint) + " -CheckId $Id"
    foreach ($name in @('IncludeNetwork','IncludeDomain','IncludeSensitive')) {
        if ($script:Context[$name]) { $command += " -$name" }
    }
    foreach ($name in @('MaxItems','MaxFileBytes','CommandTimeoutSeconds')) {
        $command += " -$name $($script:Context[$name])"
    }
    if (@($script:Context.SearchRoot | Where-Object { $_ }).Count) {
        $command += ' -SearchRoot ' + ((@($script:Context.SearchRoot | ForEach-Object { ConvertTo-VerificationLiteral $_ })) -join ',')
    }
    foreach ($name in @('DriverDatabasePath','VulnerabilityDatabasePath')) {
        if ($script:Context[$name]) { $command += " -$name " + (ConvertTo-VerificationLiteral $script:Context[$name]) }
    }
    [pscustomobject]@{
        CollectorStarted = $false
        WorkingDirectory = [string](Get-Location).Path
        RerunCommand = $command + ' -PassThru'
        Commands = New-Object 'System.Collections.Generic.List[object]'
        OmittedCommandCount = 0
        SourceReferences = @()
        Notes = 'Run the rerun command from WorkingDirectory using the same identity, elevation and PowerShell version. It preserves scope switches and collection limits; it does not enable missing prerequisites. The command list records collector entry and instrumented shared queries, not every internal API call. Attempted does not imply success. SourceReferences are implementation expressions, not proof that a branch executed. Results and secret-bearing helper arguments are not recorded.'
    }
}

function Add-CheckCommand {
    param(
        [ValidateSet('Collector','PowerShell','NativeApi','Process')][string]$Kind,
        [string]$Command,
        [string]$Detail = '',
        [ValidateSet('Attempted','Reused')][string]$State = 'Attempted',
        [object]$SourceCheckId = $null
    )
    $currentVariable = Get-Variable -Name Current -Scope Script -ErrorAction SilentlyContinue
    if (-not $currentVariable -or -not $script:Current.Contains('Verification')) { return }
    $verification = $script:Current.Verification
    if ($null -eq $SourceCheckId) { $SourceCheckId = $script:Current.Id }
    # Collapse repeated operations and bound report size independently of findings.
    foreach ($entry in $verification.Commands) {
        if ($entry.Kind -eq $Kind -and $entry.Command -ceq $Command -and $entry.State -eq $State -and $entry.SourceCheckId -eq $SourceCheckId -and $entry.Detail -ceq $Detail) {
            $entry.Count++
            return
        }
    }
    if ($verification.Commands.Count -ge 1000) { $verification.OmittedCommandCount++; return }
    $verification.Commands.Add([pscustomobject]@{
        Kind=$Kind; Command=$Command; State=$State; Count=1
        SourceCheckId=$SourceCheckId; Detail=$Detail
    })
}

function Get-HelperVerificationArguments {
    param([string]$FileName, [string]$Arguments)
    # Fail closed: only fixed, known query arguments can enter the report.
    # Encoded PowerShell payloads may contain sensitive runtime inputs.
    $known = @{
        'net.exe'=@('accounts'); 'netsh.exe'=@('winhttp show proxy')
        'wecutil.exe'=@('es'); 'citool.exe'=@('-lp -json')
        'cmdkey.exe'=@('/list'); 'vaultcmd.exe'=@('/list'); 'klist.exe'=@('')
        'auditpol.exe'=@('/get /category:*'); 'dsregcmd.exe'=@('/status')
    }
    $name = [IO.Path]::GetFileName($FileName)
    if ($known.ContainsKey($name) -and $Arguments -cin $known[$name]) { return $Arguments }
    return '[REDACTED: helper arguments; use the check rerun command]'
}

function Get-CheckSourceReferences {
    param([string]$Collector, [int]$Id)
    # Read the loaded implementation's AST, without executing it. Follow project
    # helper functions so direct native queries remain discoverable in the report.
    $pending = New-Object 'System.Collections.Generic.Queue[string]'
    $pending.Enqueue($Collector)
    $visited = @{}
    $references = New-Object 'System.Collections.Generic.List[object]'
    $root = [IO.Path]::GetFullPath($script:ModuleRoot).TrimEnd('\','/') + [IO.Path]::DirectorySeparatorChar
    $excluded = '^(Add-Evidence|Add-CheckCommand|Set-CheckPartial|Set-CheckSkipped|.*Diagnostic.*|.*Verification.*|Get-CheckSourceReferences|Export-Assessment|Invoke-Check|Get-CheckCollector)$'
    while ($pending.Count) {
        $name = $pending.Dequeue()
        if ($visited.ContainsKey($name) -or $name -match $excluded) { continue }
        $visited[$name] = $true
        $function = Get-Command -Name $name -CommandType Function -ListImported -ErrorAction SilentlyContinue
        if (-not $function -or -not $function.ScriptBlock.File) { continue }
        $file = [IO.Path]::GetFullPath($function.ScriptBlock.File)
        if (-not $file.StartsWith($root, [StringComparison]::OrdinalIgnoreCase)) { continue }
        $nodes = $function.ScriptBlock.Ast.FindAll({ param($node)
            $node -is [System.Management.Automation.Language.CommandAst] -or
            $node -is [System.Management.Automation.Language.InvokeMemberExpressionAst]
        }, $true)
        foreach ($node in $nodes) {
            # Exclude sibling cases in the catalog's switch($Id) collectors.
            $included = $true
            for ($parent = $node.Parent; $parent; $parent = $parent.Parent) {
                if ($parent -is [System.Management.Automation.Language.IfStatementAst]) {
                    foreach ($clause in $parent.Clauses) {
                        if ($node.Extent.StartOffset -ge $clause.Item2.Extent.StartOffset -and $node.Extent.EndOffset -le $clause.Item2.Extent.EndOffset -and $clause.Item1.Extent.Text -match '^\$Id\s*-eq\s*(\d+)$' -and [int]$Matches[1] -ne $Id) { $included = $false }
                    }
                }
                if ($parent -is [System.Management.Automation.Language.SwitchStatementAst] -and $parent.Condition.Extent.Text -eq '$Id') {
                    foreach ($clause in $parent.Clauses) {
                        if ($node.Extent.StartOffset -ge $clause.Item2.Extent.StartOffset -and $node.Extent.EndOffset -le $clause.Item2.Extent.EndOffset -and $clause.Item1.Extent.Text -match '^\d+$' -and [int]$clause.Item1.Extent.Text -ne $Id) { $included = $false }
                    }
                }
            }
            if (-not $included) { continue }
            $kind = 'ApiExpression'
            if ($node -is [System.Management.Automation.Language.CommandAst]) {
                $called = $node.GetCommandName()
                if (-not $called -or $called -match $excluded) { continue }
                # Reporting, transformations and control plumbing are not queries.
                if ($called -match '^(Select-Object|Where-Object|ForEach-Object|Sort-Object|Group-Object|Out-Null|Write-.*|Convert.*|New-Object|Join-Path|Split-Path|Test-AllowedLocalPath|Get-Limited|Get-Cached)$') { continue }
                $pending.Enqueue($called)
                $kind = 'PowerShellExpression'
            } elseif ($node.Expression.Extent.Text -notmatch '^\[(StealthPrivesc\.|Security\.|System\.Security\.|Microsoft\.Win32\.|Environment\]|IO\.|System\.IO\.|Net\.|System\.Net\.|Runtime\.)') {
                continue
            }
            $references.Add([pscustomobject]@{
                Kind=$kind; Expression=$node.Extent.Text
                Source='src/' + $file.Substring($root.Length).Replace('\','/')
                Line=$node.Extent.StartLineNumber
            })
        }
    }
    $references.ToArray()
}

function ConvertTo-VerificationHtml {
    param([object]$Verification)
    $html = New-Object Text.StringBuilder
    [void]$html.Append('<details><summary>Commands and verification</summary><p>' + [Net.WebUtility]::HtmlEncode($Verification.Notes) + '</p>')
    [void]$html.Append('<p><strong>Working directory:</strong> ' + [Net.WebUtility]::HtmlEncode($Verification.WorkingDirectory) + '</p><p><strong>Rerun this check:</strong></p><pre>' + [Net.WebUtility]::HtmlEncode($Verification.RerunCommand) + '</pre>')
    if (-not $Verification.CollectorStarted) { [void]$html.Append('<p>The collector was not invoked. No check commands were run.</p>') }
    [void]$html.Append('<h4>Recorded commands</h4>')
    foreach ($entry in $Verification.Commands) {
        [void]$html.Append('<p>' + [Net.WebUtility]::HtmlEncode("$($entry.Kind) | $($entry.State) | Count: $($entry.Count) | Source check: $($entry.SourceCheckId)") + '</p><pre>' + [Net.WebUtility]::HtmlEncode($entry.Command) + '</pre><p>' + [Net.WebUtility]::HtmlEncode($entry.Detail) + '</p>')
    }
    if ($Verification.OmittedCommandCount) { [void]$html.Append('<p>Command record limit reached; additional records omitted: ' + $Verification.OmittedCommandCount + '.</p>') }
    [void]$html.Append('<details><summary>Implementation command/API references (not an execution trace)</summary>')
    foreach ($reference in $Verification.SourceReferences) {
        [void]$html.Append('<p>' + [Net.WebUtility]::HtmlEncode("$($reference.Source):$($reference.Line)") + '</p><pre>' + [Net.WebUtility]::HtmlEncode($reference.Expression) + '</pre>')
    }
    [void]$html.Append('</details></details>')
    $html.ToString()
}
