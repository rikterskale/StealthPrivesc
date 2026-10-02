@{
    RootModule = 'StealthPrivesc.psm1'
    ModuleVersion = '0.2.1'
    GUID = '8a696415-187e-42e4-bad0-1f769ce04eb5'
    Author = 'StealthPrivesc contributors'
    Description = 'Read-only Windows privilege escalation exposure assessment with explicit coverage and redacted evidence.'
    PowerShellVersion = '5.1'
    FunctionsToExport = @('Invoke-StealthPrivesc', 'Get-StealthPrivescCheck', 'Get-StealthPrivescAttackPathAnalysis', 'Get-AssessmentPlan', 'Measure-AssessmentFootprint')
    CmdletsToExport = @()
    VariablesToExport = @()
    AliasesToExport = @()
}
