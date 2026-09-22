# StealthPrivesc

A read-only PowerShell Windows privilege-escalation exposure scanner. It collects token, permissions, configuration and inventory evidence, with credential values redacted. It does not exploit findings or change the assessed configuration.

**Version 0.1 is an initial implementation, not full parity with the supplied checklist.** All 148 items have stable IDs: 24 have implemented checks, 118 have partial collectors, and 6 are explicitly unsupported. Several partial collectors are artifact or configuration inventory only. See [the exact coverage matrix](docs/COVERAGE.md) before relying on a result. CVE applicability, LOLDrivers matching, leaked-handle analysis and several deep credential/domain checks remain unfinished.

## Run

Use 64-bit Windows PowerShell 5.1 or PowerShell 7 on Windows. No downloaded PowerShell modules are required for the local baseline. Some collectors depend on Windows components such as ScheduledTasks, Defender, DISM or AppLocker. Domain collectors require RSAT's ActiveDirectory module.

```powershell
# List the catalog without inspecting the host.
.\Invoke-StealthPrivesc.ps1 -ListChecks |
    Format-Table Id, Category, Scope, Coverage, Title

# Local baseline; write timestamped JSON and standalone HTML reports.
.\Invoke-StealthPrivesc.ps1 -OutputDirectory .\reports

# Run a focused permissions assessment as your current user.
.\Invoke-StealthPrivesc.ps1 -Category Identity,Services,TasksStartup,AccessControl `
    -MaxItems 500 -OutputDirectory .\reports

# Select individual checks; preserve structured results in memory.
$report = .\Invoke-StealthPrivesc.ps1 -CheckId 1,4,12,13,17,47,100 -PassThru
$report.Checks | Select-Object Id, Status, Findings

# Opt in to sensitive artifact inspection. Values remain redacted.
.\Invoke-StealthPrivesc.ps1 -CheckId 68,78,99 -IncludeSensitive `
    -SearchRoot C:\AuditFixtures -OutputDirectory .\reports

# Explicit domain queries; RSAT and a reachable joined domain required.
.\Invoke-StealthPrivesc.ps1 -CheckId 141,143,144,145,146 -IncludeDomain `
    -MaxItems 100 -OutputDirectory .\reports
```

If local script policy blocks execution, use your organization's approved script-signing/execution process. Start with a standard user token: an elevated administrator's write rights are generally expected. The scanner never requests elevation or enables token privileges.

`-IncludeSensitive` enables checks 67–99 except the separate SYSVOL domain check, plus browser/activity artifact checks 136–138. `-IncludeDomain` enables SYSVOL and AD queries, including the optional own-computer LAPS readability check. `-IncludeNetwork` enables check 132's external DNS lookup. Either network/domain opt-in also permits UNC filesystem targets. Windows APIs can perform implicit name/principal resolution; these flags are not a network isolation mechanism.

`-SearchRoot` scopes generic file checks; it does not replace fixed locations used by service, task, registry and product-specific checks. Defaults are ProgramData and the current user's Documents folder. Reparse-point traversal is skipped. `-MaxItems` bounds each collector/enumeration or result set, not the whole assessment. `-MaxFileBytes` defaults to 1 MiB for text inspection. `-CommandTimeoutSeconds` applies to external command helpers only, not every CIM/COM/LDAP call. The first version has no universal per-check timeout.

## Interpret results

Coverage describes the implementation. Status describes this particular run:

| Status | Meaning |
|---|---|
| Completed | The implemented collector completed within its declared scope. This does not mean the computer is secure. |
| Partial | A partial collector ran, access was limited, or results were truncated. Read `Limitations`. |
| Skipped | A required opt-in, dependency or applicable environment was absent. |
| Unsupported | No collector is implemented for this checklist item. |
| Error | The collector failed. Already gathered evidence is retained. |

Findings carry `Severity`, `Target`, `Observation`, structured `Evidence` and, where appropriate, `Remediation`. Information entries are context, not vulnerabilities. File/registry ACL checks use Windows `AccessCheck` with the current effective token, including deny and restricted-token handling. They do not fully evaluate mandatory integrity policy, filesystem locks, loader behavior or execution triggers. Directory write/append/delete permissions are candidates, not proof that a particular privileged executable can be replaced. AD ACE checks are explicitly heuristic and do not claim effective access.

Credential checks report marker categories, value presence and artifact locations. They do not print matched values, export tickets/keys, decrypt stores, request service tickets, or read process memory. Raw process/task/service command arguments and event payloads are omitted. Reports still contain operational metadata (usernames, SIDs, paths, hostnames), so handle them as assessment records.

## Develop and test

```powershell
.\tests\Test-StealthPrivesc.ps1
powershell.exe -NoProfile -File .\tests\Test-StealthPrivesc.ps1
```

The dependency-free test suite exercises catalog validation, executable parsing, redaction, deny-ACE evaluation, bounded traversal, cached failure propagation, report encoding and the CLI opt-ins. Native tests require Windows. Host-wide privileged collectors and AD behavior need a representative lab; tests running in a restricted token cannot validate all of those paths.

Collectors live in `src/Checks`; shared helpers and reporting are in `src/Private`; query-only Win32 interop is in `src/Native.cs`. The module exports `Invoke-StealthPrivesc` and `Get-StealthPrivescCheck`. Keep catalog coverage and limitations honest when adding a collector. Do not turn unavailable data into a completed empty check.

See [design notes](docs/DESIGN.md), [coverage](docs/COVERAGE.md) and [reference sources](docs/REFERENCES.md).
