# StealthPrivesc

A PowerShell Windows privilege-escalation exposure scanner. Version 0.2 provides collectors for all 148 checklist IDs, with credential values redacted. Checks gather evidence without exploiting findings or changing assessed configuration.

See [coverage](docs/COVERAGE.md) for each collector's scope, including heuristic assessments and platform limits. Implemented does not mean every host, format or application is supported; runtime limits produce Partial results.

## Supported platforms

The intended client targets are 64-bit Windows 11 versions 24H2, 25H2 and 26H1, using Home, Pro, Enterprise or Education. Windows 10 is outside the supported-platform scope. The intended server targets are 64-bit Windows Server 2019, 2022 and 2025, using Standard or Datacenter. Other Windows editions, ARM64, Windows Server Essentials and Azure Edition are not in the stated support scope.

Use a Windows 11 version and edition that is still receiving Microsoft security updates. Windows 11 servicing dates differ by edition; version 26H1 is intended for new devices and is not offered as an in-place update from 24H2 or 25H2. Windows Server support follows each release's Microsoft lifecycle. These platform targets describe intended compatibility, not certification on every edition or release. The automated test matrix below checks both PowerShell editions on the test host; it does not provide a separate OS-version test run for every target. See Microsoft's [Windows 11 release information](https://learn.microsoft.com/en-us/windows/release-health/windows11-release-information) and [Windows Server release information](https://learn.microsoft.com/en-us/windows/release-health/windows-server-release-info) for current servicing details.

## License

Project-authored material is licensed under the [MIT License](LICENSE). Third-party components and data retain their separate terms; see [third-party notices](docs/THIRD-PARTY.md) and the accompanying license files.

## Run

Use 64-bit Windows PowerShell 5.1 or PowerShell 7 on a supported platform. Windows components provide local APIs; AD checks require RSAT ActiveDirectory. Firefox recovery uses a verified installed Mozilla NSS runtime.

```powershell
# Catalog only.
.\Invoke-StealthPrivesc.ps1 -ListChecks

# Local baseline with JSON and standalone HTML reports.
.\Invoke-StealthPrivesc.ps1 -OutputDirectory .\reports

# Focused service/task/patch/driver checks.
.\Invoke-StealthPrivesc.ps1 -CheckId 12,13,16,17,19,23,24,54,55,59,60 `
    -MaxItems 500 -OutputDirectory .\reports

# Credential exposure indicators, always redacted.
.\Invoke-StealthPrivesc.ps1 -CheckId 72,73,74,81,95,98 -IncludeSensitive `
    -OutputDirectory .\reports

# Bounded AD checks.
.\Invoke-StealthPrivesc.ps1 -CheckId 141,143,144,145,146,147 -IncludeDomain `
    -MaxItems 100 -OutputDirectory .\reports

$report = .\Invoke-StealthPrivesc.ps1 -CheckId 1,4,12,47,100 -PassThru
$report.Checks | Select-Object Id,Status,Findings,Limitations
```

Use the identity whose access you want to assess. An elevated administrator's control rights are generally expected. The scanner never requests elevation, enables privileges, starts services, triggers tasks, changes policies, repairs MSI packages or sends exploitation payloads. Follow your organization's approved signing/execution process if script policy blocks execution.

## Opt-ins and limits

* `-IncludeSensitive` enables credential and browser/activity checks. Windows/WinRT/browser/IIS/WLAN APIs may return credentials internally; reports retain exposure indicators only. Native buffers are cleared where possible. App-bound browser encryption and Firefox primary passwords are not bypassed. The SSPI probe preserves the original challenge/security flags and exports no authentication tokens.
* `-IncludeDomain` enables SYSVOL/AD and DC policy queries. Actual gMSA password-readability probing additionally requires `-IncludeSensitive`.
* `-IncludeNetwork` enables external DNS, NVD package advisory queries and link-local cloud metadata probes. NVD receives package names/versions, capped at ten queries per run. Cloud token/credential accessibility additionally requires `-IncludeSensitive`; returned tokens are never used against other services. Metadata probes disable proxies/redirects; AWS uses a short-lived IMDSv2 session.
* Either network/domain opt-in permits UNC targets. Windows APIs can perform implicit name/principal resolution; the flags are not a network sandbox.
* `-SearchRoot` scopes generic file searches; fixed product/service/task paths are also inspected. Reparse points are skipped.
* `-MaxItems` bounds findings and individual enumerations, not total work. `-MaxFileBytes` bounds inspected content and decompression. External/native helper processes use `-CommandTimeoutSeconds`. Pipe/device loops also have a cooperative 60-second budget. CIM/COM/LDAP calls do not all have universal timeouts.

Pipe checks connect only for metadata, using identification-level security. Device/handle checks query and close handles without writing through them. Windows may log these operations. Reports still contain paths, SIDs, usernames and hostnames.

## Offline references

Dated MSRC fixed-build, LOLDrivers hash/signature and LOLBAS name/path snapshots are bundled. Scans do not refresh them automatically. Missing, invalid or older-than-30-day references produce Partial results. No driver binaries or LOLBAS command payloads are included.

```powershell
# Updater requires PowerShell 7 and explicitly accesses public sources.
pwsh .\tools\Update-ReferenceData.ps1 -Drivers -Lolbas
pwsh .\tools\Update-ReferenceData.ps1 -WindowsUpdates `
    -Month 2019-Apr,2019-May,2019-Jun,2019-Jul,2019-Aug,2019-Sep,2019-Oct,2019-Nov,2019-Dec,2020-Feb,2020-Mar,2020-Apr,2020-May,2020-Jun,2020-Jul,2020-Aug,2020-Sep,2025-Nov,2026-Jul,2026-Aug,2026-Sep
```

The Windows updater replaces the snapshot with the requested months. Include historical months to retain the Watson/Recall records. `-DriverDatabasePath` and `-VulnerabilityDatabasePath` accept compatible local snapshots. Patch assessment matches exact product branch, architecture, role and revision; it does not replace Microsoft's full applicability engine.

CI assessment distinguishes kernel-mode deny rules from user-mode rules and correlates runtime policy enforcement where accessible. Missing deny matches do **not** prove that Windows would load a driver. Conditional signer rules and incomplete metadata remain explicit.

## Results

| Status | Meaning |
|---|---|
| Completed | Collector completed within declared scope, not a security verdict. |
| Partial | Access, data, format, dependency or enumeration limits affected assessment. |
| Skipped | Required opt-in or applicable environment is absent. |
| Error | Collector failed; earlier evidence remains. |
| Unsupported | Reserved for unimplemented catalog entries; none remain in 0.2. |

File/registry/object checks use Windows access evaluation. AD checks use object-specific AccessCheckByType. These observations do not establish execution reachability or override mandatory integrity, locks or custom loaders. NVD keyword results, SOAP markers, historical ghost-DLL rules and AD CS prerequisite combinations are candidates requiring contextual validation.

## Validate

On 64-bit Windows, with both 64-bit PowerShell 7 and Windows PowerShell 5.1 installed, run the complete local test matrix from the repository root. The runner finds `pwsh.exe` on `PATH` or in its standard Program Files location:

```powershell
.\tools\Test-Project.ps1
```

The runner checks the runtime versions and architectures, then runs both test scripts under each edition. It exits with code `0` only when all four invocations pass; a missing or unsupported runtime, or any failed test, produces a nonzero exit code. Run it as a user with a loaded Windows profile: the DPAPI fixtures can fail under sandbox or service tokens without a loaded profile. Test fixtures use a uniquely named temporary directory inside the repository and the runner removes it when finished.

To run one test script manually under a single edition:

```powershell
pwsh -NoProfile -File .\tests\Test-StealthPrivesc.ps1
pwsh -NoProfile -File .\tests\Test-ExtendedChecks.ps1
powershell.exe -NoProfile -File .\tests\Test-StealthPrivesc.ps1
powershell.exe -NoProfile -File .\tests\Test-ExtendedChecks.ps1
```

Tests cover synthetic DPAPI/AES-GCM secrets, deny/object-specific ACLs, exact patch/hash matching, kernel-vs-user CI rules, read-only SQLite, decompression bounds, redaction, CLI gating and report encoding. DPAPI fixtures require a loaded user profile and fail under some sandbox tokens. Live sensitive stores, every product and every AD/AD CS topology have not been validated in a representative lab.

See [design](docs/DESIGN.md), [coverage](docs/COVERAGE.md), [sources](docs/REFERENCES.md) and [third-party notices](docs/THIRD-PARTY.md).
