# Platform validation

Windows 11 and Server 2019 use 64-bit operating systems. Here, **x86/x64 describes the PowerShell process**, not a 32-bit Windows edition. ARM64 is outside the validation scope.

| OS target | OS architecture | Process matrix | Test mechanism |
| --- | --- | --- | --- |
| Windows 11 | x64 | PowerShell 5.1, 7.4.13, 7.6.6; x86/x64 | Dedicated disposable runners; Standard/Elevated account contexts |
| Server 2019 | x64 | PowerShell 5.1, 7.4.13, 7.6.6; x86/x64 | Dedicated disposable runners; Standard/Elevated account contexts |
| Server 2022/2025 | x64 | PowerShell 5.1, 7.4.13, 7.6.6; x86/x64 | Hosted CI (12 cells total); hosted token context is recorded |
| Domain lab | x64 | PowerShell 5.1, 7.4.13, 7.6.6; x86/x64 | Dedicated domain-joined runners with RSAT and synthetic lab configuration |

A configured workflow is a validation target, not evidence of a successful run. Save `validation.json` and its matching log for the specific OS/build. One Windows 11 build does not certify all versions or editions. Server 2019 remains unverified until its dedicated machine completes validation.

Historical validation on 2026-09-30 used older suites on Windows 11 Pro build 26200. That evidence does not certify the current tree or the new CI suite. Server 2019 has offline applicability fixtures, but no run on the actual OS has been performed. Record successful runs by commit, actual OS/build, process runtime and account token before claiming coverage.

## Local validation

From a logged-in Windows session with a loaded profile:

```powershell
$modules = .\.github\ci\Bootstrap.ps1 -Destination .\TestResults\modules
$runtime = .\.github\ci\Get-Runtime.ps1 -Version 5.1 -Architecture x86 -Destination .\TestResults\runtimes
& $runtime -NoProfile -File .\.github\ci\Invoke-Validation.ps1 -ModulesDirectory $modules -ResultsDirectory .\TestResults\local-5.1-x86 -Cell local-5.1-x86 -ExpectedVersion 5.1 -ExpectedArchitecture x86
```

The exact portable PowerShell versions and official-release SHA256 values are recorded in [dependency pins](../.github/ci/dependencies.psd1). Downloads/modules stay in job-local directories; the bootstrap runs in PowerShell 7. Runtime selection probes actual version and bitness. No missing runtime or skipped automated test receives coverage credit. Scoped command coverage is for reference-data and verification helpers, not the entire scanner or native APIs.

## Dedicated GitHub runners

The [platform workflow](../.github/workflows/platform-validation.yml) is manual-only and rejects refs other than `main`. Provision disposable x64 VMs with Windows PowerShell 5.1, x64 PowerShell 7, Git and a loaded test-user profile. Use separate accounts/runners for standard and elevated tokens; the workflow validates actual elevation rather than trusting the label. Register labels along with `self-hosted`, `Windows`, `X64`:

- Windows 11: `stealthprivesc-Windows11-Standard` / `stealthprivesc-Windows11-Elevated`
- Server 2019: `stealthprivesc-Server2019-Standard` / `stealthprivesc-Server2019-Elevated`
- Domain lab: `stealthprivesc-DomainLab-Standard` / `stealthprivesc-DomainLab-Elevated`

Dispatch **Dedicated platform validation**, choosing a platform and account context. `Both` requires both context runners and defines 12 cells on that platform. The runner checks workstation build >= 22000 for Windows 11, or server product type/build 17763 for Server 2019. Domain lab requires domain membership and the ActiveDirectory module. Jobs retain evidence for 30 days. They never change domain membership, provision products or request elevation. No test VM is provisioned by this repository.

Integration first checks the read-only API contract and fails before scanner execution if it finds mutation APIs. Collector access failures and intentional bounds remain explicit; a successful offline suite is not live-environment validation. Browser/credential-store APIs, every Windows edition/build, cloud identity behavior and all AD/AD CS topologies need additional representative fixtures and lab evidence.

## Collection views

Use x64 PowerShell for native system coverage. In an x86 process, WOW64 redirects portions of registry and filesystem access. JSON records `ProcessArchitecture`, `OperatingSystemArchitecture` and `CollectionView`; HTML displays the collection-view notice. Existing explicit WOW6432Node queries supplement the selected view but do not establish identical coverage between processes.

Local account inventory uses a timed native Windows PowerShell helper when the LocalAccounts module is unavailable to the x86 host. Firefox helpers match the NSS library's PE architecture, and native x64 helpers use `Sysnative` when called from x86. Native structures are compiled and exercised in both process architectures. A `Partial` collector still needs its limitations reviewed.

Microsoft documents [Windows 11's 64-bit requirement](https://support.microsoft.com/en-us/windows/experience/compatibility/32-bit-and-64-bit-windows-frequently-asked-questions) and [Windows Server hardware requirements](https://learn.microsoft.com/windows-server/get-started/hardware-requirements). Standard [GitHub hosted runner labels](https://docs.github.com/en/actions/reference/runners/github-hosted-runners) currently include Server 2022/2025, so Win11 x64 and Server 2019 validation use dedicated machines.
