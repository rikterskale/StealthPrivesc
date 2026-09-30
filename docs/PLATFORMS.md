# Platform validation

Windows 11 and Server 2019 use 64-bit operating systems. Here, **x86/x64 describes the PowerShell process**, not a 32-bit Windows edition. ARM64 is outside the validation scope.

| OS target | OS architecture | Process matrix | Test mechanism |
| --- | --- | --- | --- |
| Windows 11 | x64 | PowerShell 5.1/7, x86/x64 | Local runner; manually dispatched dedicated-runner workflow |
| Server 2019 | x64 | PowerShell 5.1/7, x86/x64 | Manually dispatched dedicated-runner workflow; requires a provisioned machine |
| Server 2022/2025 | x64 | PowerShell 5.1/7, x86/x64 | Hosted CI |

A configured workflow is a validation target, not evidence of a successful run. Save `validation.json` and its matching log for the specific OS/build. One Windows 11 build does not certify all versions or editions. Server 2019 remains unverified until its dedicated machine completes validation.

On 2026-09-30, local validation passed all 30 suite/runtime combinations on Windows 11 Pro build 26200 with PowerShell 7.6.5 and Windows PowerShell 5.1.26100.9549, each in x86 and x64 processes. Server 2019 has offline applicability fixtures, but no run on the actual OS has been performed.

## Local validation

From a logged-in Windows session with a loaded profile:

```powershell
$x86 = .\tools\Get-TestPowerShell.ps1 -Architecture x86
.\tools\Test-Project.ps1 -PowerShell7X86Path $x86 -ExpectedPlatform Windows11 -ResultsDirectory .\TestResults\win11
# On the Server 2019 test machine:
.\tools\Test-Project.ps1 -PowerShell7X86Path $x86 -ExpectedPlatform Server2019 -ResultsDirectory .\TestResults\server2019
```

The portable dependency is PowerShell 7.6.5 from its [official release](https://github.com/PowerShell/PowerShell/releases/tag/v7.6.5), verified against the published SHA256. No machine-wide installation or PATH change is performed. You can instead supply approved installations with `-PowerShell7X86Path` and `-PowerShell7X64Path`. The full matrix runs 30 suite/runtime combinations; each focused architecture runs 15. Missing runtimes, timeouts and failed fixtures exit nonzero. DPAPI fixtures require a loaded user profile.

## Dedicated GitHub runners

The [platform workflow](../.github/workflows/platform-validation.yml) is manual-only. Provision an x64 machine with Windows PowerShell 5.1, x64 PowerShell 7, Git and a loaded test-user profile. Register these labels along with the standard `self-hosted`, `Windows`, `X64` labels:

- Windows 11: `stealthprivesc-Windows11`
- Server 2019: `stealthprivesc-Server2019`

Dispatch **Windows platform validation**, choosing the available OS and process architectures. Choosing `Both` needs both machines. The runner checks workstation build >= 22000 for Windows 11, or server product type with build 17763 for Server 2019; a mislabeled machine fails rather than receiving platform coverage. The jobs upload validation results/logs for 14 days. No Server 2019 machine is provisioned by this repository.

## Collection views

Use x64 PowerShell for native system coverage. In an x86 process, WOW64 redirects portions of registry and filesystem access. JSON records `ProcessArchitecture`, `OperatingSystemArchitecture` and `CollectionView`; HTML displays the collection-view notice. Existing explicit WOW6432Node queries supplement the selected view but do not establish identical coverage between processes.

Local account inventory uses a timed native Windows PowerShell helper when the LocalAccounts module is unavailable to the x86 host. Firefox helpers match the NSS library's PE architecture, and native x64 helpers use `Sysnative` when called from x86. Native structures are compiled and exercised in both process architectures. A `Partial` collector still needs its limitations reviewed.

Microsoft documents [Windows 11's 64-bit requirement](https://support.microsoft.com/en-us/windows/experience/compatibility/32-bit-and-64-bit-windows-frequently-asked-questions) and [Windows Server hardware requirements](https://learn.microsoft.com/windows-server/get-started/hardware-requirements). Standard [GitHub hosted runner labels](https://docs.github.com/en/actions/reference/runners/github-hosted-runners) currently include Server 2022/2025, so Win11 x64 and Server 2019 validation use dedicated machines.
