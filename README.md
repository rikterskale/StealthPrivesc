# StealthPrivesc

A read-only Windows privilege-escalation exposure scanner. It gathers evidence without exploiting findings or changing the assessed configuration. Sensitive values are redacted from reports.

## Quick start

On **64-bit Windows 11 or Windows Server 2019/2022/2025**, use **Windows PowerShell 5.1 or PowerShell 7**. First, clone the project if needed; then run the scan from the repository folder:

If you have not downloaded the project yet:

```powershell
git clone https://github.com/rikterskale/StealthPrivesc.git
Set-Location .\StealthPrivesc
```

```powershell
.\Invoke-StealthPrivesc.ps1 -OutputDirectory .\reports
```

This selects the full catalog and writes timestamped JSON and standalone HTML reports to `reports`. Checks requiring an opt-in are identified in the report; the default run does not enable domain, network, or sensitive checks.

If your organization blocks script execution, follow its approved signing and execution process.

## Choose what to scan

Each row is a complete command. These examples save JSON and HTML reports under `reports`.

| I want to check… | Run this command |
| --- | --- |
| Current identity and token | `.\Invoke-StealthPrivesc.ps1 -Category Identity -OutputDirectory .\reports` |
| Services, scheduled tasks, and startup paths | `.\Invoke-StealthPrivesc.ps1 -Category Services,TasksStartup -OutputDirectory .\reports` |
| Windows hardening, patches, and driver risk | `.\Invoke-StealthPrivesc.ps1 -Category Hardening,SystemRisk -OutputDirectory .\reports` |
| Credential exposure, including domain SYSVOL checks | `.\Invoke-StealthPrivesc.ps1 -Category CredentialExposure -IncludeSensitive -IncludeDomain -OutputDirectory .\reports` |
| Domain and AD configuration | `.\Invoke-StealthPrivesc.ps1 -Category DomainCloud -IncludeDomain -OutputDirectory .\reports` |
| Domain/cloud checks with network and sensitive probes | `.\Invoke-StealthPrivesc.ps1 -Category DomainCloud -IncludeDomain -IncludeNetwork -IncludeSensitive -OutputDirectory .\reports` |
| External DNS check | `.\Invoke-StealthPrivesc.ps1 -CheckId 132 -IncludeNetwork -OutputDirectory .\reports` |
| A hand-picked set | `.\Invoke-StealthPrivesc.ps1 -CheckId 12,13,16,23,24 -OutputDirectory .\reports` |

For example, save a service and startup review:

```powershell
.\Invoke-StealthPrivesc.ps1 -Category Services,TasksStartup -OutputDirectory .\reports
```

`-Category` combines categories. If you also provide `-CheckId`, only IDs matching both selectors run. With neither selector, the full catalog is selected. Preview the IDs and scopes before scanning:

```powershell
.\Invoke-StealthPrivesc.ps1 -ListChecks -Category Services,TasksStartup
```

## Read the results

The console shows one row per selected check and a status summary. The output directory contains timestamped `assessment-*.json` and `assessment-*.html` files. HTML is for browsing; JSON preserves structured evidence. `-PassThru` returns the report object:

```powershell
$report = .\Invoke-StealthPrivesc.ps1 -Category Identity -PassThru
$report.Checks | Select-Object Id,Status,Findings,Limitations
```

| Status | Meaning |
|---|---|
| `Completed` | The collector completed within its declared scope; this is not a security verdict. |
| `Partial` | Access, data, format, dependency, or enumeration limits affected the check. |
| `Skipped` | A required opt-in or applicable environment was absent. |
| `Error` | The collector failed; other checks continue. |

A finding is evidence to review, not automatically a vulnerability or confirmed escalation path. Check its `Observation`, `Evidence`, `Remediation`, and scope notes. Missing findings do not prove a system is safe.

## Scope and permissions

Run as the Windows identity whose access you want to assess. An elevated administrator can reveal additional control rights, but the script does not request elevation or change privileges.

| Switch | Enables | Notes |
|---|---|---|
| `-IncludeSensitive` | Credential, browser, and activity checks | Values stay redacted. Some APIs may return secret material internally; buffers are cleared where possible. |
| `-IncludeDomain` | AD, SYSVOL, and domain-controller queries | AD checks require a domain-joined host and RSAT ActiveDirectory. gMSA password-readability checks also need `-IncludeSensitive`. |
| `-IncludeNetwork` | External DNS, NVD package lookups, and cloud metadata probes | NVD receives package names/versions, capped at ten queries per run. Metadata probes use fixed link-local endpoints. |

Some checks collect local evidence while reporting a limitation for a gated portion. Network/domain opt-ins permit UNC targets; Windows may also perform implicit name or principal resolution. These switches are scope controls, not a network sandbox.

Windows, WinRT, browser, IIS, and WLAN APIs can return credential material to the process; reports retain exposure indicators only. App-bound browser encryption and Firefox primary passwords are not bypassed. Cloud identity probes record accessibility and discard returned tokens without using them elsewhere. Metadata requests use fixed endpoints without proxies or redirects; AWS uses a short-lived IMDSv2 session. Pipe, device, and handle checks inspect metadata only and close opened handles. Reports can contain paths, SIDs, usernames, and hostnames.

Firefox recovery requires a publisher-verified installed Mozilla NSS runtime; unsupported profiles or unavailable runtimes are reported as limited coverage.

`-SearchRoot` scopes generic file searches; fixed product/service/task paths are still inspected. `-MaxItems`, `-MaxFileBytes`, and `-CommandTimeoutSeconds` bound selected work; see [design and limits](docs/DESIGN.md).

## Check catalog

Use the category list to choose a bundle. Expand **All check IDs** for every ID and name, or use the [detailed check reference](docs/CHECK-REFERENCE.md) for per-ID descriptions, invocation commands, underlying APIs, and positive report examples. [Coverage notes](docs/COVERAGE.md) explain collector limits.

| Category | Checks | Typical focus |
|---|---:|---|
| `AccessControl` | 18 | Writable paths, registry/COM permissions, processes, pipes, and devices |
| `CredentialExposure` | 33 | Credential stores, browser artifacts, and secret-bearing files |
| `DomainCloud` | 8 | AD, AD CS, relay indicators, and cloud identity |
| `Hardening` | 24 | Windows policy and security configuration |
| `Identity` | 10 | Token, accounts, groups, sessions, and account policy |
| `Inventory` | 17 | Host, software, network, and artifact inventory |
| `Services` | 11 | Service configuration and permissions |
| `SystemRisk` | 20 | Installer, patch, driver, and vulnerability checks |
| `TasksStartup` | 7 | Scheduled tasks and startup locations |

<details>
<summary>All check IDs</summary>

##### AccessControl

| Check ID | Check |
| ---: | --- |
| 29 | Writable directories in executable/DLL search paths, particularly system PATH |
| 30 | Process DLL-hijacking candidates, including relevant writable process locations |
| 31 | Known services susceptible to missing/“ghost” DLL hijacking, correlated with writable search paths |
| 32 | Writable installed-application files and directories, including third-party applications |
| 33 | Writable application directories under ProgramData |
| 34 | Writable directories at fixed-drive roots and their contents |
| 35 | Writable executable files in nonstandard locations |
| 36 | Writable COM server registration keys |
| 37 | Writable COM server DLL/EXE files |
| 38 | COM registrations referencing missing modules through relative paths, creating potential ghost-DLL search opportunities |
| 39 | Stale COM registrations referencing nonexistent files |
| 40 | Writable machine registry keys: known exposed HKLM descendants and a bounded heuristic search |
| 41 | Cross-user TypingInsights registry-key permissions |
| 42 | Excessive permissions on another user’s processes or threads |
| 43 | Accessible leaked handles to privileged processes, threads or files |
| 44 | Named-pipe ACLs and writable pipes, including correlation with privileged pipe servers where implemented |
| 45 | Writable named kernel-device objects |
| 46 | Potentially unsafe .NET SOAP client proxy configurations—SOAPwn-related surfaces |

##### CredentialExposure

| Check ID | Check |
| ---: | --- |
| 67 | Winlogon/automatic-logon credentials in the registry |
| 68 | Unattended-installation and Sysprep answer files containing credentials |
| 69 | Cached Group Policy Preferences passwords / cpassword material |
| 70 | Domain/SYSVOL Group Policy Preferences password searches |
| 71 | Readable SAM, SYSTEM and SECURITY hive files, including backups or shadow-copy exposure where implemented |
| 72 | Windows Credential Manager entries and accessible saved credentials |
| 73 | Windows Vault web/Windows credentials |
| 74 | UWP PasswordVault / Credential Locker entries |
| 75 | DPAPI master-key files and credential blobs |
| 76 | Credentials exposed through Windows security packages |
| 77 | Kerberos ticket-cache and TGT information |
| 78 | PowerShell history and transcript files containing secrets |
| 79 | Secrets in event logs: PowerShell script blocks, process-creation command lines and Sysmon events |
| 80 | Registry values containing possible passwords or credential material, including application-specific locations and broader searches |
| 81 | IIS/web application configuration credentials: web.config, connection strings and application-pool credentials, including decryption where supported. U; W searches relevant files and uses AppCmd |
| 82 | McAfee SiteList.xml credentials and related configuration |
| 83 | SCCM Network Access Account credential blobs |
| 84 | SCCM cache contents and files containing possible embedded credentials. P; W also enumerates SCCM-related information |
| 85 | Symantec Management Agent Account Connectivity Credentials |
| 86 | SCOM Run As account traces indicating stored credentials |
| 87 | VNC server passwords/configuration: RealVNC, TigerVNC, TightVNC and UltraVNC where supported. P; W searches VNC artifacts |
| 88 | Saved RDP connections and RDCMan settings/credential files |
| 89 | PuTTY, SuperPuTTY and MTPuTTY session/configuration artifacts, including referenced keys and saved connection information |
| 90 | FileZilla and other FTP/SFTP-client configuration files |
| 91 | KeePass databases, configuration and key-file clues |
| 92 | Oracle SQL Developer connection/configuration files |
| 93 | Cloud credential files and token caches: AWS, Azure, Google Cloud and Bluemix-related artifacts |
| 94 | Certificates, private-key files and certificate-store metadata |
| 95 | Saved Wi-Fi profiles and recoverable pre-shared keys |
| 96 | Potentially insecure enterprise/802.1X Wi-Fi profiles |
| 97 | Clipboard contents potentially containing secrets |
| 98 | Browser credential databases and recoverable stored logins. W; S identifies relevant browser artifacts |
| 99 | Generic sensitive-file and secret searches: configuration files, backups, scripts, logs, SSH/VPN keys, Git credentials, databases, container/Kubernetes configuration, CI/CD artifacts and other configured filename/regex matches |

##### DomainCloud

| Check ID | Check |
| ---: | --- |
| 141 | Applied domain GPOs writable by the current principal, plus local GPO configuration. W; S inventories local GPOs |
| 142 | Current computer’s LAPS password readable from Active Directory |
| 143 | Readable gMSA managed-password material / relevant access relationships |
| 144 | AD object control rights, including useful write, ownership and DACL permissions on sampled objects |
| 145 | Kerberoastable service accounts and associated encryption/account-risk indicators |
| 146 | AD CS certificate-template/configuration misconfiguration indicators |
| 147 | KrbRelayUp-related configuration indicators |
| 148 | Cloud metadata, identity/token exposure and Google synchronization/join artifacts, plus detection of container context |

##### Hardening

| Check ID | Check |
| ---: | --- |
| 100 | UAC configuration: elevation policy, administrative token filtering and remote restrictions |
| 101 | LSA protection / RunAsPPL configuration |
| 102 | Credential Guard configuration/state |
| 103 | WDigest settings and cached-domain-logon configuration. W; S exposes related LSA settings — Audit |
| 104 | Credential-delegation configuration |
| 105 | NTLM settings and NTLMv1/downgrade exposure |
| 106 | SMBv1 and client/server SMB-signing requirements |
| 107 | Hardened UNC path policies |
| 108 | Broadcast/multicast name-resolution protocols and IPv6 configuration |
| 109 | Proxy, WPAD/PAC and Internet-zone configuration |
| 110 | LAPS installation and policy configuration, including legacy/Windows LAPS where supported |
| 111 | Default local Administrator account enabled/disabled state |
| 112 | AppLocker policy/enforcement and potentially permissive rules |
| 113 | PowerShell versions and security settings, including logging-related policy |
| 114 | PowerShell remoting/session endpoint configuration and permissions |
| 115 | Antivirus/EDR products, defensive processes and AMSI providers |
| 116 | Defender settings and exclusions; ASR rules; Defender for Endpoint state |
| 117 | Audit policy, Sysmon and Windows Event Forwarding settings |
| 118 | UEFI/Secure Boot, TPM, BitLocker and DMA-protection state. P covers UEFI/Secure Boot, TPM and BitLocker; S covers Secure Boot; W includes DMA protection — Audit/context |
| 119 | Office macro policy, Protected View and writable trusted locations |
| 120 | ClickOnce trust prompts, risky file-extension associations and hidden extensions |
| 121 | Lock-screen network-selection policy associated with Airstrike exposure |
| 122 | RDP client/server security settings |
| 123 | Windows Firewall profiles, state and rules |

##### Identity

| Check ID | Check |
| ---: | --- |
| 1 | Current identity and token context: username, SID, domain, integrity/elevation, token type and related identity information |
| 2 | Current token group memberships: local/domain groups, administrative membership, and relevant group attributes |
| 3 | Restricted token SIDs |
| 4 | Potentially dangerous token privileges: impersonation, debugging, backup/restore, ownership, driver loading, TCB and other privilege assignments; exact flagged sets differ |
| 5 | Privileges assigned through local/domain policy, including rights potentially available after a new logon |
| 6 | Local users and groups: administrators, account state, password timestamps and membership information |
| 7 | Password and account-lockout policies |
| 8 | Logged-on users and sessions: interactive/logon sessions, incoming RDP sessions and previously logged-on users, depending on tool |
| 9 | Other users’ profile/home directories and their accessibility, including readable or writable locations |
| 10 | Environment variables containing credentials, tokens or sensitive configuration |

##### Inventory

| Check ID | Check |
| ---: | --- |
| 124 | OS, architecture, machine role, domain/tenant join and runtime information |
| 125 | Installed applications, Windows roles/features and running processes/owners/command lines |
| 126 | Active-window information and user idle time. W; S reports idle time — Context |
| 127 | Startup, shutdown, reboot and sleep history |
| 128 | Logon and explicit-credential-use events |
| 129 | Disks, mounted volumes, mapped drives and network shares |
| 130 | Network interfaces, profiles, ARP, routes, hosts file and DNS cache |
| 131 | TCP/UDP listeners and connections, with owning processes/services where available |
| 132 | Internet connectivity, external hostname resolution and optional network/port discovery |
| 133 | RPC endpoint mappings |
| 134 | WMI permanent event consumers, filters and bindings |
| 135 | Printers and printing-related inventory |
| 136 | Browser history, bookmarks, typed URLs, open tabs and profile artifacts |
| 137 | Recent files, Explorer Run history, Office MRUs and Recycle Bin contents |
| 138 | Outlook downloads, OneNote backups, Slack artifacts and OneDrive/Office 365 synchronization locations |
| 139 | Windows Search Index queries, generic directory listing, registry querying and file metadata inspection |
| 140 | LOLBAS discovery and WSL/Linux-shell artifacts |

##### Services

| Check ID | Check |
| ---: | --- |
| 11 | Installed services: executable paths, accounts, start modes and third-party service identification |
| 12 | Modifiable service objects: service configuration, ownership or DACL rights that permit controlling a service |
| 13 | Modifiable Service Control Manager permissions |
| 14 | Writable service registry keys and settings |
| 15 | Writable extended service registry settings/subkeys |
| 16 | Writable service executables, associated files or containing directories |
| 17 | Unquoted service executable paths containing spaces, including writable interception locations where implemented |
| 18 | Writable DLLs explicitly loaded by LocalSystem services |
| 19 | Writable LocalSystem service recovery-command targets |
| 20 | Service start/stop/restart permissions: supporting feasibility checks; PrivescCheck also has a dedicated experimental restart check |
| 21 | Services using accounts whose passwords are stored locally as service secrets |

##### SystemRisk

| Check ID | Check |
| ---: | --- |
| 47 | AlwaysInstallElevated Windows Installer policy, including machine and user settings |
| 48 | Windows Installer repair UAC-prompt suppression |
| 49 | MSI repair allowlists and potentially unsafe custom actions in allowlisted packages |
| 50 | Potentially unsafe custom actions in cached MSI packages |
| 51 | Print Spooler and Point-and-Print configuration permitting unsafe printer-driver installation |
| 52 | Driver co-installer policy |
| 53 | WSUS configuration: update-server location, HTTP versus HTTPS and related policy |
| 54 | Missing Windows patches / OS-version vulnerability matching |
| 55 | Watson’s explicit CVE checks: CVE-2019-0836, -0841, -1064, -1130, -1253, -1315, -1385, -1388, -1405; CVE-2020-0668, -0683, -1013 |
| 56 | Installed hotfixes, Microsoft updates and update history/recency |
| 57 | BIOS update/release age |
| 58 | Installed third-party kernel/device drivers |
| 59 | Known vulnerable drivers matched against the LOLDrivers database |
| 60 | Known vulnerable drivers not covered by local Code Integrity blocking policies |
| 61 | Unsigned or legacy/weakly signed kernel drivers |
| 62 | Risky OEM privileged utilities/components |
| 63 | Installed-package vulnerability lookup |
| 64 | CLFS logfile-authentication mitigation configuration |
| 65 | Object Manager namespace access relevant to race-window amplification |
| 66 | KernelQuick/ValleyRAT-related registry indicators |

##### TasksStartup

| Check ID | Check |
| ---: | --- |
| 22 | Scheduled-task inventory: actions, paths, execution accounts and other task details |
| 23 | Writable scheduled-task executables, scripts or containing directories |
| 24 | Low-privilege control over enabled SYSTEM scheduled tasks |
| 25 | Unquoted scheduled-task action paths |
| 26 | Scheduled tasks configured with password-based logon, indicating locally stored account secrets |
| 27 | Microsoft Recall PolicyConfiguration task exposure, combining task configuration markers with OS/build information |
| 28 | Startup/autorun entries and writable referenced programs or directories |

</details>

## Supported platforms

The intended client targets are 64-bit Windows 11 versions 24H2, 25H2 and 26H1, using Home, Pro, Enterprise or Education. Windows 10 is outside the supported-platform scope. The intended server targets are 64-bit Windows Server 2019, 2022 and 2025, using Standard or Datacenter. Other Windows editions, ARM64, Windows Server Essentials and Azure Edition are not in the stated support scope.

Use a Windows 11 version and edition that is still receiving Microsoft security updates. Windows 11 servicing dates differ by edition; version 26H1 is intended for new devices and is not offered as an in-place update from 24H2 or 25H2. Windows Server support follows each release's Microsoft lifecycle. These platform targets describe intended compatibility, not certification on every edition or release. The automated test matrix below checks both PowerShell editions on the test host; it does not provide a separate OS-version test run for every target. See Microsoft's [Windows 11 release information](https://learn.microsoft.com/en-us/windows/release-health/windows11-release-information) and [Windows Server release information](https://learn.microsoft.com/en-us/windows/release-health/windows-server-release-info) for current servicing details.

## Offline reference data

The scanner uses bundled, dated MSRC, LOLDrivers, and LOLBAS snapshots. It does not refresh them during a scan. Missing, invalid, or older-than-30-day references produce `Partial` results. No driver binaries or LOLBAS command payloads are included. See [third-party notices](docs/THIRD-PARTY.md) for licenses and provenance.

Update snapshots only when needed; the updater requires PowerShell 7 and accesses public sources:

```powershell
pwsh .\tools\Update-ReferenceData.ps1 -Drivers -Lolbas
pwsh .\tools\Update-ReferenceData.ps1 -WindowsUpdates -Month <comma-separated-month-list>
```

The Windows updater replaces the snapshot with the requested months. Include historical months to retain Watson/Recall records. `-DriverDatabasePath` and `-VulnerabilityDatabasePath` accept compatible local snapshots. Patch assessment matches exact product branch, architecture, role, and revision; it is not Microsoft's full applicability engine.

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

## License and notices

Project-authored material is licensed under the [MIT License](LICENSE). Third-party components and data retain separate terms; see [third-party notices](docs/THIRD-PARTY.md).

See also [design](docs/DESIGN.md), [coverage](docs/COVERAGE.md), and [references](docs/REFERENCES.md).
