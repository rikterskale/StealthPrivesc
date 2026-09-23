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

# Smaller bundles by catalog category. Combine categories as needed.
.\Invoke-StealthPrivesc.ps1 -Category Identity -OutputDirectory .\reports
.\Invoke-StealthPrivesc.ps1 -Category Services,TasksStartup -OutputDirectory .\reports
.\Invoke-StealthPrivesc.ps1 -Category Hardening,SystemRisk -OutputDirectory .\reports

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

### Choosing a smaller run

`-Category` takes one or more of these exact names. Supplying multiple categories runs the checks from all of them:

| Category | Checks | What it covers |
| --- | ---: | --- |
| `AccessControl` | 18 | Object and resource permissions, including services and files |
| `CredentialExposure` | 33 | Credential, browser, and user activity exposure indicators |
| `DomainCloud` | 8 | Domain and cloud configuration checks |
| `Hardening` | 24 | Windows security and configuration policy |
| `Identity` | 10 | Current identity, token, users, groups, and account policy |
| `Inventory` | 17 | Host, software, network, and related inventory |
| `Services` | 11 | Service configuration and permissions |
| `SystemRisk` | 20 | System risk, patch, installer, driver, and vulnerability checks |
| `TasksStartup` | 7 | Scheduled tasks and startup locations |

#### Check IDs by category

This catalog shows every check ID and its full title, grouped by the exact `-Category` value accepted by the script.

For underlying Windows commands/APIs and per-check positive-result examples, see the companion [check reference](docs/CHECK-REFERENCE.md).

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

Use `-ListChecks` to see each check's ID, title, scope, and coverage without running it. You can preview the exact category selection with `-ListChecks -Category Services,TasksStartup`. To pick individual checks, use `-CheckId 12,13,16`. If you supply both `-Category` and `-CheckId`, the script runs only IDs that belong to one of the selected categories. With neither selector, it runs all 148 checks.

Category selection does not automatically enable scope opt-ins. Checks requiring domain, network, or sensitive access need `-IncludeDomain`, `-IncludeNetwork`, or `-IncludeSensitive`, respectively; otherwise they appear as skipped in the report. See [Opt-ins and limits](#opt-ins-and-limits) for what each switch permits. Script help is also available with `Get-Help .\\Invoke-StealthPrivesc.ps1 -Detailed`.

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
