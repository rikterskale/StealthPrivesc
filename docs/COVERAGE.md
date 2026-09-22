# Checklist coverage

IDs map to the supplied 148-item checklist. Coverage is separate from runtime status. Implemented checks can still return incomplete results; absence of findings does not establish safety.

| ID | Category | Scope | Coverage | Check and limitations |
|---:|---|---|---|---|
| 1 | Identity | Local | Implemented | Current identity and token context: username, SID, domain, integrity/elevation, token type and related identity information  |
| 2 | Identity | Local | Implemented | Current token group memberships: local/domain groups, administrative membership, and relevant group attributes  |
| 3 | Identity | Local | Implemented | Restricted token SIDs  |
| 4 | Identity | Local | Implemented | Potentially dangerous token privileges: impersonation, debugging, backup/restore, ownership, driver loading, TCB and other privilege assignments; exact flagged sets differ  |
| 5 | Identity | Local | Partial | Privileges assigned through local/domain policy, including rights potentially available after a new logon Effective local LSA rights for current token SIDs only; unapplied domain policy/future groups not resolved. |
| 6 | Identity | Local | Partial | Local users and groups: administrators, account state, password timestamps and membership information Local users/groups only; unresolved directory principals may cause incomplete results. |
| 7 | Identity | Local | Implemented | Password and account-lockout policies  |
| 8 | Identity | Local | Partial | Logged-on users and sessions: interactive/logon sessions, incoming RDP sessions and previously logged-on users, depending on tool CIM interactive sessions and associations only; no historical reconstruction. |
| 9 | Identity | Local | Partial | Other users’ profile/home directories and their accessibility, including readable or writable locations Profile metadata, listing access and DACL candidates; contents not recursively assessed. |
| 10 | Identity | Local | Partial | Environment variables containing credentials, tokens or sensitive configuration Environment variable-name heuristic only; values not pattern-scanned. |
| 11 | Services | Local | Partial | Installed services: executable paths, accounts, start modes and third-party service identification Service executable/account/state; publisher identity not verified. |
| 12 | Services | Local | Implemented | Modifiable service objects: service configuration, ownership or DACL rights that permit controlling a service  |
| 13 | Services | Local | Implemented | Modifiable Service Control Manager permissions  |
| 14 | Services | Local | Implemented | Writable service registry keys and settings  |
| 15 | Services | Local | Partial | Writable extended service registry settings/subkeys Only two levels of service registry subkeys, within item limits. |
| 16 | Services | Local | Partial | Writable service executables, associated files or containing directories Main executable and parent only; indirect files/scripts may be missed. |
| 17 | Services | Local | Implemented | Unquoted service executable paths containing spaces, including writable interception locations where implemented  |
| 18 | Services | Local | Partial | Writable DLLs explicitly loaded by LocalSystem services Registered ServiceDll only; other loaded DLLs not traced. |
| 19 | Services | Local | Partial | Writable LocalSystem service recovery-command targets FailureCommand target only; recovery trigger flags not evaluated. |
| 20 | Services | Local | Implemented | Service start/stop/restart permissions: supporting feasibility checks; PrivescCheck also has a dedicated experimental restart check  |
| 21 | Services | Local | Partial | Services using accounts whose passwords are stored locally as service secrets Named-account heuristic; LSA secret storage not verified. |
| 22 | TasksStartup | Local | Partial | Scheduled-task inventory: actions, paths, execution accounts and other task details Task identity/executable metadata; arguments and COM handler details omitted. |
| 23 | TasksStartup | Local | Partial | Writable scheduled-task executables, scripts or containing directories Execute field and simple script arguments only; working-directory resolution not implemented. |
| 24 | TasksStartup | Local | Partial | Low-privilege control over enabled SYSTEM scheduled tasks Task-file ACL only; scheduler API and registry authorization not assessed. |
| 25 | TasksStartup | Local | Partial | Unquoted scheduled-task action paths Unquoted Execute-field heuristic; ambiguity may not apply to Task Scheduler. |
| 26 | TasksStartup | Local | Partial | Scheduled tasks configured with password-based logon, indicating locally stored account secrets Password logon indicator only; no credential extraction. |
| 27 | TasksStartup | Local | Partial | Microsoft Recall PolicyConfiguration task exposure, combining task configuration markers with OS/build information Recall task-name/build markers only; no validated vulnerability rules. |
| 28 | TasksStartup | Local | Partial | Startup/autorun entries and writable referenced programs or directories Run/RunOnce keys and startup folders; shortcuts/other autostarts not resolved. |
| 29 | AccessControl | Local | Implemented | Writable directories in executable/DLL search paths, particularly system PATH  |
| 30 | AccessControl | Local | Partial | Process DLL-hijacking candidates, including relevant writable process locations Loaded module file ACLs; missing DLL loads and privileged owners not correlated. |
| 31 | AccessControl | Local | Partial | Known services susceptible to missing/“ghost” DLL hijacking, correlated with writable search paths Missing/inaccessible ServiceDll heuristic; no known ghost-DLL signature database. |
| 32 | AccessControl | Local | Partial | Writable installed-application files and directories, including third-party applications Registered InstallLocation directory ACLs only. |
| 33 | AccessControl | Local | Partial | Writable application directories under ProgramData Bounded ProgramData directories; privileged use not established. |
| 34 | AccessControl | Local | Partial | Writable directories at fixed-drive roots and their contents Fixed-drive roots and immediate children only. |
| 35 | AccessControl | Local | Partial | Writable executable files in nonstandard locations Bounded executable/script ACL candidates in SearchRoot; privileged use not established. |
| 36 | AccessControl | Local | Partial | Writable COM server registration keys Bounded 32/64-bit and per-user COM registration sample. |
| 37 | AccessControl | Local | Partial | Writable COM server DLL/EXE files Bounded registered COM module and parent ACL candidates. |
| 38 | AccessControl | Local | Partial | COM registrations referencing missing modules through relative paths, creating potential ghost-DLL search opportunities Relative registration strings only; loader search order not resolved. |
| 39 | AccessControl | Local | Partial | Stale COM registrations referencing nonexistent files Missing or inaccessible target candidates; File.Exists cannot distinguish the two. |
| 40 | AccessControl | Local | Partial | Writable machine registry keys: known exposed HKLM descendants and a bounded heuristic search Known HKLM roots and immediate descendants only. |
| 41 | AccessControl | Local | Partial | Cross-user TypingInsights registry-key permissions Loaded-user input Settings ACLs; no TypingInsights-specific evaluation. |
| 42 | AccessControl | Local | Partial | Excessive permissions on another user’s processes or threads Cross-user process rights only; thread objects not assessed. |
| 43 | AccessControl | Local | Unsupported | Accessible leaked handles to privileged processes, threads or files Leaked-handle enumeration and privileged-object correlation are not implemented. |
| 44 | AccessControl | Local | Partial | Named-pipe ACLs and writable pipes, including correlation with privileged pipe servers where implemented Pipe names only; ACLs/server ownership not assessed. |
| 45 | AccessControl | Local | Unsupported | Writable named kernel-device objects Native kernel-device enumeration/access checks are not implemented. |
| 46 | AccessControl | Local | Partial | Potentially unsafe .NET SOAP client proxy configurations—SOAPwn-related surfaces Bounded SOAP/remoting text markers; not a SOAPwn vulnerability determination. |
| 47 | SystemRisk | Local | Implemented | AlwaysInstallElevated Windows Installer policy, including machine and user settings  |
| 48 | SystemRisk | Local | Partial | Windows Installer repair UAC-prompt suppression Registry configuration; patch-dependent effective behavior not resolved. |
| 49 | SystemRisk | Local | Partial | MSI repair allowlists and potentially unsafe custom actions in allowlisted packages Allowlist and bounded cached-MSI deferred/no-impersonate action flags; action bodies and repair reachability need review. |
| 50 | SystemRisk | Local | Partial | Potentially unsafe custom actions in cached MSI packages Read-only MSI action type flags; actions never executed. |
| 51 | SystemRisk | Local | Partial | Print Spooler and Point-and-Print configuration permitting unsafe printer-driver installation Point-and-Print policy evidence; defaults and patch behavior not resolved. |
| 52 | SystemRisk | Local | Partial | Driver co-installer policy Co-installer registry policy evidence only. |
| 53 | SystemRisk | Local | Implemented | WSUS configuration: update-server location, HTTP versus HTTPS and related policy  |
| 54 | SystemRisk | Local | Partial | Missing Windows patches / OS-version vulnerability matching OS/build/UBR/hotfix inventory only; no maintained CVE applicability/supersedence engine. |
| 55 | SystemRisk | Local | Partial | Watson’s explicit CVE checks: CVE-2019-0836, -0841, -1064, -1130, -1253, -1315, -1385, -1388, -1405; CVE-2020-0668, -0683, -1013 Watson CVEs catalogued but not evaluated; only build/hotfix inventory. |
| 56 | SystemRisk | Local | Partial | Installed hotfixes, Microsoft updates and update history/recency QuickFixEngineering inventory only; no complete CBS/WUA history or supersedence. |
| 57 | SystemRisk | Local | Implemented | BIOS update/release age  |
| 58 | SystemRisk | Local | Partial | Installed third-party kernel/device drivers PnP signed-driver metadata; not all loaded legacy/system drivers. |
| 59 | SystemRisk | Local | Partial | Known vulnerable drivers matched against the LOLDrivers database System-driver SHA256 inventory only; LOLDrivers matching is not implemented. |
| 60 | SystemRisk | Local | Partial | Known vulnerable drivers not covered by local Code Integrity blocking policies Blocklist setting and policy-file inventory; policy decoding/hash coverage not implemented. |
| 61 | SystemRisk | Local | Partial | Unsigned or legacy/weakly signed kernel drivers PnP signing metadata; weak algorithms/catalog/legacy trust chains not verified. |
| 62 | SystemRisk | Local | Partial | Risky OEM privileged utilities/components OEM publisher heuristic; no vulnerable product/version database. |
| 63 | SystemRisk | Local | Partial | Installed-package vulnerability lookup Package inventory only; online vulnerability lookup not implemented. |
| 64 | SystemRisk | Local | Partial | CLFS logfile-authentication mitigation configuration CLFS registry evidence only; build/default interpretation not implemented. |
| 65 | SystemRisk | Local | Unsupported | Object Manager namespace access relevant to race-window amplification Object Manager namespace capability probing is not implemented. |
| 66 | SystemRisk | Local | Partial | KernelQuick/ValleyRAT-related registry indicators Code Integrity settings only; no validated KernelQuick/ValleyRAT indicators. |
| 67 | CredentialExposure | Sensitive | Implemented | Winlogon/automatic-logon credentials in the registry  |
| 68 | CredentialExposure | Sensitive | Partial | Unattended-installation and Sysprep answer files containing credentials Known answer-file locations and redacted text markers only. |
| 69 | CredentialExposure | Sensitive | Partial | Cached Group Policy Preferences passwords / cpassword material Bounded local GPP XML inspection; no decryption. |
| 70 | CredentialExposure | Domain | Partial | Domain/SYSVOL Group Policy Preferences password searches Opt-in bounded SYSVOL XML inspection; no decryption. |
| 71 | CredentialExposure | Sensitive | Partial | Readable SAM, SYSTEM and SECURITY hive files, including backups or shadow-copy exposure where implemented Live/RegBack/Windows.old hive paths only; no shadow copies or hive contents. |
| 72 | CredentialExposure | Sensitive | Partial | Windows Credential Manager entries and accessible saved credentials cmdkey saved-credential metadata; blobs/passwords not retrieved. |
| 73 | CredentialExposure | Sensitive | Partial | Windows Vault web/Windows credentials Vault containers only; entries/passwords not retrieved. |
| 74 | CredentialExposure | Sensitive | Partial | UWP PasswordVault / Credential Locker entries Vault directories only; no UWP PasswordVault API enumeration. |
| 75 | CredentialExposure | Sensitive | Partial | DPAPI master-key files and credential blobs Current-user DPAPI and credential directories only; no decryption. |
| 76 | CredentialExposure | Sensitive | Unsupported | Credentials exposed through Windows security packages Security-package credential retrieval is not implemented. |
| 77 | CredentialExposure | Sensitive | Partial | Kerberos ticket-cache and TGT information Current-logon klist metadata; no TGT/session-key export. |
| 78 | CredentialExposure | Sensitive | Partial | PowerShell history and transcript files containing secrets Known PSReadLine paths and bounded Documents transcript search. |
| 79 | CredentialExposure | Sensitive | Partial | Secrets in event logs: PowerShell script blocks, process-creation command lines and Sysmon events Newest bounded script/process events; only marker presence retained. |
| 80 | CredentialExposure | Sensitive | Partial | Registry values containing possible passwords or credential material, including application-specific locations and broader searches Sensitive value-name heuristic in immediate Software children only. |
| 81 | CredentialExposure | Sensitive | Partial | IIS/web application configuration credentials: web.config, connection strings and application-pool credentials, including decryption where supported. U; W searches relevant files and uses AppCmd Known IIS configuration files and markers; no AppCmd/app-pool enumeration/decryption. |
| 82 | CredentialExposure | Sensitive | Partial | McAfee SiteList.xml credentials and related configuration Known McAfee SiteList paths/markers; no decryption. |
| 83 | CredentialExposure | Sensitive | Partial | SCCM Network Access Account credential blobs Readable SCCM NAA object presence; blobs not retained/decrypted. |
| 84 | CredentialExposure | Sensitive | Partial | SCCM cache contents and files containing possible embedded credentials. P; W also enumerates SCCM-related information Bounded CCM cache text/configuration inspection. |
| 85 | CredentialExposure | Sensitive | Partial | Symantec Management Agent Account Connectivity Credentials Altiris installation directories only; credential storage not parsed. |
| 86 | CredentialExposure | Sensitive | Partial | SCOM Run As account traces indicating stored credentials SCOM/Monitoring Agent installation directories only; Run As traces not parsed. |
| 87 | CredentialExposure | Sensitive | Partial | VNC server passwords/configuration: RealVNC, TigerVNC, TightVNC and UltraVNC where supported. P; W searches VNC artifacts Common VNC password value presence/config markers; no decryption. |
| 88 | CredentialExposure | Sensitive | Partial | Saved RDP connections and RDCMan settings/credential files Known current-user RDP/RDCMan artifacts; no decryption. |
| 89 | CredentialExposure | Sensitive | Partial | PuTTY, SuperPuTTY and MTPuTTY session/configuration artifacts, including referenced keys and saved connection information Common PuTTY family artifacts; nonstandard paths may be missed. |
| 90 | CredentialExposure | Sensitive | Partial | FileZilla and other FTP/SFTP-client configuration files Known FileZilla/WinSCP paths and markers only. |
| 91 | CredentialExposure | Sensitive | Partial | KeePass databases, configuration and key-file clues Known KeePass config and bounded database/key-file discovery. |
| 92 | CredentialExposure | Sensitive | Partial | Oracle SQL Developer connection/configuration files SQL Developer configuration directories only; connections not decoded. |
| 93 | CredentialExposure | Sensitive | Partial | Cloud credential files and token caches: AWS, Azure, Google Cloud and Bluemix-related artifacts Known current-user cloud files and text markers; binary caches not parsed. |
| 94 | CredentialExposure | Sensitive | Partial | Certificates, private-key files and certificate-store metadata Personal certificate metadata and bounded key-file discovery; no key export. |
| 95 | CredentialExposure | Sensitive | Partial | Saved Wi-Fi profiles and recoverable pre-shared keys Readable Wi-Fi profile XML metadata; PSKs never recovered. |
| 96 | CredentialExposure | Sensitive | Partial | Potentially insecure enterprise/802.1X Wi-Fi profiles Available EAP XML validation flags; full policy interpretation not implemented. |
| 97 | CredentialExposure | Sensitive | Partial | Clipboard contents potentially containing secrets Text clipboard marker presence only; contents omitted. |
| 98 | CredentialExposure | Sensitive | Partial | Browser credential databases and recoverable stored logins. W; S identifies relevant browser artifacts Known default-browser stores; no login recovery or all-profile discovery. |
| 99 | CredentialExposure | Sensitive | Partial | Generic sensitive-file and secret searches: configuration files, backups, scripts, logs, SSH/VPN keys, Git credentials, databases, container/Kubernetes configuration, CI/CD artifacts and other configured filename/regex matches Bounded filename/content heuristics; no exhaustive disk scan. |
| 100 | Hardening | Local | Implemented | UAC configuration: elevation policy, administrative token filtering and remote restrictions  |
| 101 | Hardening | Local | Implemented | LSA protection / RunAsPPL configuration  |
| 102 | Hardening | Local | Partial | Credential Guard configuration/state Configured/WMI virtualization state; firmware/UEFI lock not verified. |
| 103 | Hardening | Local | Implemented | WDigest settings and cached-domain-logon configuration. W; S exposes related LSA settings — Audit  |
| 104 | Hardening | Local | Partial | Credential-delegation configuration Top-level delegation flags; allowlists/resultant policy not expanded. |
| 105 | Hardening | Local | Implemented | NTLM settings and NTLMv1/downgrade exposure  |
| 106 | Hardening | Local | Partial | SMBv1 and client/server SMB-signing requirements Registry/effective SMB configuration; platform support varies. |
| 107 | Hardening | Local | Implemented | Hardened UNC path policies  |
| 108 | Hardening | Local | Partial | Broadcast/multicast name-resolution protocols and IPv6 configuration LLMNR/mDNS/IPv6 registry evidence; per-interface NetBIOS omitted. |
| 109 | Hardening | Local | Partial | Proxy, WPAD/PAC and Internet-zone configuration Current-user proxy/PAC evidence; zones/effective WPAD not evaluated. |
| 110 | Hardening | Local | Implemented | LAPS installation and policy configuration, including legacy/Windows LAPS where supported  |
| 111 | Hardening | Local | Implemented | Default local Administrator account enabled/disabled state  |
| 112 | Hardening | Local | Partial | AppLocker policy/enforcement and potentially permissive rules Collection/rule metadata and path candidates; exclusions/effective rule simulation not implemented. |
| 113 | Hardening | Local | Partial | PowerShell versions and security settings, including logging-related policy Runtime/Windows PowerShell versions and logging policy; not all PowerShell Core configs. |
| 114 | Hardening | Local | Partial | PowerShell remoting/session endpoint configuration and permissions Local endpoint configuration; remote connectivity not tested. |
| 115 | Hardening | Local | Partial | Antivirus/EDR products, defensive processes and AMSI providers Registered AV/AMSI and service-name heuristics; not a full EDR inventory. |
| 116 | Hardening | Local | Partial | Defender settings and exclusions; ASR rules; Defender for Endpoint state Defender status/preferences/ASR and MDE onboarding marker; access may be restricted. |
| 117 | Hardening | Local | Partial | Audit policy, Sysmon and Windows Event Forwarding settings Audit policy, Sysmon/WEC service state and subscription subkeys; not full WEF config. |
| 118 | Hardening | Local | Partial | UEFI/Secure Boot, TPM, BitLocker and DMA-protection state. P covers UEFI/Secure Boot, TPM and BitLocker; S covers Secure Boot; W includes DMA protection — Audit/context Secure Boot, TPM and BitLocker; DMA protection omitted. |
| 119 | Hardening | Local | Partial | Office macro policy, Protected View and writable trusted locations Selected Office 16.x policy/trusted-location keys only. |
| 120 | Hardening | Local | Partial | ClickOnce trust prompts, risky file-extension associations and hidden extensions ClickOnce, HideFileExt and selected associations; no full association-risk analysis. |
| 121 | Hardening | Local | Implemented | Lock-screen network-selection policy associated with Airstrike exposure  |
| 122 | Hardening | Local | Implemented | RDP client/server security settings  |
| 123 | Hardening | Local | Partial | Windows Firewall profiles, state and rules Profiles and bounded rules; filters not expanded. |
| 124 | Inventory | Local | Partial | OS, architecture, machine role, domain/tenant join and runtime information OS/machine/domain/runtime; cloud tenant join not collected. |
| 125 | Inventory | Local | Partial | Installed applications, Windows roles/features and running processes/owners/command lines Applications/process metadata/features; command lines and owners omitted. |
| 126 | Inventory | Local | Unsupported | Active-window information and user idle time. W; S reports idle time — Context Active-window and idle-time collection is not implemented. |
| 127 | Inventory | Local | Partial | Startup, shutdown, reboot and sleep history Bounded event metadata only; no complete activity timeline. |
| 128 | Inventory | Local | Partial | Logon and explicit-credential-use events Bounded logon event metadata only; payloads omitted. |
| 129 | Inventory | Local | Partial | Disks, mounted volumes, mapped drives and network shares Logical disks/mapped drives/shares; not all mountpoints or share ACLs. |
| 130 | Inventory | Local | Partial | Network interfaces, profiles, ARP, routes, hosts file and DNS cache Interfaces/routes/neighbors and hosts-file metadata; DNS cache/profiles omitted. |
| 131 | Inventory | Local | Partial | TCP/UDP listeners and connections, with owning processes/services where available TCP/UDP with PID; service correlation not expanded. |
| 132 | Inventory | Network | Partial | Internet connectivity, external hostname resolution and optional network/port discovery Opt-in www.microsoft.com DNS lookup only; no port scan/connectivity guarantee. |
| 133 | Inventory | Local | Unsupported | RPC endpoint mappings RPC endpoint mapper enumeration is not implemented. |
| 134 | Inventory | Local | Partial | WMI permanent event consumers, filters and bindings WMI subscription class/path metadata; scripts/queries omitted. |
| 135 | Inventory | Local | Partial | Printers and printing-related inventory CIM printer inventory only. |
| 136 | Inventory | Sensitive | Partial | Browser history, bookmarks, typed URLs, open tabs and profile artifacts Browser history/bookmark artifacts; browsing data/open tabs not extracted. |
| 137 | Inventory | Sensitive | Partial | Recent files, Explorer Run history, Office MRUs and Recycle Bin contents Recent-files/Recycle Bin directory presence; MRU values/contents not decoded. |
| 138 | Inventory | Sensitive | Partial | Outlook downloads, OneNote backups, Slack artifacts and OneDrive/Office 365 synchronization locations Known collaboration/sync directories; contents not collected. |
| 139 | Inventory | Local | Partial | Windows Search Index queries, generic directory listing, registry querying and file metadata inspection Bounded generic filesystem metadata; no Windows Search Index query. |
| 140 | Inventory | Local | Partial | LOLBAS discovery and WSL/Linux-shell artifacts Small executable list and WSL artifacts; no full LOLBAS dataset. |
| 141 | DomainCloud | Domain | Partial | Applied domain GPOs writable by the current principal, plus local GPO configuration. W; S inventories local GPOs Sampled domain GPOs/allow ACEs; applied GPO correlation/local GPO parsing not implemented. |
| 142 | DomainCloud | Domain | Partial | Current computer’s LAPS password readable from Active Directory Own computer LAPS readability; encrypted attributes not decrypted. |
| 143 | DomainCloud | Domain | Partial | Readable gMSA managed-password material / relevant access relationships gMSA retrieval relationships; managed passwords not requested. |
| 144 | DomainCloud | Domain | Partial | AD object control rights, including useful write, ownership and DACL permissions on sampled objects Sampled allow ACEs matching token SIDs; deny/inheritance/object rights require review. |
| 145 | DomainCloud | Domain | Partial | Kerberoastable service accounts and associated encryption/account-risk indicators SPN/encryption/account metadata; no ticket requests or cracking. |
| 146 | DomainCloud | Domain | Partial | AD CS certificate-template/configuration misconfiguration indicators Template flags/EKUs/control ACEs; CA publication/enrollment/effective rights not fully evaluated. |
| 147 | DomainCloud | Local | Partial | KrbRelayUp-related configuration indicators Local NTDS policy markers; absence on a member says nothing about DC policy. |
| 148 | DomainCloud | Local | Partial | Cloud metadata, identity/token exposure and Google synchronization/join artifacts, plus detection of container context Local cloud/container markers only; metadata/token endpoints not contacted. |
