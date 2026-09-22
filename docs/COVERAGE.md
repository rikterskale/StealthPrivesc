# Checklist coverage

IDs preserve the supplied checklist. Implemented means the stated assessment is available; it does not mean every host is vulnerable, safe, accessible, or supported. Read the scope notes below and runtime Limitations. Bounds and missing permissions produce Partial results, never clean findings.

| ID | Category | Scope | Coverage | Check and scope notes |
|---:|---|---|---|---|
| 1 | Identity | Local | Implemented | Current identity and token context: username, SID, domain, integrity/elevation, token type and related identity information Bounded current-token evidence assessment; access failures and limits are reported at runtime. |
| 2 | Identity | Local | Implemented | Current token group memberships: local/domain groups, administrative membership, and relevant group attributes Bounded current-token evidence assessment; access failures and limits are reported at runtime. |
| 3 | Identity | Local | Implemented | Restricted token SIDs Bounded current-token evidence assessment; access failures and limits are reported at runtime. |
| 4 | Identity | Local | Implemented | Potentially dangerous token privileges: impersonation, debugging, backup/restore, ownership, driver loading, TCB and other privilege assignments; exact flagged sets differ Bounded current-token evidence assessment; access failures and limits are reported at runtime. |
| 5 | Identity | Local | Implemented | Privileges assigned through local/domain policy, including rights potentially available after a new logon Effective local LSA rights include applied policy; unapplied future domain policy is not predicted. |
| 6 | Identity | Local | Implemented | Local users and groups: administrators, account state, password timestamps and membership information Bounded current-token evidence assessment; access failures and limits are reported at runtime. |
| 7 | Identity | Local | Implemented | Password and account-lockout policies Bounded current-token evidence assessment; access failures and limits are reported at runtime. |
| 8 | Identity | Local | Implemented | Logged-on users and sessions: interactive/logon sessions, incoming RDP sessions and previously logged-on users, depending on tool Current sessions, associations and historical profile last-use metadata. |
| 9 | Identity | Local | Implemented | Other users’ profile/home directories and their accessibility, including readable or writable locations Profile listing and directory DACL access; child contents may have different permissions. |
| 10 | Identity | Local | Implemented | Environment variables containing credentials, tokens or sensitive configuration Bounded current-token evidence assessment; access failures and limits are reported at runtime. |
| 11 | Services | Local | Implemented | Installed services: executable paths, accounts, start modes and third-party service identification Bounded current-token evidence assessment; access failures and limits are reported at runtime. |
| 12 | Services | Local | Implemented | Modifiable service objects: service configuration, ownership or DACL rights that permit controlling a service Bounded current-token evidence assessment; access failures and limits are reported at runtime. |
| 13 | Services | Local | Implemented | Modifiable Service Control Manager permissions Bounded current-token evidence assessment; access failures and limits are reported at runtime. |
| 14 | Services | Local | Implemented | Writable service registry keys and settings Bounded current-token evidence assessment; access failures and limits are reported at runtime. |
| 15 | Services | Local | Implemented | Writable extended service registry settings/subkeys Recursive service registry subkeys, subject to traversal limits. |
| 16 | Services | Local | Implemented | Writable service executables, associated files or containing directories Executable and statically referenced scripts/configuration; dynamic dependencies require review. |
| 17 | Services | Local | Implemented | Unquoted service executable paths containing spaces, including writable interception locations where implemented Bounded current-token evidence assessment; access failures and limits are reported at runtime. |
| 18 | Services | Local | Implemented | Writable DLLs explicitly loaded by LocalSystem services Registered ServiceDll and currently loaded SYSTEM service modules. |
| 19 | Services | Local | Implemented | Writable LocalSystem service recovery-command targets Recovery actions, delays, non-crash flags and command targets; actions never triggered. |
| 20 | Services | Local | Implemented | Service start/stop/restart permissions: supporting feasibility checks; PrivescCheck also has a dedicated experimental restart check Bounded current-token evidence assessment; access failures and limits are reported at runtime. |
| 21 | Services | Local | Implemented | Services using accounts whose passwords are stored locally as service secrets Named service-account storage indicator; protected LSA storage may be inaccessible. |
| 22 | TasksStartup | Local | Implemented | Scheduled-task inventory: actions, paths, execution accounts and other task details Principals, execute/COM actions, triggers and settings; argument values redacted. |
| 23 | TasksStartup | Local | Implemented | Writable scheduled-task executables, scripts or containing directories Executable/script references resolved against task working directories. |
| 24 | TasksStartup | Local | Implemented | Low-privilege control over enabled SYSTEM scheduled tasks Registered task descriptors from Task Scheduler for enabled SYSTEM tasks. |
| 25 | TasksStartup | Local | Implemented | Unquoted scheduled-task action paths Ambiguous path candidates; Task Scheduler may treat the whole Execute field as one path. |
| 26 | TasksStartup | Local | Implemented | Scheduled tasks configured with password-based logon, indicating locally stored account secrets Password logon is a stored-credential indicator; no task credentials exported. |
| 27 | TasksStartup | Local | Implemented | Microsoft Recall PolicyConfiguration task exposure, combining task configuration markers with OS/build information Recall task configuration plus CVE-2025-60710 fixed-build assessment. |
| 28 | TasksStartup | Local | Implemented | Startup/autorun entries and writable referenced programs or directories Run/RunOnce, startup files and resolved shortcut targets. |
| 29 | AccessControl | Local | Implemented | Writable directories in executable/DLL search paths, particularly system PATH Bounded current-token evidence assessment; access failures and limits are reported at runtime. |
| 30 | AccessControl | Local | Implemented | Process DLL-hijacking candidates, including relevant writable process locations Process owner, loaded module ACLs and default search locations; custom loader behavior requires review. |
| 31 | AccessControl | Local | Implemented | Known services susceptible to missing/“ghost” DLL hijacking, correlated with writable search paths Known OS-family/service/DLL rules correlated with missing files and writable search directories; historical rules are candidates. |
| 32 | AccessControl | Local | Implemented | Writable installed-application files and directories, including third-party applications Bounded current-token evidence assessment; access failures and limits are reported at runtime. |
| 33 | AccessControl | Local | Implemented | Writable application directories under ProgramData Bounded current-token evidence assessment; access failures and limits are reported at runtime. |
| 34 | AccessControl | Local | Implemented | Writable directories at fixed-drive roots and their contents Fixed-drive roots and immediate contents. |
| 35 | AccessControl | Local | Implemented | Writable executable files in nonstandard locations Bounded current-token evidence assessment; access failures and limits are reported at runtime. |
| 36 | AccessControl | Local | Implemented | Writable COM server registration keys Bounded current-token evidence assessment; access failures and limits are reported at runtime. |
| 37 | AccessControl | Local | Implemented | Writable COM server DLL/EXE files Bounded current-token evidence assessment; access failures and limits are reported at runtime. |
| 38 | AccessControl | Local | Implemented | COM registrations referencing missing modules through relative paths, creating potential ghost-DLL search opportunities Relative COM modules correlated with default system/PATH search locations. |
| 39 | AccessControl | Local | Implemented | Stale COM registrations referencing nonexistent files Missing and inaccessible targets are distinguished. |
| 40 | AccessControl | Local | Implemented | Writable machine registry keys: known exposed HKLM descendants and a bounded heuristic search Known HKLM roots and bounded child-key DACL checks. |
| 41 | AccessControl | Local | Implemented | Cross-user TypingInsights registry-key permissions Other loaded profiles' Software\Microsoft\Input\TypingInsights keys. |
| 42 | AccessControl | Local | Implemented | Excessive permissions on another user’s processes or threads Process and thread control-right probes; no object mutation. |
| 43 | AccessControl | Local | Implemented | Accessible leaked handles to privileged processes, threads or files Bounded system handles, metadata-only duplication, owner and excess access correlation. |
| 44 | AccessControl | Local | Implemented | Named-pipe ACLs and writable pipes, including correlation with privileged pipe servers where implemented Metadata-only identification-level pipe connections, ACLs and server-owner correlation. |
| 45 | AccessControl | Local | Implemented | Writable named kernel-device objects Native device namespace and descriptor queries in timed helpers. |
| 46 | AccessControl | Local | Implemented | Potentially unsafe .NET SOAP client proxy configurations—SOAPwn-related surfaces SOAP proxy/WSDL, URI and default-credential indicators; input reachability requires application review. |
| 47 | SystemRisk | Local | Implemented | AlwaysInstallElevated Windows Installer policy, including machine and user settings Bounded current-token evidence assessment; access failures and limits are reported at runtime. |
| 48 | SystemRisk | Local | Implemented | Windows Installer repair UAC-prompt suppression Explicit prompt-suppression policy; effective defaults depend on servicing. |
| 49 | SystemRisk | Local | Implemented | MSI repair allowlists and potentially unsafe custom actions in allowlisted packages Repair allowlist, privileged custom actions, sequence, repair conditions and static targets. |
| 50 | SystemRisk | Local | Implemented | Potentially unsafe custom actions in cached MSI packages Read-only MSI action/sequence/target assessment; no installation or repair. |
| 51 | SystemRisk | Local | Implemented | Print Spooler and Point-and-Print configuration permitting unsafe printer-driver installation Spooler, explicit Point-and-Print restrictions and prompt suppression; absent settings use servicing defaults. |
| 52 | SystemRisk | Local | Implemented | Driver co-installer policy Bounded current-token evidence assessment; access failures and limits are reported at runtime. |
| 53 | SystemRisk | Local | Implemented | WSUS configuration: update-server location, HTTP versus HTTPS and related policy Bounded current-token evidence assessment; access failures and limits are reported at runtime. |
| 54 | SystemRisk | Local | Implemented | Missing Windows patches / OS-version vulnerability matching Dated MSRC fixed-build snapshot, exact product/architecture/branch matching; unmatched products are unknown. |
| 55 | SystemRisk | Local | Implemented | Watson’s explicit CVE checks: CVE-2019-0836, -0841, -1064, -1130, -1253, -1315, -1385, -1388, -1405; CVE-2020-0668, -0683, -1013 Published fixed-build records for all twelve requested CVEs; unsupported product combinations are unknown. |
| 56 | SystemRisk | Local | Implemented | Installed hotfixes, Microsoft updates and update history/recency Hotfix, Windows Update history and CBS packages where accessible. |
| 57 | SystemRisk | Local | Implemented | BIOS update/release age Bounded current-token evidence assessment; access failures and limits are reported at runtime. |
| 58 | SystemRisk | Local | Implemented | Installed third-party kernel/device drivers PnP and system/legacy driver inventory. |
| 59 | SystemRisk | Local | Implemented | Known vulnerable drivers matched against the LOLDrivers database Exact SHA256 matches against dated LOLDrivers data. |
| 60 | SystemRisk | Local | Implemented | Known vulnerable drivers not covered by local Code Integrity blocking policies Decoded kernel-mode deny rules, hashes/version/TBS signer candidates and runtime enforcement. Conditional rules remain explicit; no deny match does not mean load permission. |
| 61 | SystemRisk | Local | Implemented | Unsigned or legacy/weakly signed kernel drivers Authenticode/catalog trust, signer algorithm/key strength and timestamp presence; distinct from kernel load policy. |
| 62 | SystemRisk | Local | Implemented | Risky OEM privileged utilities/components OEM utility/service/ACL correlation and exact known-vulnerable driver matching. |
| 63 | SystemRisk | Local | Implemented | Installed-package vulnerability lookup Opt-in NVD package/version keyword lookup; ten queries per run. Candidates require CPE applicability review. |
| 64 | SystemRisk | Local | Implemented | CLFS logfile-authentication mitigation configuration CLFS mode, learning start and transition policy; absent configuration is unknown or unsupported. |
| 65 | SystemRisk | Local | Implemented | Object Manager namespace access relevant to race-window amplification Object Manager directory create/control capabilities; no objects or races created. |
| 66 | SystemRisk | Local | Implemented | KernelQuick/ValleyRAT-related registry indicators Published KernelQuick service and registry indicators. |
| 67 | CredentialExposure | Sensitive | Implemented | Winlogon/automatic-logon credentials in the registry Bounded current-token evidence assessment; access failures and limits are reported at runtime. |
| 68 | CredentialExposure | Sensitive | Implemented | Unattended-installation and Sysprep answer files containing credentials Known answer-file readability and redacted secret markers. |
| 69 | CredentialExposure | Sensitive | Implemented | Cached Group Policy Preferences passwords / cpassword material Cached GPP credential/cpassword markers; no values exported. |
| 70 | CredentialExposure | Domain | Implemented | Domain/SYSVOL Group Policy Preferences password searches Opt-in SYSVOL GPP XML credential markers. |
| 71 | CredentialExposure | Sensitive | Implemented | Readable SAM, SYSTEM and SECURITY hive files, including backups or shadow-copy exposure where implemented Live, backup, Windows.old and shadow-copy hive readability; no contents copied. |
| 72 | CredentialExposure | Sensitive | Implemented | Windows Credential Manager entries and accessible saved credentials Credential Manager retrieval with native secret-buffer erasure. |
| 73 | CredentialExposure | Sensitive | Implemented | Windows Vault web/Windows credentials Windows 8+ Vault retrieval with authenticator erasure. |
| 74 | CredentialExposure | Sensitive | Implemented | UWP PasswordVault / Credential Locker entries WinRT Credential Locker retrieval inside a timed Windows PowerShell helper. |
| 75 | CredentialExposure | Sensitive | Implemented | DPAPI master-key files and credential blobs Accessible profiles' DPAPI/master-key/credential files; readability is distinct from decryptability. |
| 76 | CredentialExposure | Sensitive | Implemented | Credentials exposed through Windows security packages Local NTLM SSPI probe with original challenge and flags; no network exchange or token export. |
| 77 | CredentialExposure | Sensitive | Implemented | Kerberos ticket-cache and TGT information Current-logon Kerberos ticket/TGT metadata; no session-key export. |
| 78 | CredentialExposure | Sensitive | Implemented | PowerShell history and transcript files containing secrets Bounded current-token evidence assessment; access failures and limits are reported at runtime. |
| 79 | CredentialExposure | Sensitive | Implemented | Secrets in event logs: PowerShell script blocks, process-creation command lines and Sysmon events Bounded event secret markers; event payloads discarded. |
| 80 | CredentialExposure | Sensitive | Implemented | Registry values containing possible passwords or credential material, including application-specific locations and broader searches Recursive bounded registry name/content secret indicators. |
| 81 | CredentialExposure | Sensitive | Implemented | IIS/web application configuration credentials: web.config, connection strings and application-pool credentials, including decryption where supported. U; W searches relevant files and uses AppCmd IIS administration API credential accessibility, including protected fields resolved by the current identity. |
| 82 | CredentialExposure | Sensitive | Implemented | McAfee SiteList.xml credentials and related configuration McAfee SiteList credential fields/configuration; values redacted. |
| 83 | CredentialExposure | Sensitive | Implemented | SCCM Network Access Account credential blobs Readable SCCM NAA policy and encrypted-credential indicators. |
| 84 | CredentialExposure | Sensitive | Implemented | SCCM cache contents and files containing possible embedded credentials. P; W also enumerates SCCM-related information Bounded current-token evidence assessment; access failures and limits are reported at runtime. |
| 85 | CredentialExposure | Sensitive | Implemented | Symantec Management Agent Account Connectivity Credentials Symantec PkgAccessCredentials, secure-storage references and agent/server configuration. |
| 86 | CredentialExposure | Sensitive | Implemented | SCOM Run As account traces indicating stored credentials SCOM Run As events 7002/7026; payload redacted. |
| 87 | CredentialExposure | Sensitive | Implemented | VNC server passwords/configuration: RealVNC, TigerVNC, TightVNC and UltraVNC where supported. P; W searches VNC artifacts Bounded current-token evidence assessment; access failures and limits are reported at runtime. |
| 88 | CredentialExposure | Sensitive | Implemented | Saved RDP connections and RDCMan settings/credential files Accessible profiles' RDP/RDCMan files and credential fields. |
| 89 | CredentialExposure | Sensitive | Implemented | PuTTY, SuperPuTTY and MTPuTTY session/configuration artifacts, including referenced keys and saved connection information PuTTY-family sessions/configuration and referenced key readability. |
| 90 | CredentialExposure | Sensitive | Implemented | FileZilla and other FTP/SFTP-client configuration files FileZilla/WinSCP configuration and registry credential fields. |
| 91 | CredentialExposure | Sensitive | Implemented | KeePass databases, configuration and key-file clues KeePass configuration, database and key-file discovery. |
| 92 | CredentialExposure | Sensitive | Implemented | Oracle SQL Developer connection/configuration files SQL Developer connection/configuration credential markers. |
| 93 | CredentialExposure | Sensitive | Implemented | Cloud credential files and token caches: AWS, Azure, Google Cloud and Bluemix-related artifacts Cloud credential/token files; opaque caches identified as artifacts. |
| 94 | CredentialExposure | Sensitive | Implemented | Certificates, private-key files and certificate-store metadata Certificate metadata and key-file discovery; no private-key export. |
| 95 | CredentialExposure | Sensitive | Implemented | Saved Wi-Fi profiles and recoverable pre-shared keys WLAN profile/PSK retrieval permitted to current token; values erased before reporting. |
| 96 | CredentialExposure | Sensitive | Implemented | Potentially insecure enterprise/802.1X Wi-Fi profiles Enterprise EAP server-validation settings and explicit weak-validation indicators. |
| 97 | CredentialExposure | Sensitive | Implemented | Clipboard contents potentially containing secrets Bounded current-token evidence assessment; access failures and limits are reported at runtime. |
| 98 | CredentialExposure | Sensitive | Implemented | Browser credential databases and recoverable stored logins. W; S identifies relevant browser artifacts Chromium DPAPI/AES-GCM and verified installed Firefox NSS recovery probes. App-bound and primary-password protections are not bypassed. |
| 99 | CredentialExposure | Sensitive | Implemented | Generic sensitive-file and secret searches: configuration files, backups, scripts, logs, SSH/VPN keys, Git credentials, databases, container/Kubernetes configuration, CI/CD artifacts and other configured filename/regex matches Bounded current-token evidence assessment; access failures and limits are reported at runtime. |
| 100 | Hardening | Local | Implemented | UAC configuration: elevation policy, administrative token filtering and remote restrictions Bounded current-token evidence assessment; access failures and limits are reported at runtime. |
| 101 | Hardening | Local | Implemented | LSA protection / RunAsPPL configuration Bounded current-token evidence assessment; access failures and limits are reported at runtime. |
| 102 | Hardening | Local | Implemented | Credential Guard configuration/state DeviceGuard policy and runtime state; firmware lock not independently verified. |
| 103 | Hardening | Local | Implemented | WDigest settings and cached-domain-logon configuration. W; S exposes related LSA settings — Audit Bounded current-token evidence assessment; access failures and limits are reported at runtime. |
| 104 | Hardening | Local | Implemented | Credential-delegation configuration Delegation flags and allow/deny target lists. |
| 105 | Hardening | Local | Implemented | NTLM settings and NTLMv1/downgrade exposure Bounded current-token evidence assessment; access failures and limits are reported at runtime. |
| 106 | Hardening | Local | Implemented | SMBv1 and client/server SMB-signing requirements Bounded current-token evidence assessment; access failures and limits are reported at runtime. |
| 107 | Hardening | Local | Implemented | Hardened UNC path policies Bounded current-token evidence assessment; access failures and limits are reported at runtime. |
| 108 | Hardening | Local | Implemented | Broadcast/multicast name-resolution protocols and IPv6 configuration Name-resolution policy, per-interface NetBIOS and IPv6 bindings. |
| 109 | Hardening | Local | Implemented | Proxy, WPAD/PAC and Internet-zone configuration Proxy, WPAD flags, WinHTTP and Internet-zone settings. |
| 110 | Hardening | Local | Implemented | LAPS installation and policy configuration, including legacy/Windows LAPS where supported Bounded current-token evidence assessment; access failures and limits are reported at runtime. |
| 111 | Hardening | Local | Implemented | Default local Administrator account enabled/disabled state Bounded current-token evidence assessment; access failures and limits are reported at runtime. |
| 112 | Hardening | Local | Implemented | AppLocker policy/enforcement and potentially permissive rules Effective AppLocker rules and writable path conditions; complete exclusions/rule matching require context. |
| 113 | Hardening | Local | Implemented | PowerShell versions and security settings, including logging-related policy Bounded current-token evidence assessment; access failures and limits are reported at runtime. |
| 114 | Hardening | Local | Implemented | PowerShell remoting/session endpoint configuration and permissions Remoting endpoint configuration and available descriptors. |
| 115 | Hardening | Local | Implemented | Antivirus/EDR products, defensive processes and AMSI providers SecurityCenter2, AMSI and service inventory; product-name classification is heuristic. |
| 116 | Hardening | Local | Implemented | Defender settings and exclusions; ASR rules; Defender for Endpoint state Bounded current-token evidence assessment; access failures and limits are reported at runtime. |
| 117 | Hardening | Local | Implemented | Audit policy, Sysmon and Windows Event Forwarding settings Audit policy, Sysmon settings and event-forwarding subscriptions. |
| 118 | Hardening | Local | Implemented | UEFI/Secure Boot, TPM, BitLocker and DMA-protection state. P covers UEFI/Secure Boot, TPM and BitLocker; S covers Secure Boot; W includes DMA protection — Audit/context Secure Boot, TPM and BitLocker APIs, subject to role and permissions. |
| 119 | Hardening | Local | Implemented | Office macro policy, Protected View and writable trusted locations Office 16 macros, Protected View and trusted-location ACLs. |
| 120 | Hardening | Local | Implemented | ClickOnce trust prompts, risky file-extension associations and hidden extensions Bounded current-token evidence assessment; access failures and limits are reported at runtime. |
| 121 | Hardening | Local | Implemented | Lock-screen network-selection policy associated with Airstrike exposure Bounded current-token evidence assessment; access failures and limits are reported at runtime. |
| 122 | Hardening | Local | Implemented | RDP client/server security settings Bounded current-token evidence assessment; access failures and limits are reported at runtime. |
| 123 | Hardening | Local | Implemented | Windows Firewall profiles, state and rules Active firewall rules with address, port, program and service filters. |
| 124 | Inventory | Local | Implemented | OS, architecture, machine role, domain/tenant join and runtime information Bounded current-token evidence assessment; access failures and limits are reported at runtime. |
| 125 | Inventory | Local | Implemented | Installed applications, Windows roles/features and running processes/owners/command lines Packages/features and process owners with redacted invocation structure. |
| 126 | Inventory | Local | Implemented | Active-window information and user idle time. W; S reports idle time — Context Foreground window process/class and idle time; title text never retrieved. |
| 127 | Inventory | Local | Implemented | Startup, shutdown, reboot and sleep history Bounded lifecycle event metadata. |
| 128 | Inventory | Local | Implemented | Logon and explicit-credential-use events Bounded logon/explicit-credential event fields; payloads redacted. |
| 129 | Inventory | Local | Implemented | Disks, mounted volumes, mapped drives and network shares Disks, shares, volumes, partitions, mapped drives and mount paths. |
| 130 | Inventory | Local | Implemented | Network interfaces, profiles, ARP, routes, hosts file and DNS cache Interfaces, routes, neighbors, profiles, DNS cache and hosts mappings. |
| 131 | Inventory | Local | Implemented | TCP/UDP listeners and connections, with owning processes/services where available TCP/UDP endpoints with service PID correlation. |
| 132 | Inventory | Network | Implemented | Internet connectivity, external hostname resolution and optional network/port discovery External DNS resolution requires -IncludeNetwork; it does not prove unrestricted connectivity. |
| 133 | Inventory | Local | Implemented | RPC endpoint mappings Local RPC endpoint-mapper inventory. |
| 134 | Inventory | Local | Implemented | WMI permanent event consumers, filters and bindings WMI filters, consumers and bindings with redacted action details. |
| 135 | Inventory | Local | Implemented | Printers and printing-related inventory Bounded current-token evidence assessment; access failures and limits are reported at runtime. |
| 136 | Inventory | Sensitive | Implemented | Browser history, bookmarks, typed URLs, open tabs and profile artifacts History/bookmarks/typed URLs and persisted tab/session parsing. Unknown/encrypted formats are incomplete; live state may differ. |
| 137 | Inventory | Sensitive | Implemented | Recent files, Explorer Run history, Office MRUs and Recycle Bin contents Recent shortcuts, Run/Office MRUs and Recycle Bin metadata. |
| 138 | Inventory | Sensitive | Implemented | Outlook downloads, OneNote backups, Slack artifacts and OneDrive/Office 365 synchronization locations Collaboration/download/backup artifacts and OneDrive sync locations. |
| 139 | Inventory | Local | Implemented | Windows Search Index queries, generic directory listing, registry querying and file metadata inspection Read-only SYSTEMINDEX queries and filesystem metadata. |
| 140 | Inventory | Local | Implemented | LOLBAS discovery and WSL/Linux-shell artifacts Full bundled LOLBAS name/path catalog plus WSL/Linux-shell artifacts. |
| 141 | DomainCloud | Domain | Implemented | Applied domain GPOs writable by the current principal, plus local GPO configuration. W; S inventories local GPOs Computer RSoP GPOs, AD/SYSVOL rights and local Registry.pol metadata. |
| 142 | DomainCloud | Domain | Implemented | Current computer’s LAPS password readable from Active Directory Own-computer LAPS attribute readability; encrypted values stay protected. |
| 143 | DomainCloud | Domain | Implemented | Readable gMSA managed-password material / relevant access relationships gMSA retrieval relationships; password-readability probing additionally requires -IncludeSensitive. |
| 144 | DomainCloud | Domain | Implemented | AD object control rights, including useful write, ownership and DACL permissions on sampled objects Windows object-specific AccessCheckByType on sampled AD descriptors, including denies. |
| 145 | DomainCloud | Domain | Implemented | Kerberoastable service accounts and associated encryption/account-risk indicators SPN/encryption/account/password metadata; no service-ticket requests. |
| 146 | DomainCloud | Domain | Implemented | AD CS certificate-template/configuration misconfiguration indicators CA publication, template enrollment, issuance controls and EKUs; ESC1/2/3 prerequisites, with CA-policy caveats. |
| 147 | DomainCloud | Local | Implemented | KrbRelayUp-related configuration indicators Local indicators, domain machine quota and timed read-only DC LDAP policy queries. |
| 148 | DomainCloud | Local | Implemented | Cloud metadata, identity/token exposure and Google synchronization/join artifacts, plus detection of container context Local cloud/container/join markers; network opt-in enables metadata, sensitive opt-in additionally enables token-accessibility probes. |
