# Design and assessment limits

The catalog preserves all 148 input IDs and routes each to a collector. Coverage describes implementation; Status describes the run. Completed is not an assertion of safety or exploitability. Access failures, unavailable formats/dependencies and truncation are explicit. A failed check does not stop other checks. Cached inventories replay incomplete-coverage warnings.

Reports use schema 1.0 and tool version 0.2.0, timestamped filenames, escaped HTML and redacted structured evidence. Process exit status describes runner failure, not findings; automation should inspect Summary and per-check Status. Raw secret excerpts, recovered passwords, Wi-Fi keys, managed passwords and authentication tokens are never serialized.

Native source compiles with Add-Type, subject to Windows policy. Initial compilation failure terminates scanning. x64 is the tested architecture; x86/ARM64 need further validation. Registry/filesystem views follow process architecture, with explicit WOW6432Node paths supplementing native views.

Permission checks query metadata or briefly open handles. Windows DACL evaluation respects current-token groups, restricted SIDs and denies. AD evaluation uses object-specific AccessCheckByType and principal SELF when available. Mandatory integrity, locks, custom loader flags, service/task triggers and application reachability still affect exploitability.

Potentially blocking pipe/device/handle queries, UWP, Firefox NSS, remote DC registry and CI parsing run in timed helpers. Pipe/device loops have cooperative budgets. Other CIM/COM/LDAP calls are not universally wall-time bounded. MaxItems is an enumeration/result cap, not a global memory/time budget.

Credential probes are optional. Native buffers controlled by the implementation are cleared before release. Managed strings returned by Windows/WinRT/XML APIs cannot reliably be wiped, but are never serialized. Firefox uses a publisher-verified installed NSS library in a separate process, with read-only databases and profile module loading disabled. No primary-password cracking or app-bound encryption bypass is attempted.

SQLite connections are read-only and do not copy credential databases into the workspace. Queries have busy, execution and result limits. Session parsers bound input/decompressed sizes; persisted sessions do not establish live browser state. XML DTDs/external entities are prohibited. File traversal skips reparse points, and secret searches retain categories rather than excerpts.

MSRC assessment uses the earliest fixing revision published for an exact Windows product/branch/architecture/role in the selected snapshot. Legacy fixing builds come from Microsoft KB titles when CVRF lacks FixedBuild. Unmatched products are unknown, not patched. Update history does not independently prove supersedence.

CI analysis uses a pinned BSD parser with documented compatibility changes. Kernel signing-scenario references are checked before attributing a deny. Hash/version rules and TBS signer candidates are distinguished. Publisher/EKU/issuer/OEM/exception/signing-time restrictions remain conditional when unresolved. No deny match is never a load-permission result. Unknown future CI extensions are a coverage limit.

Domain queries are opt-in and sampled. Applied GPOs use computer RSoP; unavailable RSoP does not mean no policies. AD CS checks combine publication, enrollment rights, flags/EKUs and issuance controls; CA-side settings can constrain results. Encrypted LAPS attributes remain encrypted. gMSA password-readability requires both domain and sensitive opt-ins. Relay assessment reads one discovered DC's configuration and never performs an authentication relay.

NVD receives package name/version for keyword candidate lookup; exact CPE applicability needs review. Cloud probes use fixed link-local endpoints without proxies/redirects. Optional identity responses are reduced to accessibility/expiration evidence and never used elsewhere. An identity accessible to its own workload is not inherently a vulnerability.

MSI databases open read-only. There are no Win32_Product queries, repair/installation consistency checks or custom-action execution. Static analysis cannot resolve arbitrary runtime MSI properties or prove repair reachability.
