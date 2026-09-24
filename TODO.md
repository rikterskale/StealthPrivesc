# TODO — native EDR-evasive rewrite

Goal: replace all PowerShell beacons (Add-Type, child procs, CIM, reg sweeps, events, HTTP, DNS) with one in-process native DLL (`dist\stealthnative.dll`) + unsigned `scanner.exe` host; CLI/report schema unchanged (schema 1.5, additive `'Native'` kind); `-Jitter` added (50–500 ms gaps + shuffled checks); then tests + before/after report diff + commit.

## Native source status (src/Native/)
DONE (final): NativeSyscall.cs (syscall stub + ntoskrnl export scan), all pre-existing files.
CLEAN, minor owed at compile: NativeCalls.cs (drop unused `slot`, `pid.ToString` x3), NativeFilesystem.cs (drop unused fake `GetDescriptor`).
JUNK — rewrite small+clean next: NativeRegistry.cs (broken `Split`, bogus `value.Truncated`, odd loop bound), NativeSystem.cs, NativeSvc.cs, NativeFsSearch.cs (dead junk lines in Search).
NOT YET WRITTEN (~80–120 lines each):
- NativeSvc.cs — `Svc`/`SvcResult` + ntdll `Zw*` pinvoke + one enumerate fn (all SCM checks).
- NativeSystem.cs — `Q(key,val,cap,out type)` for REG_SZ/DWORD/QWORD/BINARY/MULTI_SZ + tiny funcs: whoami, computer, profiles, hotfixes, shares, printers, Audit, Winhttp, Dsreg, Wec, ci-policy Active-dir read.
- NativeRegistry.cs — fix `Split("HKLM:\""/"Registry::")`, value caps/types, working subkey.
- NativeFsSearch.cs — strip dead branches in Search (keep regex IgnoreCase BFS, caps, skips SysVol/`$RECYCLE.BIN`/`$Extend`).
- NativeTasks.cs — `%windir%\System32\Tasks` XML (DtdProcessing=Prohibit) → tasks + `State`.
- NativeEvt.cs — EvtQuery/EvtRender flag 16 → XML strings, newest-first, capped.
- NativeNet.cs — raw UDP DNS (servers from registry DhcpNameServer) + raw TCP HTTP/1.1 GET (IMDS, timeout+max).

BUILD RULE: one small file per message (~≤150 lines), distinctive identifiers (a repetition glitch corrupts long repeated payloads).

Key facts: tasks XML at `%windir%\System32\Tasks`; events via Evt API not Get-WinEvent; DNS raw to registry DhcpNameServer; IMDS raw TCP http-only.
Locked decisions: authenticode = PS `Get-AuthenticodeSignature` cmdlet (native = meta/hash/ACL only); cmdkey→existing NativeInspection.Credentials, vault→existing NativeVault.Inspect; `klist.exe` single allowed child-proc exception (check 30); auditpol/netsh/dsregcmd/wececutil/netsh-interface → NativeSystem registry funcs.
Build: `tools\Build-Native.ps1` (dotnet at `C:\Program Files\dotnet\dotnet.exe`, net48 csproj `..\src\Native\*.cs`, AllowUnsafe, RefAssemblies.net48) → `dist\stealthnative.dll` + `dist\scanner.exe`.
DLL load: env `STEALTHNATIVE=<temp>\stealthnative.dll`, else `<repo>\dist\stealthnative.dll`.
scanner.exe: repo source; in-process PowerShell via `Assembly.LoadFrom`; embeds full `src/` + `checks.json` + all `data/*.json`; extracts to `%TEMP%` at runtime; same params/defaults.

## Next (resume point)
1. Rewrite junked: `src/Native/NativeSvc.cs`, `NativeSystem.cs`, `NativeRegistry.cs`; strip junk from `NativeFsSearch.cs`; tidy `NativeCalls.cs`, `NativeFilesystem.cs`.
2. Write: `NativeTasks.cs`, `NativeEvt.cs`, `NativeNet.cs`, ci-policy fn in `NativeSystem.cs`.
3. `tools\Build-Native.ps1` + csproj/exe project → first compile → iterate fixes until DLL+EXE link.
4. `scanner.exe` host (loader, env var, embed, runtime extract) + signtool usage docs.
5. Port every beacon to native calls + `-Jitter`.
6. CI windows job; run `tools\Test-Project.ps1` green on PS 5.1 + pwsh7.
7. Before/after JSON diff (ignore timestamps), docs update, commit.
