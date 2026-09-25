# TODO — native EDR-evasive rewrite

Goal: replace all PowerShell beacons (Add-Type, child procs, CIM, reg sweeps, events, HTTP, DNS) with one in-process native DLL (`dist\stealthnative.dll`) + unsigned `scanner.exe` host; CLI/report schema unchanged (schema 1.5, additive `'Native'` kind); `-Jitter` added (50–500 ms gaps + shuffled checks); then tests + before/after report diff + commit.

## Native source status (src/Native/)
DONE — every file rewritten/tidied and compiling: NativeSvc, NativeSystem, NativeRegistry, NativeFsSearch, NativeTasks, NativeEvt, NativeNet, NativeCalls, NativeFilesystem (+ all pre-existing).

BUILD RULE: one small file per message (~≤150 lines), distinctive identifiers (a repetition glitch corrupts long repeated payloads).

Key facts: tasks XML at `%windir%\System32\Tasks`; events via Evt API not Get-WinEvent; DNS raw to registry DhcpNameServer; IMDS raw TCP http-only.
Locked decisions: authenticode = PS `Get-AuthenticodeSignature` cmdlet (native = meta/hash/ACL only); cmdkey→existing NativeInspection.Credentials, vault→existing NativeVault.Inspect; `klist.exe` single allowed child-proc exception (check 30); auditpol/netsh/dsregcmd/wececutil/netsh-interface → NativeSystem registry funcs.
Build: `tools\Build-Native.ps1` (dotnet at `C:\Program Files\dotnet\dotnet.exe`, net48 csproj `..\src\Native\*.cs`, AllowUnsafe, RefAssemblies.net48) → `dist\stealthnative.dll` + `dist\scanner.exe`.
DLL load: env `STEALTHNATIVE=<temp>\stealthnative.dll`, else `<repo>\dist\stealthnative.dll`.
scanner.exe: repo source; in-process PowerShell via `Assembly.LoadFrom`; embeds full `src/` + `checks.json` + all `data/*.json`; extracts to `%TEMP%` at runtime; same params/defaults.

## Next (resume point)
DONE 1–3: junked natives rewritten, all natives written+clean, first compile green (`tools\Build-Native.ps1` → `dist\stealthnative.dll`, 0 warn/0 err).
4. (active) `scanner.exe` host: csproj/cs + `tools\Build-Native.ps1` done; deps pinned (`System.Management.Automation` 7.4.20, `microsoft.powershell.commands.{diagnostics,management,utility}` 7.4.20, `System.Diagnostics.PerformanceCounter` 8.0.1). LEFT: rebuild → `dist\scanner.exe -ListChecks` green (+ add any further missing runtime pkg) → `-Category Identity -PassThru` smoke → signtool usage docs.
5. Port every beacon to native calls + `-Jitter`.
6. CI windows job; run `tools\Test-Project.ps1` green on PS 5.1 + pwsh7.
7. Before/after JSON diff (ignore timestamps), docs update, `.gitignore` += `dist/`, commit.
