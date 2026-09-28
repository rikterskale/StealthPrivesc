# Roadmap

## v0.3.0 (planned)

- `-Execute` escalation executor ("make me SYSTEM" mode): takes a fresh scan (fixed internal check set 11,12,14,16,17,20,22,23,24) or `-ReportPath` to existing JSON. New parameters: `-Execute`, `-ReportPath`, `-Path <candidate-id>`, `-Command <string>`, `-Force`, `-Keep`, `-Restore -AttackId <id>`, `-DropPath`.
- Fresh live prerequisite re-check with the current token before any host change; numbered candidate prompt, default top-ranked, `-Path` overrides, `-Force` skips confirmation (required for non-interactive and already-elevated reports).
- Six exploit branches, each backing up, applying, verifying (`whoami`) and auto-restoring (skip with `-Keep`; saved state enables `-Restore` later):
  - `ServiceConfiguration` — SCM image-path retarget (temporary self DACL grant when only WRITE_DAC is held)
  - `ServiceRegistry` — writable service `ImagePath` registry value write
  - `ServiceImage` — overwrite writable service executable, restore original bytes
  - `ServiceUnquotedPath` — drop payload at the ambiguous prefix candidate
  - `TaskDefinition` — writable SYSTEM task XML action update, `/reload` and restore
  - `TaskImage` — overwrite writable task executable, restore original bytes
- On success: interactive SYSTEM PowerShell over a named pipe, or one-shot `-Command` with captured output; result `Attacks` array added to the report and written as a standalone `attack-*.json`.
- New native file `src/NativeExecute.cs` (SCM mutators: image-path change, status, control, DACL set — only new mutating API) and small self-contained runtime-compiled `src/Payload.cs` dropper (default `$env:TEMP`, random name, removed on exit unless `-Keep`).
- `tests/Test-Executor.ps1` wired into `tools/Test-Project.ps1` and CI like the existing suites; README quick-start plus command-table row; DESIGN.md paragraph; version 0.3.0 and schema 1.6 (`Attacks`).

Documented limits for v0.3.0: a registry-image candidate without start/stop rights is flagged reboot-required instead of failing; the shell is pipe-based with no visible window (session 0); no concurrency guarantee between scan and exec — the re-check runs before any modification.

## Backlog (later)

- Credential-extraction logins: decrypted GPP cpassword (checks 69/70), winlogon/SAM (67/71), task/service password logons (21/26) to reach SYSTEM as the recovered account.
- Wider opportunistic surfaces: PATH/DLL hijack (29/30/31), MSI AlwaysInstallElevated (47), COM registrations (36/39).
