# References

The 148-item catalog comes from the user's supplied checklist. W/P/U/H/S/T labels in that checklist compare upstream tools; they are not claims that this implementation has equivalent coverage. No upstream scanner code is vendored or executed.

Primary references consulted for implementation semantics:

- [Windows AccessCheck](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-accesscheck)
- [GetTokenInformation](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-gettokeninformation)
- [Service security and access rights](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights)
- [AlwaysInstallElevated](https://learn.microsoft.com/en-us/windows/win32/msi/alwaysinstallelevated)
- [CLFS logfile authentication configuration](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/clfs-authentication)
- [Get-ADServiceAccount parameters](https://learn.microsoft.com/en-us/powershell/module/activedirectory/get-adserviceaccount)
- [PrivescCheck service checks](https://github.com/itm4n/PrivescCheck/blob/master/src/check/Services.ps1)
- [PrivescCheck configuration checks](https://github.com/itm4n/PrivescCheck/blob/master/src/check/Configuration.ps1)
- [PrivescCheck hardening checks](https://github.com/itm4n/PrivescCheck/blob/master/src/check/Hardening.ps1)
- [winPEAS Active Directory check inventory](https://github.com/peass-ng/PEASS-ng/blob/master/winPEAS/winPEASexe/winPEAS/Checks/ActiveDirectoryInfo.cs)

Validate OS- and update-dependent policy interpretations against current Microsoft documentation before promoting a configuration indicator to a vulnerability rule.
