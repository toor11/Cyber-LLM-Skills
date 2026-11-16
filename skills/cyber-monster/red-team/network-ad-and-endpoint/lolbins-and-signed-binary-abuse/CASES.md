# Multi-Dataset Provenance Log

> Sub-skill: [`lolbins-and-signed-binary-abuse`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Case labels below are stored in this file. The procedure is in [`SKILL.md`](SKILL.md).

## In-file case labels

| Tag | What this file already states |
|---|---|
| - | Rundll32 |
| - | PubPrn |
| - | Mavinject |
| - | InstallUtil |
| - | Msiexec |
| - | CMSTP |
| - | Control Panel |
| - | Odbcconf |
| - | Verclsid |
| - | Mshta |
| - | Regsvr32 |
| - | Regsvcs/Regasm |
| Sigma Rule | Potential Provisioning Registry Key Abuse For Binary Proxy Execution - REG |
| Sigma Rule | Pubprn.vbs Proxy Execution |
| Sigma Rule | Launch-VsDevShell.PS1 Proxy Execution |
| Sigma Rule | Potential Manage-bde.wsf Abuse To Proxy Execution |
| Sigma Rule | Use of Scriptrunner.exe |
| Sigma Rule | Uncommon Child Process Of BgInfo.EXE |
| Sigma Rule | Binary Proxy Execution Via Dotnet-Trace.EXE |
| Sigma Rule | Potential Script Proxy Execution Via CL_Mutexverifiers.ps1 |
| Sigma Rule | Proxy Execution Via Wuauclt.EXE |
| Sigma Rule | Potential Binary Proxy Execution Via Cdb.EXE |
| Sigma Rule | Msiexec Quiet Installation |
| Atomic Validation Test | T1127 - Trusted Developer Utilities Proxy Execution |
| Atomic Validation Test | T1127.001 - Trusted Developer Utilities Proxy Execution: MSBuild |
| Atomic Validation Test | T1216.001 - Signed Script Proxy Execution: Pubprn |
| Execution Prevention | Applying strict firewall rules to prevent external network connections |
| Defense Evasion | Implement strict code obfuscation techniques to prevent reverse engineering of the utilities. |
| System Binary Proxy Execution | Notepad |
| Process Monitoring | Benefits: Completely prevents the execution of malicious payloads; |
