# Expected telemetry — Conti-style impact through admin shares

A batch file launches a locker binary per target host against the C$ admin share; the locker renames files and drops a ransom note in every affected directory.

| Source | Event | Fields |
|---|---|---|
| Sysmon E1 | `cmd.exe /c locker.bat` then `*_locker.exe -m -net -size 10 -nomutex -p \\HOST\C$` | `process.command_line`, `process.parent.name` |
| Sysmon E11 | `readme.txt` created in many directories | `file.name`, `file.path` |
| Sysmon E26 / E23 | file deletion and rename during encryption | `TargetFilename` |
| Security 5145 | write access to `C$` of each target | `ShareName`, `AccessMask` |

Collection notes: Sysmon 15.x with the profile in `infra/sysmon/`; Security channel with process
creation auditing and command-line inclusion; PowerShell script block logging for the enumeration
step. Field names in the rules assume the Elastic Common Schema mapping produced by the Elastic
Agent Windows integration.
