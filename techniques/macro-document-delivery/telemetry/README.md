# Expected telemetry — Word document macro execution

A weaponised Word document runs a VBA macro when the user enables content. The macro writes the HTML Application for the next stage to the user profile and launches it through cmd.exe.

| Source | Event | Fields |
|---|---|---|
| Sysmon E1 | `WINWORD.EXE` -> `cmd.exe /c mshta ...` | `process.parent.name`, `process.command_line` |
| Sysmon E11 | `compareforfor.hta` created under the user profile | `file.path`, `file.name` |
| Security 4688 | Word child process with command line (if ProcessCreationIncludeCmdLine is enabled) | `CreatorProcessName`, `CommandLine` |

Collection notes: Sysmon 15.x with the profile in `infra/sysmon/`; Security channel with process
creation auditing and command-line inclusion; PowerShell script block logging for the enumeration
step. Field names in the rules assume the Elastic Common Schema mapping produced by the Elastic
Agent Windows integration.
