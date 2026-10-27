# Ticket T-003: WMI remote execution from a workstation to the file server

| Field | Value |
|---|---|
| Ticket | T-003 |
| Case | [WMI lateral execution](../cases/wmi-execution.md) |
| Run | `run-1`, capture `cap-run1-1` |
| Opened (UTC) | 2026-10-27T12:27:03Z |
| Status | Open - escalated to Tier 2 |

## Summary

`ws01` issued five `wmic /node:FS01` process creations with an explicit `helpdesk` credential. Each one
produced a matching process under `WmiPrvSE.exe` on `fs01`, including a loader, a defence-disable
command, an injector, a credential dump command and an impact batch file.

## Priority

Critical: the sequence covers loader execution, defence tampering, credential access and impact on the
backup server within twenty-one seconds.

## Entities

| Type | Value |
|---|---|
| Source host | `ws01` |
| Target host | `fs01` |
| Account | `C0015\helpdesk` |
| Files | `C:\ProgramData\143.dll`, `inject.cmd`, `dump.cmd`, `C:\locker.bat` |

## Evidence

| Event | Locator |
|---|---|
| Source invocation 1-5 | `AaF9VI505TXapMElq26Z`, `...MElq27j`, `...MFMrXYV`, `...MFyrcL7`, `...MFyrsI5` |
| Target execution 1-5 | `AaF9VI505TXapMEVqvrh`, `...MFBrF1u`, `...MFBrF2t`, `...MFlrcSd`, `...MGMriKM` |

## Findings

- Source and target documents agree on account, command content and sub-second timing.
- The account used is a helpdesk identity, not an administrative account expected to run these commands.

## Unknowns

- The WMI logon type on `fs01` is not in the bundle.
- Whether the impact batch completed encryption is not shown; it renames and writes a note.

## Actions taken

- Alerts triaged, source and target documents resolved and paired.

## Recommended actions

- Disable the `helpdesk` account and reset its password.
- Collect `C:\ProgramData` from `fs01` and hash the files listed above.
- Check for other hosts where `helpdesk` authenticated in the same hour.

## Escalation

Tier 2 immediately. Containment is recommended but has **not** been performed.


