# Case: LSASS access

**Bundle** [`evidence/runs/run-1/`](../../evidence/runs/run-1/run.json), capture `cap-run1-1`.
**Alert** `C0015 | lsass credential access`, document created 2026-10-27T12:27:19.358Z.

## 1. Source event

| Field | Value |
|---|---|
| Source event time | 2026-10-27T12:27:19.204Z |
| Locator | `.ds-logs-windows.sysmon_operational-c0015-2026.10.24-000002` / `AaF9VI505TXapMFlrcSr` |
| Host | `fs01` |
| Source process | `C:\ProgramData\mk.exe`, pid 6364, entity `{88E52A21-98A7-6AE0-7002-000000001500}` |
| Source user (`SourceUser`) | `C0015\helpdesk` |
| Target (`TargetImage`) | `C:\Windows\system32\lsass.exe` |
| Target user (`TargetUser`) | `NT AUTHORITY\SYSTEM` |
| Granted access | `0x1010` |

`SourceUser` is the identity the opening process runs as; `TargetUser` is the account LSASS runs as. They
are different fields, and neither is a substitute for `user.id`, which this event leaves empty.

## 2. What the event shows

A process outside the system directories, running as a domain helpdesk account, opened LSASS with a mask
that includes `PROCESS_VM_READ` and `PROCESS_QUERY_LIMITED_INFORMATION` (`0x1010`). That is the access
pattern a credential dumper uses.

## 3. What it does not show

| Claim | Status |
|---|---|
| Credentials were read | Not shown. The event records a handle, not reads. |
| A dump file was written | Not shown in this bundle; needs a file-creation event in the same window. |
| The process was started by the intrusion | Not shown. The E10 record carries no parent and no creation event for `mk.exe` is in the bundle. |
| The account has rights beyond its group membership | Not shown. `SourceUser` records the token owner, not the privileges used. |

## 4. Context worth collecting next

- the process-creation event for `C:\ProgramData\mk.exe` (parent, command line);
- file creation under `C:\ProgramData` and `C:\Windows\Temp` in the same minute;
- the WMI invocations from `ws01` at 12:27Z, which use the same account.

## 5. Disposition

Investigate and escalate. The identity is known, the binary runs from a staging directory, and the same
account drives WMI execution on this host in the same minute. The missing dump artefact limits the
conclusion to "suspicious LSASS access", not "credential theft".

