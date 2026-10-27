# Case: LSASS access

**Bundle** [`evidence/runs/run-1/`](../../evidence/runs/run-1/run.json), capture `cap-run1-2`.
**Alert** `C0015 | lsass credential access`; the alert document carries `@timestamp` 12:27:26.810Z and
refers to a source event at 12:27:19.204Z. Alert creation, rule execution and the event time are distinct.

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

`SourceUser` is the identity the opening process runs as; `TargetUser` is the account LSASS runs as. The
ECS `user.id` on this document is `S-1-5-18`, the SID that also identifies the target account. Whether the
pipeline maps it from `TargetUser` is not confirmed here, so it is recorded as the target SID rather than
used as the source identity. The raw document is not altered to make the fields agree.

## 2. What the event shows

A process outside the system directories, running as a domain helpdesk account, opened LSASS with a mask
that includes `PROCESS_VM_READ` and `PROCESS_QUERY_LIMITED_INFORMATION` (`0x1010`). That is the access
pattern a credential dumper uses.

## 3. What it does not show

| Claim | Status |
|---|---|
| Credentials were read | Not shown. The event records a handle, not reads. |
| A dump file was written | Not shown in this bundle; needs a file-creation event in the same window. |
| The process was started by the intrusion | Shown for the last two edges: `WmiPrvSE.exe` → `cmd.exe` (`AaF9VI505TXapMFlrcSd`, 12:27:19.109) → `mk.exe` (`AaF9VI505TXapMFlrcSm`, 12:27:19.170). The chain to the LSASS access at 12:27:19.204 is connected by entity ids. |
| The account has rights beyond its group membership | Not shown. `SourceUser` records the token owner, not the privileges used. |

## 4. Context worth collecting next

- the full command line of the `cmd.exe` that started `mk.exe`;
- file creation under `C:\ProgramData` and `C:\Windows\Temp` in the same minute;
- the WMI invocations from `ws01` at 12:27Z, which use the same account.

## 5. Disposition

Investigate and escalate. The identity is known, the binary runs from a staging directory, and the same
account drives WMI execution on this host in the same minute. The missing dump artefact limits the
conclusion to "suspicious LSASS access", not "credential theft".

