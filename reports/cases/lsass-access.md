# Case: LSASS access

**Alert** `C0015 | lsass credential access`, 2026-10-27T12:27:19Z, host `fs01`.
**Bundle** [`evidence/runs/run-1/`](../../evidence/runs/run-1/run.json).

## 1. Source event

| Field | Value |
|---|---|
| UTC | 2026-10-27T12:27:19.204Z |
| Locator | `.ds-logs-windows.sysmon_operational-c0015-2026.10.24-000002` / `AaF9VI505TXapMFlrcSr` |
| Host | `fs01` |
| Source process | `mk.exe` |
| Target | `C:\Windows\system32\lsass.exe` |
| Granted access | `0x1010` |

The alert resolves to exactly this document; `sources/by_alert.json` links it to the alert id.

## 2. What the event shows

A process named `mk.exe`, with no parent recorded in this document, opened LSASS with `0x1010` - a mask
that includes `PROCESS_VM_READ` and `PROCESS_QUERY_LIMITED_INFORMATION`. That is the pattern a credential
dumper produces, and the rule was written for it.

## 3. What it does not show

| Claim | Status |
|---|---|
| Credentials were read | Not shown. The event records the handle, not the reads. |
| A dump file was written | Not shown here. That needs a file-creation event in the same window. |
| The process was malicious | Not shown by the event alone. The name is short and generic; the parent is missing. |
| The account used has privileges | Not shown; no user field on the event. |

## 4. Disposition

Investigate. The mask and target are consistent with dumping, but the case needs the file-creation event
for a dump and the process creation of `mk.exe` before it can be called credential theft.

## 5. Operator ground truth

The lab copies `mk.exe` from the tooling and runs it as the recovered `helpdesk` identity. That context
is not in the event and is kept out of the analyst conclusion.

