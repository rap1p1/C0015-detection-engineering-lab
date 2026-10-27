# Ticket T-002: LSASS opened with a dump-like access mask

| Field | Value |
|---|---|
| Ticket | T-002 |
| Case | [LSASS access](../cases/lsass-access.md) |
| Run | `run-1`, capture `cap-run1-2` |
| Opened (UTC) | 2026-10-27T12:27:19Z |
| Status | Open - Tier 1 investigation, escalation required |

## Summary

`fs01` reported `C:\ProgramData\mk.exe` opening `lsass.exe` with `0x1010` while running as
`C0015\helpdesk`.

## Priority

High. LSASS access with a read mask, from a binary in a staging directory, under a helpdesk identity,
on the host that holds the backup corpus, in the same minute as WMI execution from `ws01`.

## Entities

| Type | Value |
|---|---|
| Host | `fs01` (192.168.50.30) |
| Source process | `C:\ProgramData\mk.exe`, pid 6364, entity `{88E52A21-98A7-6AE0-7002-000000001500}` |
| Source user | `C0015\helpdesk` |
| Target | `C:\Windows\system32\lsass.exe`, target user `NT AUTHORITY\SYSTEM`, access `0x1010` |

## Evidence

| Event | Locator |
|---|---|
| Process access to LSASS | `AaF9VI505TXapMFlrcSr` |

## Findings

- Source identity and executable path are recorded on the event (`SourceUser`, `process.executable`).
- The access mask is consistent with reading LSASS memory.
- The process runs from `C:\ProgramData`, not a system directory.

## Unknowns

- Whether a dump file was written (no file-creation event in the bundle).
- How `mk.exe` arrived on the host and which process created it (no E1 for it in the bundle).
- Which privileges the account effectively used.

## Actions taken

- Alert triaged, source event resolved, identity extracted from the raw document.

## Recommended actions

- Create a hunt for `mk.exe` process creation on both hosts and in the WMI execution window.
- Search file creation under `C:\ProgramData` and `C:\Windows\Temp` at 12:27Z.
- Correlate with the `helpdesk` WMI invocations from `ws01` at the same time.

## Escalation

Escalate to Tier 2. A missing dump artefact does **not** close this ticket: the access is unexplained, the
binary lives in a staging directory, and the account is already implicated in the WMI chain. Closing
requires a documented benign cause or a decision recorded by the incident owner.

