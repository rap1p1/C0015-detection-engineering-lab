# T-001 - Document starts a loader chain

| Field | Value |
|---|---|
| Case | [01-delivery](../cases/01-delivery.md) |
| Host | WS01 |
| Account | `C0015\duc.user` (standard) |
| Priority | High |
| Status | Open - evidence pending |

## Summary

A Word document started `cmd.exe`, which started `mshta.exe`, which started `regsvr32.exe` on a staged
`.jpg`; the module is unsigned.

## Findings

- Parent chain by entity id: Word -> cmd -> mshta -> regsvr32.
- The module is unsigned and lives under `C:\Users\Public`.
- The loader wrote a script into the HealthMonitor checks directory.

## Unknowns

- Whether the module executed.
- What the script did (covered by T-002).

## Actions and escalation

Triage complete; escalate to T-002 once the agent child process is confirmed.
