# T-002 - Agent escalation to SYSTEM and administrator secret

| Field | Value |
|---|---|
| Case | [02-privilege-credential](../cases/02-privilege-credential.md) |
| Host | WS01 |
| Account | SYSTEM, then `C0015\Administrator` |
| Priority | Critical |
| Status | Open - evidence pending |

## Summary

The HealthMonitor agent executed a script planted by a standard user and ran it as SYSTEM. A beacon
started, and mimikatz read the LSA secret of the maintenance task, which holds the domain administrator
password.

## Findings

- `checks` directory is writable by Users; the service runs as LocalSystem.
- The maintenance task runs as `C0015\Administrator`.
- The secret was read with `lsadump::secrets`, not from LSASS.

## Unknowns

- Whether the administrator credential was used elsewhere before FS01.

## Escalation

Critical: domain administrator credentials are in play. Escalate to T-003 and to incident response.
