# T-002 - Agent escalation, discovery and administrator secret

| Field | Value |
|---|---|
| Run | R05/R18 from run-3; R04/R13 from run-4 |
| Host | WS01 |
| Account | SYSTEM, then `C0015\Administrator` |
| Priority | Critical |
| Status | Open - evidence captured |

## Summary

The agent executed a script planted by a standard user as SYSTEM; discovery ran from that context; the
LSA secret of the backup service was requested and yielded the domain administrator password.

## Evidence

- R13: E11 `AaH8g-2TxY-KOm0gigB5` (writer `regsvr32`, user `duc.user`).
- R04: PowerShell E1 under SYSTEM, 29.730 s after the write; no parent in the event.
- R18: E1 `AaH54ZKtksj2Z05CAh4g` (`nltest`), plus the net.exe/net1.exe pair and net view.
- R05: E1 `AaH54ZKtksj2Z06SA00d` (`lsadump::secrets`).

## Not proven

That the secret was used after extraction; that LSASS was touched.

## Escalation

Critical: domain administrator credentials are in play. Continue in T-003.
