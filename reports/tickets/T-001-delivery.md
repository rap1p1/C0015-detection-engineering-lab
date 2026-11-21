# T-001 - Document starts a loader chain

| Field | Value |
|---|---|
| Run | run-4 (2026-11-21 05:00-05:35Z) |
| Host | WS01 |
| Account | `C0015\duc.user` (standard) |
| Priority | High |
| Status | Open - evidence captured |

## Summary

Word started a script host, which started `regsvr32` on a staged `.jpg`; the module is untrusted and the
loader wrote a script into the HealthMonitor checks directory.

## Evidence

- R01/R02: E1 chain on WS01; representative E1 `AaH8fO2TxY-KOm1PbsjC`.
- R03: E7 `AaH8hO2TxY-KOm2Njkvd`, `dll.code_signature.trusted=false`.
- R13: E11 `AaH8g-2TxY-KOm0gigB5` (the write is shared with T-002).

## Open questions

Whether the module executed beyond the load, and what the script did - tracked in T-002.
