# Case 01 - Delivery: document to loader

**Run:** `run-4`, window `2026-11-21T05:00Z - 05:35Z`. This case uses run-4 only.

## Expected alerts

| Rule | Run-4 matches | What it shows |
|---|---|---|
| R01 | 2 | Word starts a script host |
| R02 | 1 | script host starts `regsvr32` |
| R03 | 1 | `regsvr32` loads an untrusted module |

## Evidence

| Step | Locator | What it shows |
|---|---|---|
| script host | `logs-windows.sysmon_operational-*` / `AaH8fO2TxY-KOm1PbsjC` | E1 `mshta.exe` under the Office chain |
| module load | `logs-windows.sysmon_operational-*` / `AaH8hO2TxY-KOm2Njkvd` | E7 for the loader, `dll.code_signature.trusted = false` |
| script write | `logs-windows.sysmon_operational-*` / `AaH8g-2TxY-KOm0gigB5` | E11 `regsvr32.exe` writes into `HealthMonitor\checks` |

R02 records the invocation of `regsvr32`; R03 records that a module was actually loaded. They are two
observations of the same step, not duplicates. Cite "untrusted" because the field is a trust verdict,
not a signature verdict.

## What it proves

A document started a shell, which started `mshta`, which started `regsvr32`, which loaded an untrusted
module from a user-writable path and wrote a script into the agent checks directory.

It does not prove the script ran (case 02) or that the module's code executed beyond the load event.
