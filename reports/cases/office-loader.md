# Case: Office to loader

**Alert** `C0015 | loader loads unsigned module`, 2026-10-27T12:22:19Z, host `ws01`.
**Bundle** [`evidence/runs/run-1/`](../../evidence/runs/run-1/run.json), capture `cap-final04-v3`.

The investigation starts from the alert and walks backwards through the source documents to the process
chain that produced it.

## 1. The alert

| Field | Value |
|---|---|
| Rule | R03 loader loads unsigned module (role `alert`, revision 3) |
| Alert time | 2026-10-27T12:22:19.358Z and 12:22:19.360Z |
| Host | `ws01` |
| Detection fields | module path, signature state, loading process |

## 2. Source events

Every row is a document the alert references, with its index and id in `sources/by_alert.json`.

| UTC | Source locator | Process / parent | Command line | File |
|---|---|---|---|---|
| 12:21:47.263 | `...2026.10.24-000002` / `AaF9T4505TXapMFDnV4y` | `cmd.exe` ← `WINWORD.EXE` | `cmd.exe /c mshta "C:\Users\duc.user\compareforfor.hta"` | - |
| 12:21:48.568 | `...2026.10.24-000002` / `AaF9T4505TXapMFqnWWP` | `regsvr32.exe` ← `mshta.exe` | `regsvr32.exe C:\Users\Public\compareForfor.jpg` | - |
| 12:21:48.802 | `...2026.10.24-000002` / `AaF9T4505TXapMFqnWWV` | `regsvr32.exe` (module load) | - | `C:\Users\Public\compareForfor.jpg`, `Signed=false` |
| 12:22:04.962 | `...2026.10.24-000002` / `AaF9T4505TXapMGSnkEd` | `rundll32.exe` (module load) | - | `C:\Windows\Temp\c0015_d8b3.dll`, `Signed=false` |

The two R03 alerts point at two different module loads: the proxy-execution DLL and the DLL the loader
wrote to a temporary path. The second one is the more interesting event and the one a reader should
follow.

## 3. What the chain proves

Reading the four documents in order:

1. Word spawned `cmd.exe` with a command line that starts `mshta` on a file in the user's profile.
2. `mshta.exe` spawned `regsvr32.exe` with the image path `C:\Users\Public\compareForfor.jpg`.
3. `regsvr32.exe` loaded that `.jpg` as a module, and the sensor recorded it as unsigned.
4. About sixteen seconds later, `rundll32.exe` loaded `C:\Windows\Temp\c0015_d8b3.dll`, also unsigned.

The ancestry is direct: each event names its parent, and the timestamps are consistent with that order.
This is an execution chain from a document to a proxy-executed module and then to a second, unsigned
module outside the Office process tree.

## 4. What it does not prove

| Claim | Status |
|---|---|
| The document ran a macro | Not shown here. The first event is `cmd.exe` under Word; macro execution itself needs a Word or Office telemetry source. |
| `compareForfor.jpg` is malicious | Not shown. Only that it is unsigned and was loaded by `regsvr32`. |
| The loader contacted a remote host | Not shown. No network event is in this bundle; the proxy-execution and module-load events carry no destination. |
| Code executed successfully | Not shown. A module load is not proof that its exports ran. |
| Persistence or system-level access | Not shown in this case; it happens later in the chain and is out of scope here. |

## 5. Analyst disposition

Investigate further, priority high. The behaviour is consistent with a document that drops a script
host, which in turn proxy-executes an unsigned module from a user-writable path. The next step is to
look for network activity from `regsvr32.exe` and `rundll32.exe` on `ws01` in the same minute, and for
the file creation of `c0015_d8b3.dll`.

## 6. Operator ground truth (not derived from telemetry)

The lab was built to reproduce this chain, so the operator knows the document is `decree-08.03.2021.docm`,
the HTA is `compareforfor.hta`, and `compareForfor.jpg` is the loader stub that fetches the next stage.
None of that is visible in the evidence above, and the case must be readable without it.

## 7. Reproduction

```
python3 tools/evidence/validate_run.py evidence/runs/run-1
python3 -c "import json;d=json.load(open('evidence/runs/run-1/sources/by_alert.json'));print(len(d))"
```

Open [`alerts/c0015.json`](../../evidence/runs/run-1/alerts/c0015.json) for the alert documents
and [`sources/by_alert.json`](../../evidence/runs/run-1/sources/by_alert.json) for the mapping
from each alert to the events above.


