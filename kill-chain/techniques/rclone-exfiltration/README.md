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

<!-- Elastic capture for this phase: elastic-rclone-exfiltration.png -->
<!-- Manual capture for this phase: manual-rclone-exfiltration.png -->

No capture yet: the chain is being rebuilt and the first run of this design has not been recorded.
