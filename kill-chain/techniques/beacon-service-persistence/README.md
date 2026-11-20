# Beacon service persistence

| | |
|---|---|
| Chain phase | Beacon service persistence |
| Account | SYSTEM |
| What happens | the beacon is installed as an auto-start service so it survives reboot |
| Telemetry | Security 7045, Sysmon 1 |
| Detection | R09 |
| Payload / tooling | service install command (attack-playbook) |

## How the lab reproduces it

See [`attack-playbook/README.md`](../../../attack-playbook/README.md) for the ordered steps, the exact
commands and the checks after each step. Anything this phase writes is listed in
[`attack-playbook/payloads`](../../../attack-playbook/payloads/README.md).

## Evidence

<!-- Elastic capture for this phase: elastic-beacon-service-persistence.png -->
<!-- Manual capture for this phase: manual-beacon-service-persistence.png -->

No capture yet: the chain is being rebuilt and the first run of this design has not been recorded.
