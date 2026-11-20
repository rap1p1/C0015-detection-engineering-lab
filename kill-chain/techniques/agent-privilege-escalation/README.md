# Agent privilege escalation

| | |
|---|---|
| Chain phase | Agent privilege escalation |
| Account | duc.user -> SYSTEM |
| What happens | HealthMonitor runs the planted script as SYSTEM; the script stages the injector and the beacon DLL |
| Telemetry | Sysmon 1 (child of HealthMonitor), Sysmon 11 (script written) |
| Detection | R04 (agent child), R13 (script written) |
| Payload / tooling | agent-update.ps1, install-healthmonitor.ps1 |

## How the lab reproduces it

See [`attack-playbook/README.md`](../../../attack-playbook/README.md) for the ordered steps, the exact
commands and the checks after each step. Anything this phase writes is listed in
[`attack-playbook/payloads`](../../../attack-playbook/payloads/README.md).

## Evidence

<!-- Elastic capture for this phase: elastic-agent-privilege-escalation.png -->
<!-- Manual capture for this phase: manual-agent-privilege-escalation.png -->

No capture yet: the chain is being rebuilt and the first run of this design has not been recorded.
