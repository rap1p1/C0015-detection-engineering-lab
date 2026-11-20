# HTA proxy execution

| | |
|---|---|
| Chain phase | HTA proxy execution |
| Account | duc.user |
| What happens | mshta runs an .hta that starts regsvr32 on a staged file |
| Telemetry | Sysmon 1, Sysmon 3 if it fetches |
| Detection | R02 |
| Payload / tooling | compareforfor.hta |

## How the lab reproduces it

See [`attack-playbook/README.md`](../../../attack-playbook/README.md) for the ordered steps, the exact
commands and the checks after each step. Anything this phase writes is listed in
[`attack-playbook/payloads`](../../../attack-playbook/payloads/README.md).

## Evidence

<!-- Elastic capture for this phase: elastic-hta-proxy-execution.png -->
<!-- Manual capture for this phase: manual-hta-proxy-execution.png -->

No capture yet: the chain is being rebuilt and the first run of this design has not been recorded.
