# Loaders and unsigned module

| | |
|---|---|
| Chain phase | Loaders and unsigned module |
| Account | duc.user |
| What happens | regsvr32 loads the staged .jpg as a module; the loader writes the agent script |
| Telemetry | Sysmon 1, Sysmon 7 (image load), Sysmon 11 |
| Detection | R03 |
| Payload / tooling | loader-regsvr32.c |

## How the lab reproduces it

See [`attack-playbook/README.md`](../../../attack-playbook/README.md) for the ordered steps, the exact
commands and the checks after each step. Anything this phase writes is listed in
[`attack-playbook/payloads`](../../../attack-playbook/payloads/README.md).

## Evidence

<!-- Elastic capture for this phase: elastic-regsvr32-loader.png -->
<!-- Manual capture for this phase: manual-regsvr32-loader.png -->

No capture yet: the chain is being rebuilt and the first run of this design has not been recorded.
