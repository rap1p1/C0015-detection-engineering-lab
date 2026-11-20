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

No capture yet: the chain is being rebuilt and the first run of this design has not been recorded.
