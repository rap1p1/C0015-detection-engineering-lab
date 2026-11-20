# WMI lateral movement

| | |
|---|---|
| Chain phase | WMI lateral movement |
| Account | Administrator |
| What happens | WMI with the recovered credential disables Defender on FS01, then delivers the beacon |
| Telemetry | Security 4624 type 3, 4672, Sysmon 1 under WmiPrvSE |
| Detection | R07 / R08 |
| Payload / tooling | none; operator action |

## How the lab reproduces it

See [`attack-playbook/README.md`](../../../attack-playbook/README.md) for the ordered steps, the exact
commands and the checks after each step. Anything this phase writes is listed in
[`attack-playbook/payloads`](../../../attack-playbook/payloads/README.md).

## Evidence

<!-- Elastic capture for this phase: elastic-wmi-lateral-movement.png -->
<!-- Manual capture for this phase: manual-wmi-lateral-movement.png -->

No capture yet: the chain is being rebuilt and the first run of this design has not been recorded.
