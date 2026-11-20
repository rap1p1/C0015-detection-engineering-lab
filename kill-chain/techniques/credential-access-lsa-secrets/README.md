# Credential access from LSA secrets

| | |
|---|---|
| Chain phase | Credential access from LSA secrets |
| Account | SYSTEM |
| What happens | mimikatz reads the LSA secrets of the backup service and recovers C0015\Administrator |
| Telemetry | Sysmon 1, Security 4688, 4672 |
| Detection | R05 |
| Payload / tooling | mimikatz (tools/mimikatz) |

## How the lab reproduces it

See [`attack-playbook/README.md`](../../../attack-playbook/README.md) for the ordered steps, the exact
commands and the checks after each step. Anything this phase writes is listed in
[`attack-playbook/payloads`](../../../attack-playbook/payloads/README.md).

## Evidence

<!-- Elastic capture for this phase: elastic-credential-access-lsa-secrets.png -->
<!-- Manual capture for this phase: manual-credential-access-lsa-secrets.png -->

No capture yet: the chain is being rebuilt and the first run of this design has not been recorded.
