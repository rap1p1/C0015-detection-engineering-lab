# Document and macro

| | |
|---|---|
| Chain phase | Document and macro |
| Account | duc.user |
| What happens | WINWORD.EXE starts cmd.exe /c mshta on the user profile |
| Telemetry | Sysmon 1 (process create), Office macro telemetry |
| Detection | R01 |
| Payload / tooling | macro-payload.vba, macro-install-docm.ps1, macro-build-embedded.ps1 |

## How the lab reproduces it

See [`attack-playbook/README.md`](../../../attack-playbook/README.md) for the ordered steps, the exact
commands and the checks after each step. Anything this phase writes is listed in
[`attack-playbook/payloads`](../../../attack-playbook/payloads/README.md).

## Evidence

<!-- Elastic capture for this phase: elastic-delivery-macro-document.png -->
<!-- Manual capture for this phase: manual-delivery-macro-document.png -->

No capture yet: the chain is being rebuilt and the first run of this design has not been recorded.
