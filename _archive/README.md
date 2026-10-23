# Archive

Material from the earlier phase-based layout. It is retained for reference and is not part of the
current structure.

| Folder | Contents |
|---|---|
| `docs-legacy/` | The phase plan, correlation design, and payload notes that described the previous layout |
| `detections-eql/` | EQL queries and rule exports written for the PowerShell beacon model |
| `payloads/` | The earlier C surrogates, the PowerShell beacon, the C2 simulator, and the packaging scripts |
| `scripts/` | The C2 simulator, evidence tooling, and verification scripts |
| `phases/` | Phase narratives and the operator gap runbook |
| `reports/` | Run reports for the earlier replay runs |
| `evidence/` | Ledgers, manifests, and receipts for those runs |
| `configs/` | The previous location of the Sysmon profiles, now in `infra/sysmon/` |

The content here describes a different implementation: a PowerShell beacon driven by a local HTTP
simulator, with the surrogate DLL spawning the beacon directly instead of hosting a C2 implant. The
technique folders replace it. Nothing in this folder is referenced by the current documentation.
