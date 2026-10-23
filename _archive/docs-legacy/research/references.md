# Source register and citation conventions

[Reading guide](../README.md) · [Research overview](overview.md)

| ID | Source | Role in this study |
|---|---|---|
| C1 | [MITRE ATT&CK, Campaign C0015](https://attack.mitre.org/campaigns/C0015/) | Campaign technique/software vocabulary and references. |
| C2 | [The DFIR Report, CONTInuing the Bazar Ransomware Story, 29 November 2021](https://thedfirreport.com/2021/11/29/continuing-the-bazar-ransomware-story/) | Primary published intrusion narrative, chronology, tools and uncertainties. |
| C3 | [Microsoft Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) | Meaning of event types; not proof of lab configuration or source-campaign events. |
| L1 | [Retained run reports](../../reports/README.md) | Human-readable analysis of each lab execution. |
| L2 | [Run ledgers and artifacts](../../evidence/runs/README.md) | Event/alert references, UTC timestamps, manifests, receipts and recovery records. |
| L3 | [Detection queries and exports](../../detections/README.md) | Committed detection logic and metadata. |

## Citation and claim rules

1. Historical claims cite C1/C2 and retain qualifiers such as likely, inferred or unknown. In the older campaign narrative, source labels S1/S2 mean MITRE/DFIR respectively; they are distinct from lab stage IDs S1/S2.
2. Lab findings cite a run ID and event/artifact record. The report is an interpretation of those records.
3. Design documents and synthetic fixtures are not observations. A technique mapping does not certify detection coverage.
4. Preserve exact source-event times, run IDs and hash conventions. State when a measurement came from an operator probe instead of a log field.
5. Mutable external documentation describes product behavior; recorded configuration files and run context identify the tested versions.

## Revision context

The documentation reorganization was based on upstream commit **`f8b8ce0b393948f60b2d25ac49f446b84b16206b`**, whose latest retained run is RUN-20261002-09. This baseline describes the reviewed source snapshot, not a new live experiment. Original references were retained; this edit adds no claim of a fresh external-source review.
