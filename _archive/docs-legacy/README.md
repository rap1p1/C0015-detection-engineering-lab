# Technical reading guide

The study follows a research argument: question → historical evidence → laboratory model → telemetry/detection → evaluation. Use the numbered order below for a full read; use the last two columns to inspect the supporting implementation and run evidence.

| Chapter | Read | Supporting material |
|---|---|---|
| 1. Question and foundations | [Research overview](research/overview.md) | [Source register](research/references.md) |
| 2. Original campaign and laboratory fidelity | [Campaign mapping](research/campaign-mapping.md) | [Behavior/telemetry comparison](research/telemetry-comparison.md) |
| 3. Laboratory method | [Architecture](lab/architecture.md) | [Detailed diagram](lab/architecture-overview.md), [components](lab/components.md), [Sysmon profiles](../configs/README.md) |
| 4. Execution and observations | [RUN-09 report](../reports/reference-run-20261002-09.md) | [Run ledger](../evidence/runs/RUN-20261002-09/RUN-20261002-09.json), [operator runbook](lab/runbook.md) |
| 5. Detection engineering | [Rule catalogue](../detections/README.md) | [Correlation model](detection/correlation.md), [query sources](../detections/queries/) |
| 6. Evaluation and limitations | [Validation guide](validation/README.md) | [RUN-07 tuning reference](../reports/reference-run-20261002-07.md), [all run reports](../reports/README.md) |

## How to interpret the documents

- Campaign claims cite historical sources. Lab findings cite a specific run and artifact/event references.
- Design/runbook instructions describe intended procedures; reports and ledgers record execution outcomes.
- S1–S14 are campaign stages. S15 is post-run validation. A successful verifier result does not override PARTIAL or NOT RUN stage statuses.
- [Phase narratives](../phases/README.md) retain development history. Their older planning numbering is not the current ledger numbering.

Files at the former flat `docs/*.md` paths are compatibility entry points. Current content is maintained in `research/`, `lab/`, `detection/` and `validation/`; existing payload references and rule metadata can continue using the old paths.
