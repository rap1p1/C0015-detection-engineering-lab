# Documentation

| Area | Document | Contents |
|---|---|---|
| Study | [architecture](study/architecture.md) | Hosts, network, account model, telemetry path |
| Study | [scenario contract](study/scenario-contract.md) | Ordered execution, from listener start to restore |
| Study | [gaps](study/gaps.md) | What the campaign does that the lab substitutes or omits |
| Detection | [attack coverage](detection/attack-coverage.md) | Generated from the catalog: what each rule observes and what it does not |
| Detection | [Sigma reference](detection/sigma-reference.md) | Upstream SigmaHQ rules read as prior art, with links |
| History | [killchain](history/killchain.md) | Earlier iterations and their runs, kept as history |

Technique detail lives in `techniques/<name>/`: the payload or tooling, the telemetry expectations and
the notes for that behaviour.

The reference run report is in [`../reports/reference-run.md`](../reports/reference-run.md), and the data
it cites is under [`../evidence/runs/`](../evidence/runs/).
