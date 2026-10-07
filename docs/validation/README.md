# Validation, findings and limitations

[Reading guide](../README.md) · [Latest run](../../reports/reference-run-20261002-09.md) · [Evidence contract](../../evidence/README.md)

## Evaluation layers

| Layer | Question | Available method | Boundary |
|---|---|---|---|
| Offline component checks | Do artifact, receipt, fixture and simulator helpers satisfy their tests? | 20 tests in `scripts/tests/test_offline.py` | Synthetic/component checks do not establish EQL behavior or live coverage. |
| Artifact consistency | Do indexed documents and sink files match the recorded manifest/receipt contracts? | Run artifacts and verifier assertions | Artifact integrity does not by itself prove process causality. |
| Telemetry provenance | Do retained references resolve to the expected host/event/time and join fields? | `scripts/verify/verify_run_evidence.py` and live event retrieval | Requires the retained backend data; a ledger `_id` alone is a reference. |
| Campaign acceptance | Do the implemented final-phase assertions hold? | `scripts/verify/verify_final_phases.py` with runtime records | Overall acceptance is scoped to the assertions and preserves PARTIAL/NOT RUN. |
| Operational detection | Which alerts were recorded for the run and rule revision? | Per-run event/alert references; RUN-07 tuning report | Stored documents, unique activity and suppressed matches are different counts. |

## Reproduce offline checks

Run from the repository root:

```bash
python -m unittest discover -s scripts/tests
```

## Reproduce recorded acceptance

The live verifier requires access to the run's retained Elasticsearch events, expected runtime C2 log and local artifacts. Supply backend settings through `ES_URL`, `ES_USER` and `ES_PASS`, following the [runbook](../lab/runbook.md) and [script index](../../scripts/README.md).

```bash
python scripts/verify/verify_final_phases.py RUN-20261002-09
```

A documentation-only review can inspect committed evidence and run offline checks; it cannot recreate missing runtime logs or certify the current remote Elastic state. The published acceptance results are recorded in the [run reports](../../reports/README.md).

## Findings across the retained runs

| Assertion | Supported scope | Limitation |
|---|---|---|
| S6 target selection | RUN-09 artifact records FS01 decision | Fixed scenario selection; runs 05–08 remain NOT RUN. |
| WMI → rundll32 → module | E1/E7 and artifact-hash continuity as recorded | DLL load is not proof of cross-process injection. |
| Collection → transfer | 11-file manifests and two full-set sink receipts per recorded run | Internal WebDAV substitutes for MEGA; connection events alone do not prove transfer. |
| RDP lifecycle | Same-host Type-10 4624/4634 LogonId joins | Reconnect 4778 / disconnect 4779 unverified; S12 PARTIAL. |
| Recovery | RUN-05 one-directional comparison; 06–09 bidirectional comparison | Bounded corpus, not arbitrary enterprise recovery. |
| Detection behavior | RUN-07 tuning results; RUN-09 recorded references | No representative benign corpus or production precision/recall estimate. |

## Threats to validity

- **Historical fidelity:** original WMI credentials are unknown; some source behaviors are inferred. Malware, infrastructure, host roles and timing are substituted or consolidated in the lab.
- **Causality:** operator actions and multiple beacon registrations/relaunches create separate execution segments. Timing alone does not prove an uninterrupted end-to-end parent chain.
- **Measurement:** mapped ECS fields must be inspected before declaring telemetry absent. E7 SHA-256 was available at `file.hash.sha256`; count parity is not event-by-event reconciliation.
- **Detection validity:** ATT&CK labels and rule count are inventories. They do not measure variant coverage, recall, false-positive rate or latency.
- **Generalization:** five development replays on one lab topology are not independent production trials. Improvements in one run do not retroactively validate earlier runs.

## Reporting future evaluations

Record the source revision, software/configuration versions, run window, actual starting conditions, test input, expected observation, actual event/alert references and exclusions. Report each variant and benign control separately. Keep measurement denominators explicit; use “not measured” when the data does not support a rate.
