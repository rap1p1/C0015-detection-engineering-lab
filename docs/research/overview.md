# Research overview and foundations

[Reading guide](../README.md) · Next: [campaign mapping](campaign-mapping.md)

## Research objective

Determine which behaviors in the published C0015 intrusion can be represented in a controlled Windows/AD laboratory, which observables support detection, and where the laboratory evidence stops short of historical equivalence.

## Research questions and evaluation material

| Question | Method | Evaluation record |
|---|---|---|
| RQ1. Which reported procedures can be represented, and with what substitutions? | Map each historical claim to a source, a lab stage and a fidelity boundary. | [Campaign mapping](campaign-mapping.md), [telemetry comparison](telemetry-comparison.md) |
| RQ2. Can phase handoffs be traced across WS01 and FS01? | Combine same-host process identities, authentication context, server receipts and run-scoped artifacts. | RUN-09 [ledger](../../evidence/runs/RUN-20261002-09/RUN-20261002-09.json), [correlation design](../detection/correlation.md) |
| RQ3. Which detection patterns have recorded operational support? | Inspect query/export definitions and run-specific event and alert references. | [Catalogue](../../detections/README.md), RUN-07 tuning report and RUN-09 report |
| RQ4. Which claims remain incomplete? | Compare acceptance assertions with stage statuses and missing evidence. | [Validation and limitations](../validation/README.md) |

## Conceptual foundations

**Campaign, tactic, technique and procedure.** ATT&CK supplies a vocabulary for the adversary's objective and behavior. A procedure is a concrete implementation in a particular intrusion. The same technique can have multiple procedures with different observables; one working lab example cannot establish coverage of every procedure. [C1, C2](references.md)

**Detection engineering.** A detection starts with a behavior of interest and required data, then a query and its execution configuration. Evaluation needs evidence that the data arrived, the predicate matched the intended behavior and the alert was produced under the stated schedule. A technique tag or a query file alone does not establish that sequence. The repository's [catalogue](../../detections/README.md) and [validation guide](../validation/README.md) make these stages inspectable.

**Telemetry and causality.** Process creation and module loading describe different actions. ProcessGuid/entity joins belong to one host; LogonId joins belong to the relevant host/session context. A network connection supports connectivity, while receiver-side records and hashes support transfer assertions. Event semantics come from [Sysmon](references.md); concrete observations come from run records.

**Reconstruction fidelity.** This study distinguishes observed, inferred and unknown source claims from surrogates and supplemental lab techniques. The lab consolidates historical victim roles into WS01/FS01, compresses the timeline, substitutes internal services and includes operator-driven actions. No complete original victim topology or original raw campaign dataset is claimed.

## Study design

The retained dataset comprises five runs, RUN-20261002-05 through -09. RUN-09 is the latest execution reference; RUN-07 is the tuning reference. These iterations are not independent randomized trials, and their configurations differ. Report per-run results instead of computing a pooled success rate.

The reproducibility unit is a **run plus its ledger, configuration context, source revision, artifacts and evaluation method**. A Git commit identifies implementation state; the run report supplies the observation window. UTC source-event time must remain distinguishable from alert time and later analysis time.

## Contribution and scope

The contribution is the traceable connection between a published intrusion narrative, a lab stage map, telemetry-dependent detections and recorded evidence. Production detection accuracy, antivirus evasion, original malware execution and complete historical reproduction are outside the demonstrated scope. See the [full evaluation boundaries](../validation/README.md).
