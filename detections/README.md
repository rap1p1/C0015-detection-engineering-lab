# Detection content

Sixteen EQL rules for Elastic Security, one source of truth in `detections/eql/`. Each rule is a
behaviour, not a single event, and each carries a MITRE ATT&CK tactic and technique in its metadata.

The previous generation had twenty rules, most of them building blocks that fired on one event and
produced hundreds of alerts in a day of ordinary activity. This set keeps the same coverage and folds
the building blocks into sequences and scoped event queries.

## Design

Rules follow the shape Sigma uses, which is also the shape Elastic documents for detection
engineering:

- a behaviour that an analyst can explain to a stakeholder, in one sentence
- a data source and a query that reads it, with the field names actually present in this pipeline
- ATT&CK tactic and technique in the metadata, not in the description text
- a severity and a risk score that mean something: `critical` only for code execution in a system
  process, credential theft, and impact
- a false-positive note in the description when the behaviour has a benign explanation

Three families:

| Family | Rules | Question it answers |
|---|---|---|
| Execution | 01, 02, 03, 08 | Did a document, a script host or a service host start a loader, and did that loader load code from a writable path? |
| Access | 04, 05, 06, 07, 09, 13 | Did something inject into a system process, read LSASS, or move to another host over WMI, NTLM or RDP? |
| Objectives | 11, 12, 14 | Is data leaving, is a note being written, is the operator looking at processes? |

## Index

| Rule | Event | ATT&CK | Severity | Hits in 3 h |
|---|---|---|---|---|
| 01 office spawns script host | Sysmon 1 sequence | T1204 | high | 3 |
| 02 script host starts loader | Sysmon 1 sequence | T1218 | high | 2 |
| 03 loader loads unsigned module | Sysmon 1 then 7 | T1574 | critical | 4 |
| 04 injection into system process | Sysmon 8 | T1055.003 | critical | 2 |
| 05 lsass credential access | Sysmon 10 | T1003.001 | critical | 1 |
| 06 wmi remote creation | Sysmon 1 | T1047 | medium | 2 |
| 07 wmi hosted loader | Sysmon 1 | T1047 | high | 2 |
| 08 service host starts loader | Sysmon 1 | T1543.003 | medium | 1 |
| 09 ntlm logon with privileges | Security 4624 then 4672 | T1550.002 | high | 0 |
| 11 cloud transfer | Sysmon 1 | T1567.002 | high | 2 |
| 12 ransom note | Sysmon 11 | T1486 | high | 5 |
| 13 rdp interactive logon | Security 4624 | T1021.001 | medium | 2 |
| 14 task manager from shell | Sysmon 1 | T1057 | low | 2 |
| 15 password spray | Security 4625 then 4624 | T1110.003 | high | 2 |
| 16 lsass protection removed | Sysmon 13 | T1562.001 | high | 0 |
| 17 discovery burst | Sysmon 1 | T1057 | medium | 36 |

The hit counts are from the run that produced `killchain/telemetry/run-2026-10-25.json`, over the
three hours that contain the whole chain. A rule that shows zero has no matching event in that
window; rule 09 needs an NTLM network logon and a privileged token for the same account inside one
minute, which the pass-the-hash step in that run produced before the rule existed.

## Tuning history

| Rule | Before | After | Why |
|---|---|---|---|
| lsass credential access | 59 alerts in 90 min | 1 in 3 h | the agent, Defender and system processes open LSASS with the same mask; excluded by image and by name |
| service host starts loader | 15 in 3 h | 1 in 3 h | Windows components call `rundll32` from System32; the rule now requires a loader from a writable path |
| ntlm network logon plus privileged logon | 200+ each | one sequence | the two events are normal on their own; requiring the pair for one account inside a minute removes the background |
| service host egress | 168 in 90 min | removed | a service host reaching the internet is normal on this build; the behaviour of interest is covered by 03 and 04 |
| dns nxdomain retry | 32 in 90 min | removed | Windows produces failed lookups constantly; without a name list the rule cannot separate signal |
| implant opens rdp | 3 false positives | removed | replaced by 13, which reads the logon event instead of a listening socket |

## Field assumptions

The queries use the Elastic Common Schema as produced by the Elastic Agent Windows integration.

| Query field | Source event | Raw field |
|---|---|---|
| `process.parent.name`, `process.entity_id` | Sysmon 1 | `ParentImage`, `ProcessGuid` |
| `winlog.event_data.Signed` | Sysmon 7 | `Signed` (string, `"false"`) |
| `winlog.event_data.TargetImage` | Sysmon 8 and 10 | same |
| `process.name` as the `E8` source | Sysmon 8 | `SourceImage` is not mapped in this pipeline |
| `winlog.event_data.GrantedAccess` | Sysmon 10 | same |
| `winlog.event_data.LogonType`, `AuthenticationPackageName` | Security 4624 | same |
| `winlog.event_data.SubjectUserName` | Security 4672 | same |
| `file.name`, `file.extension` | Sysmon 11 | `TargetFilename` |

Two fields decide whether a rule fires at all, and both are configuration-dependent:

- Sysmon 8 must be enabled. In the profile shipped here it is enabled through an empty `exclude`
  group in the rule set.
- Sysmon 7 must cover the directory the module is loaded from. The balanced profile scopes
  `ImageLoad` to staging paths; the extension masquerade puts the file under `C:\Users\Public`, which
  the profile includes.

## References used while writing the rules

SigmaHQ rules with the same intent were read as prior art; the mapping is in
[`docs/sigma-reference.md`](../docs/sigma-reference.md). The style follows the Sigma specification
(`title`, `description`, `level`, `tags` with `attack.*`) and Elastic's own detection-rule guidance,
which is the same shape: one behaviour per rule, ATT&CK metadata, and a documented false-positive
surface.

