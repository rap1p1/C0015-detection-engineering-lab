# Detection content

Rules are EQL queries for Elastic Security. Each technique folder carries its own rules; this folder
holds the index and the cross-technique material.

```
detections/
├── eql/         rules that span more than one technique
└── README.md    index, field assumptions, and the SigmaHQ references
```

There is no second rule language in the tree. Sigma rules were read as prior art while the queries were
written; the mapping, with links into the SigmaHQ repository, is in
[`docs/sigma-reference.md`](../docs/sigma-reference.md).

## Index

| Technique | Rule | Signal | Level |
|---|---|---|---|
| macro-document-delivery | [`office-spawns-shell.eql`](../techniques/macro-document-delivery/detection_rules/eql/office-spawns-shell.eql) | Office process starts a shell or script host | medium |
| hta-proxy-execution | [`mshta-spawns-loader.eql`](../techniques/hta-proxy-execution/detection_rules/eql/mshta-spawns-loader.eql) | mshta starts regsvr32 or rundll32 | high |
| regsvr32-module-execution | [`regsvr32-unsigned-image.eql`](../techniques/regsvr32-module-execution/detection_rules/eql/regsvr32-unsigned-image.eql) | regsvr32 loads an unsigned image from a writable path | high |
| bazar-svchost-stage | [`svchost-spawns-rundll32.eql`](../techniques/bazar-svchost-stage/detection_rules/eql/svchost-spawns-rundll32.eql) | service host starts the loader | high |
| winlogon-injection | [`thread-into-system-process.eql`](../techniques/winlogon-injection/detection_rules/eql/thread-into-system-process.eql) | remote thread created in a system process | critical |
| winlogon-injection | [`winlogon-spawns-shell.eql`](../techniques/winlogon-injection/detection_rules/eql/winlogon-spawns-shell.eql) | logon process starts a shell or discovery binary | critical |
| svchost-injection | [`service-host-egress.eql`](../techniques/svchost-injection/detection_rules/eql/service-host-egress.eql) | service host opens an outbound connection | medium |
| wmi-remote-process-creation | [`wmiprvse-spawns-loader.eql`](../techniques/wmi-remote-process-creation/detection_rules/eql/wmiprvse-spawns-loader.eql) | provider host creates the loader | high |
| wmi-remote-process-creation | [`wmic-remote-process-create.eql`](../techniques/wmi-remote-process-creation/detection_rules/eql/wmic-remote-process-create.eql) | remote process creation through wmic | high |
| lolbin-discovery | [`winlogon-discovery-burst.eql`](../techniques/lolbin-discovery/detection_rules/eql/winlogon-discovery-burst.eql) | winlogon to cmd to discovery binary | high |
| share-enumeration | [`sharefinder-cradle.eql`](../techniques/share-enumeration/detection_rules/eql/sharefinder-cradle.eql) | download cradle plus Invoke-ShareFinder | high |
| rdp-lateral-movement | [`implant-opens-rdp.eql`](../techniques/rdp-lateral-movement/detection_rules/eql/implant-opens-rdp.eql) | non-client process opens 3389 | high |
| rdp-lateral-movement | [`rdp-type10-logon.eql`](../techniques/rdp-lateral-movement/detection_rules/eql/rdp-type10-logon.eql) | interactive logon on the target | low |
| anydesk-deployment | [`remote-access-tool-in-media-path.eql`](../techniques/anydesk-deployment/detection_rules/eql/remote-access-tool-in-media-path.eql) | remote-access tool in a media directory | high |
| processhacker-lsass-access | [`lsass-access-read-mask.eql`](../techniques/processhacker-lsass-access/detection_rules/eql/lsass-access-read-mask.eql) | LSASS handle with read rights | critical |
| rclone-exfiltration | [`rclone-cloud-transfer.eql`](../techniques/rclone-exfiltration/detection_rules/eql/rclone-cloud-transfer.eql) | throttled transfer to a cloud remote | high |
| conti-style-impact | [`locker-argument-set.eql`](../techniques/conti-style-impact/detection_rules/eql/locker-argument-set.eql) | locker argument combination | critical |
| conti-style-impact | [`ransom-note-creation.eql`](../techniques/conti-style-impact/detection_rules/eql/ransom-note-creation.eql) | note written per directory | high |
| cross-technique | [`detections/eql/`](eql/) | loader plus unsigned module outside Program Files | high |

## Field assumptions

The queries use the Elastic Common Schema as produced by the Elastic Agent Windows integration:

| Query field | Source event | Raw field |
|---|---|---|
| `process.parent.name`, `process.entity_id` | Sysmon 1 | `winlog.event_data.ParentImage`, `ProcessGuid` |
| `file.code_signature.signed` | Sysmon 7 | `winlog.event_data.Signed` |
| `winlog.event_data.SourceImage`, `TargetImage` | Sysmon 8 and 10 | same |
| `winlog.event_data.GrantedAccess` | Sysmon 10 | same |
| `winlog.event_data.LogonType` | Security 4624 | same |
| `dns.question.name` | Sysmon 22 | `QueryName` |

Two fields decide whether a rule fires at all, and both are configuration-dependent:

- Sysmon event 8 must be enabled. In the profile shipped here it is enabled through an empty `exclude`
  group in the rule set.
- Sysmon event 7 must cover the directory the module is loaded from. The balanced profile scopes
  `ImageLoad` to staging paths; the extension masquerade puts the file under `C:\Users\Public`, which
  the profile includes.

## Threshold rules

Two behaviours need a count rather than a single event: the note spread during impact and the retry
loop of a beacon whose infrastructure is gone. Both are expressed as Elastic threshold rules over the
EQL above, grouped by `host.name` and `file.path` or by `process.entity_id`.
