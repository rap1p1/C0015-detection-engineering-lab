# Detection content

Rules are stored twice on purpose: once beside the technique they describe, and once here when they
apply to more than one stage.

```
detections/
├── sigma/       cross-technique Sigma rules
├── suricata/    network rules for the C2 profile and the exfiltration destination
└── yara/        file rules for the beacon module
```

Per-technique rules live in `techniques/<name>/detection_rules/`. The table below is the index; the
count is derived from the files in the tree.

| Technique | Rule | Signal |
|---|---|---|
| macro-document-delivery | `sigma/office-spawns-cmd.yml` | Office process starts a shell or script host |
| hta-proxy-execution | `sigma/mshta-downloads-and-executes.yml` | mshta starts a module loader |
| regsvr32-module-execution | `sigma/regsvr32-unsigned-module-user-path.yml` | unsigned module loaded from a user path |
| bazar-svchost-stage | `sigma/svchost-spawns-rundll32.yml` | service host starts the loader |
| bazar-svchost-stage | `sigma/dns-nxdomain-beacon-retry.yml` | repeated lookups for non-existent names |
| winlogon-injection | `sigma/rundll32-injects-system-process.yml` | thread created in a system process |
| winlogon-injection | `sigma/winlogon-spawns-shell.yml` | logon process starts a shell |
| svchost-injection | `sigma/service-host-egress.yml` | service host opens an outbound connection |
| wmi-remote-process-creation | `sigma/wmiprvse-spawns-rundll32.yml` | provider host starts the loader |
| wmi-remote-process-creation | `sigma/wmic-process-create-rundll32.yml` | remote process creation with a loader |
| lolbin-discovery | `sigma/discovery-lolbin-burst.yml` | several discovery binaries in a short window |
| share-enumeration | `sigma/powerview-sharefinder-cradle.yml` | download cradle plus Invoke-ShareFinder |
| rdp-lateral-movement | `sigma/beacon-process-opens-rdp.yml` | non-client process opens 3389 |
| rdp-lateral-movement | `sigma/rdp-type10-logon.yml` | interactive logon on the target |
| anydesk-deployment | `sigma/remote-access-tool-in-user-media-path.yml` | remote-access tool in a media directory |
| processhacker-lsass-access | `sigma/lsass-access-read-mask.yml` | LSASS handle with read rights |
| rclone-exfiltration | `sigma/rclone-to-cloud-storage.yml` | throttled transfer to a cloud remote |
| conti-style-impact | `sigma/locker-binary-argument-set.yml` | locker argument combination |
| conti-style-impact | `sigma/ransom-note-spread.yml` | note written to many directories |
| cross-technique | `sigma/rundll32-loads-unsigned-module-from-programdata.yml` | loader + unsigned module outside Program Files |

Network and file rules:

| File | Covers |
|---|---|
| `suricata/c0015-cobalt-strike-profile.rules` | jQuery profile URIs, certificate subject, unresolved fallback domain, MEGA API |
| `yara/c0015-go-beacon.yar` | Go beacon DLL by runtime and import strings |

Field names in the Sigma rules follow the Elastic Common Schema as produced by the Elastic Agent
Windows integration for Sysmon. `create_remote_thread`, `process_access`, `dns_query`, `image_load`,
`file_event`, and `registry_set` map to Sysmon events 8, 10, 22, 7, 11, and 13.
