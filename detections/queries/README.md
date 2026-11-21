# Kibana queries (run-6)

One folder per query: the KQL, the screenshot and what it shows. Run window `2026-11-21T11:45:00Z` - `2026-11-21T12:10:00Z`.

| # | Query | Folder | Technique |
|---:|---|---|---|
| 1 | Office starts a script host | [`01-office-starts-a-script-host`](01-office-starts-a-script-host/README.md) | delivery-macro-document |
| 2 | HTA host | [`02-mshta`](02-mshta/README.md) | delivery-macro-document |
| 3 | Loader invocation | [`03-loader-invocation`](03-loader-invocation/README.md) | regsvr32-loader |
| 4 | Untrusted module load | [`04-untrusted-module-load`](04-untrusted-module-load/README.md) | regsvr32-loader |
| 5 | Script written into the agent checks | [`05-script-written-into-the-agent-checks`](05-script-written-into-the-agent-checks/README.md) | regsvr32-loader |
| 6 | Agent runs the script | [`06-agent-runs-the-script`](06-agent-runs-the-script/README.md) | agent-privilege-escalation |
| 7 | All three delivery alerts | [`07-all-three-delivery-alerts`](07-all-three-delivery-alerts/README.md) | delivery-macro-document |
| 8 | Domain group enumeration | [`08-domain-group-enumeration`](08-domain-group-enumeration/README.md) | discovery |
| 9 | Trust enumeration | [`09-trust-enumeration`](09-trust-enumeration/README.md) | discovery |
| 10 | Local group enumeration | [`10-local-group-enumeration`](10-local-group-enumeration/README.md) | discovery |
| 11 | Connectivity check | [`11-connectivity-check`](11-connectivity-check/README.md) | discovery |
| 12 | All discovery events | [`12-all-discovery-events`](12-all-discovery-events/README.md) | discovery |
| 13 | R18 alerts | [`13-r18-alerts`](13-r18-alerts/README.md) | discovery |
| 14 | LSA secret request | [`14-lsa-secret-request`](14-lsa-secret-request/README.md) | credential-access-lsa-secrets |
| 15 | Mimikatz process | [`15-mimikatz-process`](15-mimikatz-process/README.md) | credential-access-lsa-secrets |
| 16 | R05 alert | [`16-r05-alert`](16-r05-alert/README.md) | credential-access-lsa-secrets |
| 17 | Remote process creation request | [`17-remote-process-creation-request`](17-remote-process-creation-request/README.md) | wmi-lateral-movement |
| 18 | WMI provider child | [`18-wmi-provider-child`](18-wmi-provider-child/README.md) | wmi-lateral-movement |
| 19 | Network logon on FS01 | [`19-network-logon-fs01-scoped`](19-network-logon-fs01-scoped/README.md) | wmi-lateral-movement |
| 20 | WMI children on FS01 | [`20-wmi-children-on-fs01`](20-wmi-children-on-fs01/README.md) | wmi-lateral-movement |
| 21 | R07 and R08 alerts | [`21-r07-and-r08-alerts`](21-r07-and-r08-alerts/README.md) | wmi-lateral-movement |
| 22 | Remote thread into svchost | [`22-remote-thread-into-svchost`](22-remote-thread-into-svchost/README.md) | process-injection |
| 23 | Beacon module loaded | [`23-beacon-module-loaded`](23-beacon-module-loaded/README.md) | process-injection |
| 24 | Injector invocation | [`24-injector-invocation`](24-injector-invocation/README.md) | process-injection |
| 25 | R14 and R15 alerts | [`25-r14-and-r15-alerts`](25-r14-and-r15-alerts/README.md) | process-injection |
| 26 | Campaign domain lookup | [`26-campaign-domain-lookup`](26-campaign-domain-lookup/README.md) | process-injection |
| 27 | Connection to the listener | [`27-connection-to-the-listener`](27-connection-to-the-listener/README.md) | process-injection |
| 28 | svchost outbound 443 | [`28-svchost-outbound-443`](28-svchost-outbound-443/README.md) | process-injection |
| 29 | R16 and R17 alerts | [`29-r16-and-r17-alerts`](29-r16-and-r17-alerts/README.md) | process-injection |
| 30 | Boot task creation | [`30-boot-task-creation`](30-boot-task-creation/README.md) | wmi-lateral-movement |
| 31 | Task by name | [`31-task-by-name`](31-task-by-name/README.md) | wmi-lateral-movement |
| 32 | R19 alert | [`32-r19-alert`](32-r19-alert/README.md) | wmi-lateral-movement |
| 33 | rclone | [`33-rclone`](33-rclone/README.md) | rclone-exfiltration |
| 34 | Shadow copy deletion | [`34-shadow-copy-deletion`](34-shadow-copy-deletion/README.md) | conti-ransomware |
| 35 | Locker invocation | [`35-locker-invocation`](35-locker-invocation/README.md) | conti-ransomware |
| 36 | Notes written | [`36-notes-written`](36-notes-written/README.md) | conti-ransomware |
| 37 | Ransom-note extension written | [`37-ransom-note-extension-written`](37-ransom-note-extension-written/README.md) | conti-ransomware |
| 38 | R10, R11, R12 alerts | [`38-r10-r11-r12-alerts`](38-r10-r11-r12-alerts/README.md) | conti-ransomware |
| 39 | Process chain on both hosts | [`39-process-chain-on-both-hosts`](39-process-chain-on-both-hosts/README.md) | kill-chain |
| 40 | All file writes of interest | [`40-all-file-writes-of-interest`](40-all-file-writes-of-interest/README.md) | kill-chain |
| 41 | Everything the rules can see | [`41-everything-the-rules-can-see`](41-everything-the-rules-can-see/README.md) | kill-chain |
| 42 | All C0015 alerts | [`42-all-c0015-alerts`](42-all-c0015-alerts/README.md) | detections |
| 43 | Alerts per host | [`43-alerts-per-host`](43-alerts-per-host/README.md) | detections |
| 44 | One rule at a time | [`44-alerts-per-rule`](44-alerts-per-rule/README.md) | detections |

Total queries with screenshots: 44.
