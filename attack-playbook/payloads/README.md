# Payloads

| File | Phase | Purpose |
|---|---|---|
| `loader-regsvr32.c` | delivery | DLL loaded by `regsvr32`; drops the agent script |
| `agent-update.ps1` | privilege escalation | runs as SYSTEM from HealthMonitor; starts the beacon |
| `HealthMonitor.c` | privilege escalation | the agent service itself (build with mingw) |
| `macro-payload.vba` | delivery | macro that starts the HTA |
| `macro-install-docm.ps1` | delivery | installs the macro into the document |
| `macro-build-embedded.ps1` | delivery | builds the document with the macro embedded |
| `compareforfor.hta` | delivery | HTA that starts `regsvr32` |
| `fs01-task.ps1` | post-exploitation | gated steps on FS01: defences, persistence, exfil, impact |
| `ransomware-sim.c` | impact | realistic locker: skips system paths, renames data, writes notes |
| `ransomware-launcher.bat.tpl` | impact | deployment batch with the campaign argument set |
| `ransom-note.txt` | impact | note dropped in affected directories |
