# Payloads

| File | Phase | Purpose |
|---|---|---|
| `loader-regsvr32.c` | delivery | DLL loaded by `regsvr32`; drops the agent script |
| `agent-update.ps1` | privilege escalation | runs as SYSTEM from HealthMonitor; stages `injector.dll` and `beacon.dll` and starts the injector |
| `HealthMonitor.c` | privilege escalation | the agent service itself (build with mingw) |
| `macro-payload.vba` | delivery | macro that writes `config.ini` and the HTA from base64, then starts mshta |
| `macro-install-docm.ps1` | delivery | installs the macro into the document |
| `build-macro.py` | delivery | regenerates `macro-payload.vba` from the HTA and the staging config |
| `compareforfor.hta` | delivery | HTA that starts `regsvr32`; embedded in the macro, kept as source |
| `injector.c` | injection | rundll32 DLL that loads `beacon.dll` into a SYSTEM svchost and calls `StartW` |
| `fs01-task.ps1` | post-exploitation | gated steps on FS01: defences, injection, exfil, impact |
| `ransomware-sim.c` | impact | realistic locker: skips system paths, renames data, writes notes |
| `ransomware-launcher.bat.tpl` | impact | deployment batch with the campaign argument set |
| `ransom-note.txt` | impact | note dropped in affected directories |
