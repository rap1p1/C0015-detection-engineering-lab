# Document and macro

## Tooling

```text
decree-08.03.2021.docm opened as C0015\duc.user
macro writes C:\Users\Public\C0015\config.ini and compareforfor.hta
macro starts: mshta.exe C:\Users\Public\C0015\compareforfor.hta
```

| | |
|---|---|
| Chain phase | Document and macro |
| Account | duc.user |
| What happens | WINWORD.EXE runs the macro, which writes config.ini and compareforfor.hta into %PUBLIC%\C0015 and starts mshta on the HTA |
| Telemetry | Sysmon 1 (process create), Office macro telemetry |
| Detection | R01 |
| Payload / tooling | macro-payload.vba (carries the HTA and config as base64), macro-install-docm.ps1 |

## How the lab reproduces it

See [`attack-playbook/README.md`](../../../attack-playbook/README.md) for the ordered steps, the exact
commands and the checks after each step. Anything this phase writes is listed in
[`attack-playbook/payloads`](../../../attack-playbook/payloads/README.md).

## Evidence

![Document downloaded on WS01](../../../docs/evidence/run-6/delivery/01-docm-download.png)
The `.docm` downloaded to the public desktop on WS01.

![Delivery alerts](../../../docs/evidence/run-6/delivery/05-delivery-alerts.png)
R01, R02 and R03 in one alert view.

Run 6, 2026-11-21, WS01. The document was opened by the autologon `duc.user` session and the whole
delivery ran in under seven seconds.

| UTC | Event | Locator | Excerpt |
|---|---|---|---|
| 11:48:05.842 | E1 | `AaH97-2TxY-KOnGPUa0V` | `"C:\Program Files\Microsoft Office\Root\Office16\WINWORD.EXE"  "C:\Users\Public\Desktop\decree-08.03.2021.docm"` (parent `cmd.exe`) |
| 11:48:10.978 | E1 | `AaH97-2TxY-KOnGPUq0_` | `mshta.exe  "C:\Users\Public\C0015\compareforfor.hta"` (parent `WINWORD.EXE`) |
| 11:48:12.233 | E1 | `AaH97-2TxY-KOnGPUq1e` | `regsvr32.exe  "C:\Users\Public\compareForfor.jpg"` (parent `mshta.exe`) |
| 11:48:12.285 | E7 | `AaH97-2TxY-KOnGPUq1n` | `regsvr32.exe` loads `C:\Users\Public\compareForfor.jpg`, `Signed=false`, user `duc.user` |
| 11:48:12.295 | E11 | `AaH97-2TxY-KOnGPUq1o` | `regsvr32.exe` writes `C:\ProgramData\HealthMonitor\checks\loader.log` |
| 11:48:12.427 | E11 | `AaH97-2TxY-KOnGPUq1y` | `regsvr32.exe` writes `C:\ProgramData\HealthMonitor\checks\update.ps1` |

The last two are the hand-off to the agent phase: the loader drops its script into the directory the
HealthMonitor service executes.

### Query screenshots (run-6)

![Query 1](../../../detections/queries/01-office-starts-a-script-host/screenshot.jpg)

Office starts a script host: `WINWORD.EXE` -> `mshta.exe`, `ws01`.

![Query 2](../../../detections/queries/02-mshta/screenshot.jpg)

The HTA host: `mshta.exe` running `compareforfor.hta`, `ws01`.

![Query 7](../../../detections/queries/07-all-three-delivery-alerts/screenshot.jpg)

All three delivery alerts (R01, R02, R03) in the window.
