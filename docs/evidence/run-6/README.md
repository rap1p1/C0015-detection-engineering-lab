# Run-6 screenshots

Captured during the run-6 manual replay. Paths are relative to this folder.

Two captures were left out on purpose because the command line in the image contained the
Administrator password in clear text: the `net use`/`copy` batch and the `wmic` invocation.
The password itself is not in the repository.

## Setup and delivery

| Image | What it shows |
|---|---|
| `setup/01-stage-sources-on-kali.png` | sources copied to Kali before the build |
| `setup/02-sliver-client-start.png` | Sliver client opened with the operator config |
| `setup/03-https-listener.png` | HTTPS listener started for `checkauj.com:443` |
| `setup/04-listener-job.png` | `jobs` showing the listener |
| `setup/05-ports.png` | 80, 443 and 31337 listening |
| `setup/06-generate-beacon.png` | shared beacon generated with `--run-at-load` |
| `setup/07-staged-files.png` | staging directory contents |
| `setup/09-healthmonitor-install.png` | `HealthMonitor` service installed and started as LocalSystem |
| `setup/10-c0015backup-service.png` | `C0015Backup` service running as `C0015\Administrator` |
| `setup/11-rules-enabled.png` | 18 C0015 rules enabled in Kibana |

## Delivery and execution

| Image | What it shows |
|---|---|
| `delivery/01-docm-download.png` | the document downloaded to the victim |
| `delivery/02-regsvr32-dialog.png` | Word with the `RegSvr32` dialog after the loader ran |
| `delivery/03-mshta-process.png` | `mshta.exe` running the staged HTA as `duc.user` |
| `delivery/04-loader-log.png` | `loader.log` showing the agent script staged in `checks` |
| `delivery/05-delivery-alerts.png` | the five delivery alerts in Kibana |

## Agent, discovery, credential

| Image | What it shows |
|---|---|
| `agent/01-agent-log.png` | `agent.log`: injector and beacon downloaded and injector started |
| `agent/02-system-session.png` | Sliver session on WS01 as SYSTEM |
| `discovery/01-use-session-whoami.png` | session selected, shell opened, `whoami` = SYSTEM |
| `discovery/02-net-nltest.png` | `net group "domain admins"` and `nltest /domain_trusts` |
| `discovery/03-ping-fs01.png` | reachability check for FS01 |
| `discovery/04-r18-alerts.png` | the R18 discovery alerts |
| `credential/01-mimikatz-secret.png` | `lsadump::secrets`; the password line is cropped out |
| `credential/02-r05-alert.png` | the R05 alert |

## Lateral movement, injection

| Image | What it shows |
|---|---|
| `lateral/01-impacket-whoami.png` | credential check against FS01 |
| `lateral/02-disable-defender.png` | `Set-MpPreference` and the resulting `False` |
| `lateral/03-r06-r08-alerts.png` | R06 and R08 alerts on FS01 |
| `lateral/04-staged-files-fs01.png` | payloads and `run-*.cmd` on FS01 |
| `lateral/05-certutil-downloads.png` | payload downloads through the C2 session |
| `lateral/06-run-command-files.png` | command files created for the WMI step |
| `injection/01-alert-burst.png` | ten alert documents from a single injection |
| `injection/02-fs01-inject-log.png` | FS01 `inject.log` with `injector done` |
