# Portable AnyDesk deployment

AnyDesk is dropped as a portable executable into `C:\Users\<user>\Videos` and started from there. The
directory is not on any software-installation path, which is what makes the artifact worth detecting:
a signed remote-access binary running from a media folder.

The application establishes a long-lived connection to the vendor relay infrastructure. The traffic is
legitimate and the destination ranges are registered to the vendor, so the network signal is weak on
its own; the file-system placement and the parent process are the reliable parts.

## How the lab reproduces it

The genuine portable build is copied to the Videos directory of the interactive user on the backup
server and launched from there, inside the RDP session. The lab does not use the vendor relay as a
command channel; the connection exists because the application makes it.

`tools/deploy-anydesk.ps1` copies the binary, records the hash, starts it, and reports the resulting
process and connection for the run record. `tools/remove-anydesk.ps1` removes the binary and the
per-user configuration after the run.

## Artifacts

| File | Purpose |
|---|---|
| `tools/deploy-anydesk.ps1` | Placement, launch, and evidence capture |
| `tools/remove-anydesk.ps1` | Cleanup of binary and profile data |

## Telemetry and detection

Expected events are listed in [`telemetry/README.md`](telemetry/README.md). The rule
[`detection_rules/eql/remote-access-tool-in-media-path.eql`](detection_rules/eql/remote-access-tool-in-media-path.eql)
matches a remote-access binary created and executed from `Videos`, `Music`, or `Pictures` under a user
profile.

