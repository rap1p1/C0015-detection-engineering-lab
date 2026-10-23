# Account model

The source report does not establish where the credentials for the WMI pivot came from. No credential
dump precedes it, and the Domain Controller is never touched. The lab therefore provisions the
credential explicitly rather than pretending to recover one, and keeps the provisioning step outside
the attack timeline so the detection surface is still complete.

| Account | Scope | Purpose |
|---|---|---|
| `C0015\duc.user` | Local administrator on WS01 | Interactive victim. Opens the document, enables the macro, owns the entry chain |
| `C0015\bk.admin` | Local administrator on FS01 | Backup server administrator. Used for the WMI pivot and the RDP session |
| `C0015\it.admin` | Domain administrator | Lab administration, DC-side changes, snapshot and restore work |
| `C0015\svc_backup` | Log on as a service on FS01 | Backup agent context, present so the backup server has a plausible service identity |
| `C0015\WS01$` | Member of local Administrators on FS01 | Machine account. Lets a SYSTEM context on WS01 reach FS01 without an explicit credential |

## Why these names

`duc.user` is the interactive victim from the original lab. `bk.admin` is new: a backup server in an
estate of this size has a dedicated administrator, and the pivot needs an account with administrative
rights on that host. Using it keeps the pivot attributable to a real identity instead of a domain
administrator, which is what the campaign implies by reaching a single high-value server.

`WS01$` is added to the local Administrators group on FS01 so that a SYSTEM context on the workstation
can create a process on the backup server through the machine account. This path exists in most
estates and requires no credential material on the host. The lab uses `bk.admin` for the documented
path and keeps the machine account as an alternative that needs no provisioning in the run.

`it.admin` is not used by the simulated operator. It exists for lab administration; its use during a
run would be an operator error and is recorded as such.

## Provisioning

`scripts/New-LabAccounts.ps1` creates the accounts, sets the group memberships, and creates the shares.
It is idempotent and takes the DC as a parameter.

```powershell
.\scripts\New-LabAccounts.ps1 -DomainController DC01 -BackupServer FS01
```

## Password handling

Passwords are not stored in the repository. The provisioning script prompts for them, and the run
sequence supplies them through the operating system credential store on the operator host. The
`stage/` directory, which is excluded from version control, may hold exported credentials for the
duration of a run.
