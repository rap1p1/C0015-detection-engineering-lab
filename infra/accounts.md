# Account model

The scenario uses two identities and nothing else.

| Account | Type | Rights used | Role |
|---|---|---|---|
| `C0015\duc.user` | domain user, standard | member of `Remote Desktop Users` on WS01; **no** local admin | opens the document, runs the loader |
| `C0015\Administrator` | domain administrator (RID 500, built-in) | full domain admin | recovered from LSA secrets, then used for WMI and the FS01 beacon |

Local `SYSTEM` runs the agent service, the beacon and the ransomware; its network identity is the machine
account (`WS01$`, `FS01$`).

## What is deliberately not provisioned

`helpdesk`, `IT-Support`, `it.admin`, `bk.admin`, `svc_backup` and the `WS01$` local-admin grant are gone.
The earlier design used them to make the lateral movement work; the current chain does not need a second
intermediate identity.

## Where the administrator password comes from

The one-time maintenance task runs as `C0015\Administrator`. Task Scheduler stores the password as an LSA
secret, and the attacker reads it with `mimikatz lsadump::secrets` after the agent gives them SYSTEM. The
lab does not place the password on disk in plaintext.

## Provisioning

[`scripts/New-LabAccounts.ps1`](scripts/New-LabAccounts.ps1) creates `duc.user`, adds it to the workstation
`Remote Desktop Users` group and sets the password. `Administrator` exists with the domain; its password is
set during domain creation and is entered interactively when the maintenance task is created.
