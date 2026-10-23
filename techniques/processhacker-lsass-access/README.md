# LSASS access through ProcessHacker

ProcessHacker is dropped in the root of `C:` and started from the RDP session. The tool is used to
open `lsass.exe` and write a memory dump. The report records the process access and the tool
placement, and states that the dump is likely but not confirmed; no credential material was recovered
in the source investigation.

The access mask is the discriminating field. A tool that opens `lsass.exe` with query rights only
produces a low-value event; a tool that reads process memory produces a mask containing
`PROCESS_VM_READ` and is the pattern worth alerting on.

## How the lab reproduces it

The lab performs the confirmed part literally and the uncertain part explicitly:

1. ProcessHacker is placed at `C:\ProcessHacker.exe` and started from the interactive session.
2. A dump of `lsass.exe` is written to `C:\ProgramData\lsass.dmp`.
3. The dump is parsed offline with Mimikatz (`sekurlsa::minidump`), so the credential material is
   produced by the tool the operator would use, not by the dumper.

Both the access and the dump are recorded, which closes the gap left by the source report. Credential
material stays in the run and is never written to the repository; the dump is deleted at the end of
the run.

`tools/processhacker-dump.md` lists the GUI steps and the expected event fields.
`tools/mimikatz-minidump.txt` records the offline parsing command.

## Artifacts

| File | Purpose |
|---|---|
| `tools/processhacker-dump.md` | GUI dump procedure and event expectations |
| `tools/mimikatz-minidump.txt` | Offline parsing of the dump |

## Telemetry and detection

Expected events are listed in [`telemetry/README.md`](telemetry/README.md). The rule
[`detection_rules/sigma/lsass-access-read-mask.yml`](detection_rules/sigma/lsass-access-read-mask.yml)
matches a handle request against `lsass.exe` whose granted access includes read rights, excluding the
known system consumers.
