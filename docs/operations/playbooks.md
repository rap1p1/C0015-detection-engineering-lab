# Investigation playbooks

Three playbooks, one per case. Each assumes the analyst has the bundle open and can resolve a locator.

## P1 - Office to loader (R03)

1. **Telemetry check.** Confirm Sysmon events 1 and 7 exist for the host in the alert window. Without E7
   the alert itself cannot exist; without E1 the ancestry cannot be reconstructed.
2. **Collect.** The alert's source documents, then process creation on the host from two minutes before
   the alert.
3. **Benign check.** Office add-ins and signed installers also start script hosts. A signed module, or a
   path under `Program Files`, argues for benign.
4. **Escalate** when the module is unsigned, lives in a user-writable path, and the parent chain reaches
   a document process.
5. **Close** when the module is signed and the chain matches a known deployment.
6. **Insufficient information** when the module event exists but no process ancestry is recorded; keep
   the ticket open and record the gap.

## P2 - LSASS access (R05)

1. **Telemetry check.** Sysmon event 10 for the host; the alert cannot exist without it.
2. **Collect.** The access event, the source process creation, and any file creation in the same minute.
3. **Benign check.** Security tooling, backup agents and EDR open LSASS on a schedule. Compare the mask
   and the process provenance; a system binary under `System32` is usually benign, the same name outside
   it is not.
4. **Escalate** when the mask includes read rights and the source process has no explained origin.
5. **Close** when the process is a known agent and the mask is limited.
6. **Insufficient information** when the source process is unknown and no dump artefact is present.

## P3 - WMI remote execution (R06, R07, R18)

1. **Telemetry check.** Source side needs Sysmon 1 on the origin host; target side needs Sysmon 1 on the
   destination. A missing side halves the case.
2. **Collect.** Source invocations, target children under `WmiPrvSE.exe`, and logon events on the target
   for the same account and minute.
3. **Benign check.** Configuration management also uses WMI. Look for a scheduled cadence, a service
   account, and commands that belong to the platform.
4. **Escalate** when the invocation carries an explicit credential, runs a loader or a defence-disable
   command, and the target is a server.
5. **Close** when the account is a known management identity and the commands are part of a documented
   task.
6. **Insufficient information** when source and target events cannot be paired by account and time; say
   "correlated by content and time", not "proven".
