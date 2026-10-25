# SigmaHQ reference rules

The detection content is EQL and runs in Elastic Security. Before writing each rule the closest
upstream Sigma rule was read to borrow field selection and false-positive boundaries. No Sigma file is
shipped here; the links are prior art, the EQL under `detections/eql/` is the implementation.

| Rule | SigmaHQ rule |
|---|---|
| 01 office spawns script host | [`proc_creation_win_office_susp_child_processes.yml`](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_office_susp_child_processes.yml) |
| 02 script host starts loader | [`proc_creation_win_mshta_susp_execution.yml`](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_mshta_susp_execution.yml), [`proc_creation_win_regsvr32_susp_parent.yml`](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_regsvr32_susp_parent.yml) |
| 03 loader loads unsigned module | [`proc_creation_win_rundll32_susp_execution_with_image_extension.yml`](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_rundll32_susp_execution_with_image_extension.yml) |
| 04 injection into system process | [`proc_access_win_svchost_susp_access_request.yml`](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_access/proc_access_win_svchost_susp_access_request.yml) |
| 05 lsass credential access | [`proc_access_win_lsass_susp_access_flag.yml`](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_access/proc_access_win_lsass_susp_access_flag.yml) |
| 06 wmi remote creation | [`proc_creation_win_wmic_remote_execution.yml`](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_wmic_remote_execution.yml) |
| 07 wmi hosted loader | [`proc_creation_win_wmiprvse_spawning_process.yml`](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_wmiprvse_spawning_process.yml) |
| 08 service host starts loader | [`proc_creation_win_svchost_uncommon_command_line_flags.yml`](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_svchost_uncommon_command_line_flags.yml) |
| 09 ntlm logon with privileges | [`win_security_susp_logon_explicit_credentials.yml`](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/security/win_security_susp_logon_explicit_credentials.yml) |
| 11 cloud transfer | [`proc_creation_win_pua_rclone_execution.yml`](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_pua_rclone_execution.yml) |
| 12 ransom note | [`proc_creation_win_malware_conti_ransomware_commands.yml`](https://github.com/SigmaHQ/sigma/blob/master/rules-emerging-threats/2021/Malware/Conti/proc_creation_win_malware_conti_ransomware_commands.yml) |
| 13 rdp interactive logon | [`proc_creation_win_svchost_termserv_proc_spawn.yml`](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_svchost_termserv_proc_spawn.yml) |
| 14 task manager from shell | no direct upstream rule; modelled on the ATT&CK technique T1057 and the campaign note about `taskmgr /4` |
| 15 password spray | no verified upstream path at the time of writing; the sequence follows the ATT&CK technique T1110.003 |
| 16 lsass protection removed | no verified upstream path at the time of writing; the registry value is documented by Microsoft |

Two rules have no upstream link. They are marked here rather than given a path that may not resolve.

## Differences from upstream

- The parent-image sets include `winlogon.exe`, which upstream rules do not treat as a shell parent.
  That edge is specific to this campaign.
- The unsigned-image rule keys on the load path, not the extension, because the masquerade defeats
  extension checks.
- The WMI rules keep the target-side `WmiPrvSE.exe` edge and the source-side `wmic /node:` command line
  separate, so either half can fire alone.
- The impact rule accepts any binary ending in `_locker.exe` and matches the argument set, which
  survives a rename.
