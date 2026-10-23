# SigmaHQ reference rules

The detection content in this repository is written in EQL and runs in Elastic Security. Before
writing each rule, the corresponding upstream Sigma rule was read to borrow the field selection and the
false-positive boundaries. No Sigma file is shipped here; the links below are the prior art, and the
EQL under `techniques/<name>/detection_rules/eql/` is the implementation.

Each path resolves in the SigmaHQ repository. The table lists the rule that informed the local rule,
not a rule that is bundled.

| Technique | SigmaHQ rule |
|---|---|
| macro-document-delivery | [`proc_creation_win_office_susp_child_processes.yml`](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_office_susp_child_processes.yml) |
| hta-proxy-execution | [`proc_creation_win_mshta_susp_execution.yml`](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_mshta_susp_execution.yml), [`proc_creation_win_mshta_http.yml`](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_mshta_http.yml) |
| regsvr32-module-execution | [`proc_creation_win_regsvr32_uncommon_extension.yml`](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_regsvr32_uncommon_extension.yml), [`proc_creation_win_regsvr32_susp_parent.yml`](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_regsvr32_susp_parent.yml) |
| bazar-svchost-stage | [`proc_creation_win_svchost_uncommon_parent_process.yml`](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_svchost_uncommon_parent_process.yml), [`proc_creation_win_svchost_uncommon_command_line_flags.yml`](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_svchost_uncommon_command_line_flags.yml) |
| winlogon-injection | [`proc_creation_win_hktl_cobaltstrike_load_by_rundll32.yml`](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_hktl_cobaltstrike_load_by_rundll32.yml), [`proc_access_win_svchost_susp_access_request.yml`](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_access/proc_access_win_svchost_susp_access_request.yml) |
| svchost-injection | [`proc_access_win_svchost_susp_access_request.yml`](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_access/proc_access_win_svchost_susp_access_request.yml), [`proc_access_win_svchost_credential_dumping.yml`](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_access/proc_access_win_svchost_credential_dumping.yml) |
| wmi-remote-process-creation | [`proc_creation_win_wmiprvse_spawning_process.yml`](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_wmiprvse_spawning_process.yml), [`proc_creation_win_wmic_process_creation.yml`](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_wmic_process_creation.yml), [`proc_creation_win_wmic_remote_execution.yml`](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_wmic_remote_execution.yml) |
| lolbin-discovery | [`proc_creation_win_net_view_share_and_sessions_enum.yml`](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_net_view_share_and_sessions_enum.yml) |
| share-enumeration | [`win_security_smb_file_creation_admin_shares.yml`](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/security/win_security_smb_file_creation_admin_shares.yml) |
| rdp-lateral-movement | [`proc_creation_win_svchost_termserv_proc_spawn.yml`](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_svchost_termserv_proc_spawn.yml) |
| anydesk-deployment | [`proc_creation_win_remote_access_tools_anydesk_susp_exec.yml`](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_remote_access_tools_anydesk_susp_exec.yml), [`file_event_win_anydesk_artefact.yml`](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/file/file_event/file_event_win_anydesk_artefact.yml) |
| processhacker-lsass-access | [`proc_access_win_lsass_susp_access_flag.yml`](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_access/proc_access_win_lsass_susp_access_flag.yml), [`win_security_susp_lsass_dump_generic.yml`](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/security/win_security_susp_lsass_dump_generic.yml) |
| rclone-exfiltration | [`proc_creation_win_pua_rclone_execution.yml`](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_pua_rclone_execution.yml), [`file_event_win_rclone_config_files.yml`](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/file/file_event/file_event_win_rclone_config_files.yml) |
| conti-style-impact | [`proc_creation_win_malware_conti_ransomware_commands.yml`](https://github.com/SigmaHQ/sigma/blob/master/rules-emerging-threats/2021/Malware/Conti/proc_creation_win_malware_conti_ransomware_commands.yml), [`proc_creation_win_malware_conti.yml`](https://github.com/SigmaHQ/sigma/blob/master/rules-emerging-threats/2021/Malware/Conti/proc_creation_win_malware_conti.yml) |
| cross-technique | [`proc_creation_win_rundll32_susp_execution_with_image_extension.yml`](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_rundll32_susp_execution_with_image_extension.yml) |

## Differences from the upstream rules

The upstream rules target any estate. The local rules are narrower in three places and wider in one:

- The parent-image sets include `winlogon.exe`, which the upstream rules do not treat as a shell
  parent. That edge is specific to this campaign.
- The unsigned-image rule keys on the load path rather than on the file extension, because the
  masquerade defeats extension checks.
- The WMI rules keep the target-side `WmiPrvSE.exe` edge and the source-side `wmic /node:` command line
  separate, so either half can fire alone.
- The impact rule accepts any binary name ending in `_locker.exe` and matches on the argument set,
  which survives a rename of the loader.
