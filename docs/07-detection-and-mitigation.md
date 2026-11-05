# 07 - Detection & Mitigation

## 7.1 Detection opportunities

| # | Behavior | Data source | Fidelity |
|---|---|---|---|
| 1 | `vssadmin.exe delete shadows` (also `wmic shadowcopy delete`, `wbadmin delete`, `bcdedit /set recoveryenabled no`) | Sysmon EID 1 / Security 4688 with command line | High |
| 2 | Same file name (`readme.txt`) created in hundreds of directories within seconds | Sysmon EID 11 / EDR file telemetry | High |
| 3 | Mass rename/creation of files with a new, uncommon extension (`.basta`) | Sysmon EID 11, 2 / EDR | High |
| 4 | 32-bit process under `SysWOW64\cmd.exe` spawned from an unsigned user-writable binary | Sysmon EID 1 | Medium |
| 5 | Change of `HKCU\Control Panel\Desktop\Wallpaper` by a non-system process | Sysmon EID 13 | Medium |
| 6 | Attempt to create `HKCR\.<random ext>` / `DefaultIcon` | Sysmon EID 12/13 | Medium |
| 7 | Sudden CPU spike plus very high file I/O from a single process | EDR / performance telemetry | Low-Medium |

Sigma rules for #1 and #2 are in [`detections/sigma/`](../detections/sigma/).

## 7.2 Hunting queries (examples)

**Microsoft Defender / Sentinel (KQL) - shadow copy deletion**
```kql
DeviceProcessEvents
| where FileName =~ "vssadmin.exe"
| where ProcessCommandLine has_all ("delete", "shadows")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, ProcessCommandLine
```

**Many identical ransom-note names written by one process**
```kql
DeviceFileEvents
| where ActionType == "FileCreated" and FileName =~ "readme.txt"
| summarize Dirs=dcount(FolderPath), Files=count() by DeviceName, InitiatingProcessFileName, bin(Timestamp, 1m)
| where Dirs > 50
```

## 7.3 Mitigation and hardening

1. **Backups** - 3-2-1 backups with at least one offline/immutable copy; test restore regularly.
2. **Endpoint protection** - keep EDR/AV and **Tamper Protection enabled**; enable ASR rules (e.g. "Use advanced protection against ransomware").
3. **Least privilege** - remove local admin rights; restrict `vssadmin`/`wbadmin` execution to admins (AppLocker/WDAC).
4. **Initial-access reduction** - patch internet-facing systems, enforce MFA on VPN/RDP, block macro/ISO/LNK delivery from the internet.
5. **Network segmentation** - restrict SMB and admin shares; monitor/block TOR egress.
6. **Controlled Folder Access** on high-value workstations.
7. **Incident response** - rehearsed playbook: isolate host, preserve memory, identify patient zero, rotate credentials, restore from clean backups.

## 7.4 Response checklist if this family is detected

- [ ] Isolate affected hosts from the network (do not power off if memory capture is required)
- [ ] Collect volatile data and the sample; hash it and compare to the IOCs in [06-iocs.md](06-iocs.md)
- [ ] Search for `.basta` files and `readme.txt` notes across file shares
- [ ] Look for shadow-copy deletion and preceding access/lateral-movement activity
- [ ] Reset credentials and review privileged accounts
- [ ] Restore from known-good backups; validate before reconnecting
