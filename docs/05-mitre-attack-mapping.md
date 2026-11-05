# 05 - MITRE ATT&CK Mapping

Confidence: **High** = directly observed in dynamic telemetry; **Medium** = strong static evidence (capa/strings/imports); **Low** = sandbox/heuristic only.

| Tactic | ID | Technique | Evidence | Confidence |
|---|---|---|---|---|
| Execution | T1106 | Native API | Direct use of Win32 file/volume/process APIs (pestudio imports) | Medium |
| Execution | T1129 | Shared Modules | capa; runtime linking via PEB | Medium |
| Execution | T1059.003 | Windows Command Shell | `cmd.exe` + `conhost.exe` spawned (Procmon) | High |
| Defense Evasion | T1027 | Obfuscated Files or Information | capa: obfuscated stackstrings (3); FLOSS 12 stack strings | Medium |
| Defense Evasion | T1027.005 | Indicator Removal from Tools | capa | Medium |
| Defense Evasion | T1497.001 | Virtualization/Sandbox Evasion: System Checks | capa: VirtualBox anti-VM strings | Medium |
| Defense Evasion | T1070.004 | Indicator Removal: File Deletion | capa | Medium |
| Discovery | T1083 | File and Directory Discovery | `FindFirstFileExW`, `FindNextFileW` + massive directory traversal (Procmon) | High |
| Discovery | T1082 | System Information Discovery | capa; processor count, disk info APIs | Medium |
| Discovery | T1120 | Peripheral Device Discovery (volumes) | `FindFirstVolumeW`, `FindNextVolumeW`, `GetVolumePathNamesForVolumeNameW` | Medium |
| Impact | T1486 | Data Encrypted for Impact | `.basta` files, Salsa20/ChaCha constants | High |
| Impact | T1490 | Inhibit System Recovery | `vssadmin delete shadows /all /quiet` strings; capa | Medium (string/capability; execution of the command was not isolated in screenshots) |
| Impact | T1491.001 | Defacement: Internal Defacement | `HKCU\Control Panel\Desktop\Wallpaper` change + ransom wallpaper | High |
| Persistence / Priv. Esc. | T1547 | Boot or Logon Autostart Execution | Sandbox matrix only; service-key `RegSetValue` seen but truncated | Low |
| Defense Evasion | T1055 | Process Injection | Sandbox matrix only; **not confirmed** locally | Low |

> Low-confidence rows are listed for completeness and should be validated with a debugger or full API tracing before being used in a formal report.
