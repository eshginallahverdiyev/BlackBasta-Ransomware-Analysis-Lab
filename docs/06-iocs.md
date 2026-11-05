# 06 - Indicators of Compromise

> IOCs derived from this single sample and lab run. Network IOCs come from the ransom note (not from live C2 traffic).

## File indicators
| Type | Value |
|---|---|
| SHA-256 | `ae7c868713e1d02b4db60128c651eb1e3f6a33c02544cc4cb57c3aa6c6581b6e` |
| SHA-1 | `a996ccd0d58125bf299e89f4c03ff37afdab33fc` |
| MD5 | `53fdeb923b1890d29b8f29da77995938` |
| Imphash | `b3794746554a5701b2de3e5ea435c59b` |
| SSDEEP | `12288:M1DTMHixr1moQqUiXINDl/m1s6BQio67VlAU:AzmoQqUiXw2s6yiVxR` |
| TLSH | `T1D9C47C213581C43BD6A243B04DACDA95727DBC300F6206CBE3D45A6E5A7C5F27B329B6` |
| Rich PE header hash | `097c3efd91e657b69051326b4792cc68` |
| File size | 556,576 bytes |
| Compile timestamp | 2022-04-16 06:29:58 UTC |
| Overlay (32 B) | `02981b768d214cd8a05a2ee0f8cb76af` |

## Host indicators
| Type | Value |
|---|---|
| Ransom note | `readme.txt` written in many directories |
| Encrypted extension | `.basta` ("BASTA File") |
| Wallpaper text | "Your network is encrypted by the Black Basta group. Instructions in the file readme.txt." |
| Registry | `HKCU\Control Panel\Desktop\Wallpaper` modified |
| Registry | `HKCR\.basta` and `HKCR\.basta\DefaultIcon` creation attempted |
| Child processes | `SysWOW64\cmd.exe`, `System32\conhost.exe` spawned by the sample |
| Command line | `vssadmin.exe delete shadows /all /quiet` (embedded string) |
| Console output string | `Done time: %.4f seconds, encrypted: %.4f gb` |

## Network indicators (from ransom note)
| Type | Value |
|---|---|
| TOR negotiation site | `aazsbsgya565vlu2c6bzy6yfiebkcbtvvcytvolt33s77xypi7nypxyd.onion` (port 80) |
| Victim/company ID format | UUID, e.g. `ba7a7058-3531-4b67-bae6-d602e9110361` (unique per build/victim) |

> Do not browse `.onion` addresses from a production network. The company ID in this lab is specific to the analyzed build.

## Detection names (VirusTotal)
`Windows.Ransomware.BlackBasta` (Elastic), `Win.Ransomware.BlackBasta-9950286-0` (ClamAV), `Win32/Filecoder.BlackBasta.C` (ESET), `Trojan-Ransom.BlackBasta` (Ikarus), `Ransomware/Win.BastaCrypt.R782098` (AhnLab).

A machine-readable version is in [`../iocs/iocs.csv`](../iocs/iocs.csv).
