/*
    Black Basta ransomware - shadow copy deletion (T1490)
    Observed embedded commands (ASCII):
      C:\Windows\SysNative\vssadmin.exe delete shadows /all /quiet
      C:\Windows\System32\vssadmin.exe delete shadows /all /quiet
    Note: shadow-copy deletion is used by many ransomware families; this rule
    is intentionally combined with other indicators to limit false positives.
*/

import "pe"

rule BlackBasta_Shadow_Copy_Deletion_Commands
{
    meta:
        description = "Executable embedding both SysNative and System32 vssadmin 'delete shadows' commands"
        author      = "Malware Analysis Lab"
        date        = "2026-11-05"
        mitre_attack = "T1490"
        confidence  = "medium (generic ransomware behavior)"

    strings:
        $sysnative = "\\SysNative\\vssadmin.exe delete shadows /all /quiet" ascii nocase
        $system32  = "\\System32\\vssadmin.exe delete shadows /all /quiet" ascii nocase

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        all of them
}

rule BlackBasta_Shadow_Deletion_Plus_Ransom_Indicators
{
    meta:
        description = "vssadmin shadow deletion combined with Black Basta note/crypto indicators"
        author      = "Malware Analysis Lab"
        date        = "2026-11-05"
        mitre_attack = "T1490, T1486"
        confidence  = "high"

    strings:
        $vss   = "vssadmin.exe delete shadows /all /quiet" ascii nocase wide
        $note  = "Your data are stolen and encrypted" ascii
        $tor   = "published on TOR website" ascii
        $chacha = "expand 32-byte k" ascii
        $done  = "encrypted: %.4f gb" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        $vss and 2 of ($note, $tor, $chacha, $done)
}
