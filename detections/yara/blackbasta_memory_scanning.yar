/*
    Black Basta ransomware - memory / process scanning rules
    Intended for use with yara against process memory or memory dumps
    (e.g. Volatility yarascan, yara -p <pid>, EDR memory scanning).
    No PE header assumptions, because the image may be unmapped or modified.
*/

rule BlackBasta_Memory_Strings_Combo
{
    meta:
        description = "Process memory containing Black Basta ransom, crypto and shadow-copy strings"
        author      = "Malware Analysis Lab"
        date        = "2026-11-05"
        mitre_attack = "T1486, T1490"
        confidence  = "high"

    strings:
        $n1  = "Your data are stolen and encrypted" ascii wide
        $n2  = "published on TOR website" ascii wide
        $v   = "vssadmin.exe delete shadows /all /quiet" ascii wide nocase
        $c   = "expand 32-byte k" ascii
        $m   = "encrypted: %.4f gb" ascii
        $w   = "Black Basta group" ascii wide nocase

    condition:
        3 of them
}

rule BlackBasta_Memory_Onion_And_Company_ID
{
    meta:
        description = "Memory/dump containing the Black Basta note's TOR link together with the 'company id' phrase"
        author      = "Malware Analysis Lab"
        date        = "2026-11-05"
        confidence  = "medium-high"

    strings:
        $id    = "Your company id for log in" ascii wide
        $onion = /[a-z2-7]{56}\.onion/ ascii wide
        $tor   = "download and install TOR browser" ascii wide

    condition:
        $id and ($onion or $tor)
}
