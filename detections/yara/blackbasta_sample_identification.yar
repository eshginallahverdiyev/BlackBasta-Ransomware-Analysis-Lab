/*
    Black Basta ransomware - sample identification rules
    Sample: BlackBasta.exe
    SHA-256: ae7c868713e1d02b4db60128c651eb1e3f6a33c02544cc4cb57c3aa6c6581b6e
    Source : lab analysis (FLARE-VM, VMware) - see README.md
    NOTE   : Hash/imphash rules match THIS build only. Use the behavioral and
             string rules for family-level detection.
*/

import "pe"
import "hash"

rule BlackBasta_Lab_Sample_Exact_Hash
{
    meta:
        description = "Exact match for the analyzed Black Basta sample (SHA-256 / MD5)"
        author      = "Malware Analysis Lab"
        date        = "2026-11-05"
        reference   = "README.md"
        sha256      = "ae7c868713e1d02b4db60128c651eb1e3f6a33c02544cc4cb57c3aa6c6581b6e"
        md5         = "53fdeb923b1890d29b8f29da77995938"
        mitre_attack = "T1486"
        confidence  = "high (single build)"
        tlp         = "WHITE"

    condition:
        uint16(0) == 0x5A4D and
        filesize == 556576 and
        (
            hash.sha256(0, filesize) == "ae7c868713e1d02b4db60128c651eb1e3f6a33c02544cc4cb57c3aa6c6581b6e" or
            hash.md5(0, filesize)    == "53fdeb923b1890d29b8f29da77995938"
        )
}

rule BlackBasta_Lab_Sample_Imphash
{
    meta:
        description = "PE with the imphash observed in the analyzed Black Basta build"
        author      = "Malware Analysis Lab"
        date        = "2026-11-05"
        imphash     = "b3794746554a5701b2de3e5ea435c59b"
        confidence  = "medium (imphash can collide with builds sharing the same import set)"

    condition:
        uint16(0) == 0x5A4D and
        pe.is_pe and
        pe.imphash() == "b3794746554a5701b2de3e5ea435c59b"
}

rule BlackBasta_Lab_Sample_PE_Metadata
{
    meta:
        description = "PE32 with the compile timestamp, size and structure observed in the analyzed sample"
        author      = "Malware Analysis Lab"
        date        = "2026-11-05"
        compile_ts  = "2022-04-16 06:29:58 UTC"
        confidence  = "medium"

    condition:
        uint16(0) == 0x5A4D and
        pe.is_pe and
        not pe.is_64bit() and
        pe.subsystem == pe.SUBSYSTEM_WINDOWS_CUI and
        pe.timestamp == 1650090598 and
        pe.number_of_sections == 5 and
        filesize > 500KB and filesize < 600KB
}
