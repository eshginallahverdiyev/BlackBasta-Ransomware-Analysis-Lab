/*
    Black Basta ransomware - PE structure heuristics
    Based on pestudio/DIE observations: PE32 console, MSVC 14.31 (VS2022),
    five sections (.text .rdata .data .rsrc .reloc), tiny .rsrc (manifest only),
    32-byte overlay, asInvoker manifest, ~540 KB.
*/

import "pe"

rule BlackBasta_PE_Structure_Heuristic
{
    meta:
        description = "Unpacked 32-bit MSVC console PE with the section layout and 32-byte overlay seen in Black Basta"
        author      = "Malware Analysis Lab"
        date        = "2026-11-05"
        confidence  = "low-medium (structural heuristic; use with string rules)"
        note        = "Overlay value is not used - it is expected to differ between builds"

    condition:
        uint16(0) == 0x5A4D and
        pe.is_pe and
        not pe.is_64bit() and
        pe.subsystem == pe.SUBSYSTEM_WINDOWS_CUI and
        pe.number_of_sections == 5 and
        pe.sections[0].name == ".text" and
        pe.sections[1].name == ".rdata" and
        pe.sections[2].name == ".data" and
        pe.sections[3].name == ".rsrc" and
        pe.sections[4].name == ".reloc" and
        pe.sections[3].raw_data_size <= 1024 and
        pe.overlay.size == 32 and
        filesize > 400KB and filesize < 800KB and
        pe.linker_version.major == 14
}

rule BlackBasta_PE_Imports_FileAndVolume_Enumeration
{
    meta:
        description = "PE importing the volume/file enumeration, rename and device I/O APIs flagged in the Black Basta sample"
        author      = "Malware Analysis Lab"
        date        = "2026-11-05"
        mitre_attack = "T1083, T1120"
        confidence  = "low (ransomware-typical API set; combine with other rules)"

    condition:
        uint16(0) == 0x5A4D and
        pe.is_pe and
        not pe.is_64bit() and
        pe.imports("kernel32.dll", "FindFirstVolumeW") and
        pe.imports("kernel32.dll", "FindNextVolumeW") and
        pe.imports("kernel32.dll", "FindVolumeClose") and
        pe.imports("kernel32.dll", "GetVolumePathNamesForVolumeNameW") and
        pe.imports("kernel32.dll", "FindFirstFileExW") and
        pe.imports("kernel32.dll", "FindNextFileW") and
        pe.imports("kernel32.dll", "MoveFileW") and
        pe.imports("kernel32.dll", "DeviceIoControl") and
        pe.imports("kernel32.dll", "SetEnvironmentVariableW")
}
