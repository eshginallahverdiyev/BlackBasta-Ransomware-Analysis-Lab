/*
    Black Basta ransomware - broader / generic hunting rules
    These are lower-confidence, wider-net rules for threat hunting and
    retro-hunting. Expect more false positives than the family rules.
*/

import "pe"
import "math"

rule Hunt_Ransomware_VSSAdmin_Deletion_Plus_Enumeration
{
    meta:
        description = "32-bit PE embedding vssadmin shadow deletion and importing volume + file enumeration APIs"
        author      = "Malware Analysis Lab"
        date        = "2026-11-05"
        mitre_attack = "T1490, T1083, T1120"
        confidence  = "low-medium"

    strings:
        $vss = "vssadmin.exe delete shadows" ascii wide nocase

    condition:
        uint16(0) == 0x5A4D and
        pe.is_pe and
        filesize < 5MB and
        $vss and
        pe.imports("kernel32.dll", "FindFirstVolumeW") and
        pe.imports("kernel32.dll", "FindFirstFileExW")
}

rule Hunt_Ransomware_Note_Template_Embedded_Generic
{
    meta:
        description = "Executables embedding double-extortion note wording (stolen + encrypted + TOR + free test decryption)"
        author      = "Malware Analysis Lab"
        date        = "2026-11-05"
        mitre_attack = "T1486"
        confidence  = "medium"

    strings:
        $a = "stolen and encrypted" ascii wide nocase
        $b = "TOR" ascii wide fullword
        $c = "decrypt one file for free" ascii wide nocase
        $d = ".onion" ascii wide nocase
        $e = "company id" ascii wide nocase

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        3 of them
}

rule Hunt_Ransomware_Stream_Cipher_Constant_With_Bignum
{
    meta:
        description = "Small PE with Salsa/ChaCha constant and GMP big-number library traces (symmetric + RSA-style hybrid scheme)"
        author      = "Malware Analysis Lab"
        date        = "2026-11-05"
        mitre_attack = "T1486"
        confidence  = "low (legitimate crypto software also matches)"

    strings:
        $c   = "expand 32-byte k" ascii
        $gmp = "gmp_default_alloc" ascii
        $vss = "delete shadows" ascii nocase wide

    condition:
        uint16(0) == 0x5A4D and
        pe.is_pe and
        filesize < 3MB and
        $c and $gmp and $vss
}

rule Hunt_Unpacked_Small_Console_PE_With_Stackstrings_And_Overlay
{
    meta:
        description = "Unpacked MSVC console PE with tiny resources, small trailing overlay and ransom-related imports (Black Basta-like structure)"
        author      = "Malware Analysis Lab"
        date        = "2026-11-05"
        confidence  = "low (structural hunt only)"

    condition:
        uint16(0) == 0x5A4D and
        pe.is_pe and
        pe.subsystem == pe.SUBSYSTEM_WINDOWS_CUI and
        pe.overlay.size > 0 and pe.overlay.size <= 64 and
        pe.imports("kernel32.dll", "FindFirstVolumeW") and
        pe.imports("kernel32.dll", "MoveFileW") and
        math.entropy(0, filesize) < 7.0 and
        filesize > 300KB and filesize < 1MB
}
