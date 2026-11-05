/*
    Black Basta ransomware - cryptographic / runtime strings
    capa: "encrypt data using Salsa20 or ChaCha", Base64 string.
    Strings: "expand 32-byte k", GMP allocator messages (big-number library),
    console progress/error messages.
*/

import "pe"

rule BlackBasta_Crypto_Library_Artifacts
{
    meta:
        description = "32-bit PE with ChaCha/Salsa constant, GMP allocator messages and Black Basta console messages"
        author      = "Malware Analysis Lab"
        date        = "2026-11-05"
        mitre_attack = "T1486"
        confidence  = "medium"

    strings:
        $chacha_const = "expand 32-byte k" ascii
        $gmp1         = "gmp_default_alloc: Virtual memory exhausted." ascii
        $gmp2         = "gmp_default_realloc: Virtual memory exhausted." ascii
        $msg1         = "Done time: %.4f seconds, encrypted: %.4f gb" ascii
        $msg2         = "ERRRROR with file" ascii
        $msg3         = "Error 755:" ascii
        $msg4         = "ext index:" ascii

    condition:
        uint16(0) == 0x5A4D and
        pe.is_pe and
        not pe.is_64bit() and
        filesize < 2MB and
        $chacha_const and 1 of ($gmp*) and 1 of ($msg*)
}

rule BlackBasta_Console_Progress_Messages
{
    meta:
        description = "Black Basta console output format strings (encryption summary / error text)"
        author      = "Malware Analysis Lab"
        date        = "2026-11-05"
        confidence  = "medium-high"

    strings:
        $a = "Done time: %.4f seconds, encrypted: %.4f gb" ascii
        $b = "ERRRROR with file" ascii
        $c = "ENCRYPTION" ascii fullword
        $d = "Error 755:" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        $a and 1 of ($b, $c, $d)
}
