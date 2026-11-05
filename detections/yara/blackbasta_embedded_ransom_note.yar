/*
    Black Basta ransomware - embedded ransom-note template (421 bytes in the binary)
    Observed text (ASCII):
      "Your data are stolen and encrypted"
      "The data will be published on TOR website if you do not pay the ransom"
      "You can contact us and decrypt one file for free on this TOR site"
      "(you should download and install TOR browser first https://torproject.org)"
*/

import "pe"

rule BlackBasta_Embedded_Ransom_Note_Template
{
    meta:
        description = "Executable embedding the Black Basta ransom-note template text"
        author      = "Malware Analysis Lab"
        date        = "2026-11-05"
        mitre_attack = "T1486"
        confidence  = "high"

    strings:
        $n1 = "Your data are stolen and encrypted" ascii
        $n2 = "The data will be published on TOR website if you do not pay the ransom" ascii
        $n3 = "You can contact us and decrypt one file for free on this TOR site" ascii
        $n4 = "you should download and install TOR browser first" ascii
        $n5 = "Your company id for log in" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        3 of ($n*)
}

rule BlackBasta_Embedded_Note_Plus_Crypto_Strings
{
    meta:
        description = "Executable combining the ransom-note text with encryption/progress strings seen in Black Basta"
        author      = "Malware Analysis Lab"
        date        = "2026-11-05"
        confidence  = "high"

    strings:
        $note1 = "Your data are stolen and encrypted" ascii
        $note2 = "published on TOR website" ascii
        $s1    = "Done time: %.4f seconds, encrypted: %.4f gb" ascii
        $s2    = "ERRRROR with file" ascii
        $s3    = "ENCRYPTION" ascii fullword
        $s4    = "expand 32-byte k" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        1 of ($note*) and 2 of ($s*)
}
