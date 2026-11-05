/*
    Black Basta ransomware - dropped ransom-note file (readme.txt)
    Scan file shares / endpoints for notes dropped in many directories.
    Observed note layout:
      Your data are stolen and encrypted
      The data will be published on TOR website if you do not pay the ransom
      You can contact us and decrypt one file for free on this TOR site
      (you should download and install TOR browser first https://torproject.org)
      https://<56-char>.onion:80/
      Your company id for log in: <uuid>
*/

rule BlackBasta_Ransom_Note_File
{
    meta:
        description = "Black Basta readme.txt ransom note text file"
        author      = "Malware Analysis Lab"
        date        = "2026-11-05"
        mitre_attack = "T1486"
        confidence  = "high"

    strings:
        $l1 = "Your data are stolen and encrypted" ascii wide
        $l2 = "The data will be published on TOR website if you do not pay the ransom" ascii wide
        $l3 = "You can contact us and decrypt one file for free on this TOR site" ascii wide
        $l4 = "you should download and install TOR browser first" ascii wide
        $id = "Your company id for log in:" ascii wide
        $onion = /https?:\/\/[a-z2-7]{56}\.onion(:80)?\/?/ ascii

    condition:
        filesize < 4KB and
        (3 of ($l*) or ($id and 1 of ($l*)) ) and
        ($onion or $id)
}

rule BlackBasta_Ransom_Note_Generic_TOR_Leak_Wording
{
    meta:
        description = "Generic hunting rule for short notes with 'stolen and encrypted' + TOR leak-site wording (Black Basta-style)"
        author      = "Malware Analysis Lab"
        date        = "2026-11-05"
        mitre_attack = "T1486"
        confidence  = "medium (may match related double-extortion notes)"

    strings:
        $a = "stolen and encrypted" ascii wide nocase
        $b = "published on TOR" ascii wide nocase
        $c = "decrypt one file for free" ascii wide nocase
        $d = ".onion" ascii wide nocase

    condition:
        filesize < 8KB and 3 of them
}
