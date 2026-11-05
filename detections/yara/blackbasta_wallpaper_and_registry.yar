/*
    Black Basta ransomware - wallpaper message, registry artifacts
    Procmon (dynamic): RegSetValue HKCU\Control Panel\Desktop\Wallpaper,
                       RegCreateKey HKCR\.basta and HKCR\.basta\DefaultIcon (ACCESS DENIED when non-elevated)
    Wallpaper text : "Your network is encrypted by the Black Basta group. Instructions in the file readme.txt."
    The wallpaper text is rendered into an image, so these rules target
    text artifacts (memory dumps, scripts, strings, .reg exports, logs).
*/

rule BlackBasta_Wallpaper_Message_Text
{
    meta:
        description = "Black Basta wallpaper message text (memory, scripts, reports, resources)"
        author      = "Malware Analysis Lab"
        date        = "2026-11-05"
        mitre_attack = "T1491.001"
        confidence  = "high"

    strings:
        $a = "Your network is encrypted by the Black Basta group" ascii wide nocase
        $b = "Instructions in the file readme.txt" ascii wide nocase

    condition:
        any of them
}

rule BlackBasta_Basta_Extension_Registry_Artifacts
{
    meta:
        description = "Registry/file-association artifacts for the .basta extension (memory, exported .reg files, logs)"
        author      = "Malware Analysis Lab"
        date        = "2026-11-05"
        mitre_attack = "T1486"
        confidence  = "medium"

    strings:
        $k1 = ".basta\\DefaultIcon" ascii wide nocase
        $k2 = "HKEY_CLASSES_ROOT\\.basta" ascii wide nocase
        $k3 = "HKCR\\.basta" ascii wide nocase
        $k4 = "\\Software\\Classes\\.basta" ascii wide nocase

    condition:
        any of ($k*) and filesize < 50MB
}

rule BlackBasta_Binary_Basta_Extension_And_Wallpaper_Strings
{
    meta:
        description = "Executable referencing the .basta extension together with desktop-wallpaper registry handling"
        author      = "Malware Analysis Lab"
        date        = "2026-11-05"
        confidence  = "medium"
        note        = "Strings may be stored wide or built at runtime; absence does not rule out the family"

    strings:
        $ext = ".basta" ascii wide
        $dsk = "Control Panel\\Desktop" ascii wide nocase
        $wp  = "Wallpaper" ascii wide
        $ic  = "DefaultIcon" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        $ext and $dsk and ($wp or $ic)
}
