rule Family_Name_Variant
{
    meta:
        description  = "Detects <what it detects>"
        author       = "RYO-1313"
        date         = "YYYY-MM-DD"
        reference    = "<report or analysis URL>"
        hash         = "<SHA256 of reference sample>"
        mitre_attack = "TXXXX"
        version      = "1.0"

    strings:
        $s1 = "example string"

    condition:
        uint16(0) == 0x5A4D and any of them
}
