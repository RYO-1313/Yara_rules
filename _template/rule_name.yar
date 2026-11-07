rule Family_Name
{
    meta:
        description  = "What this rule detects"
        author       = "Your name"
        date         = "YYYY-MM-DD"
        reference    = "Link to a report or analysis"
        hash         = "SHA256 of a sample you tested on"
        mitre_attack = "T1486"

    strings:
        $a = "a string from the sample"
        $b = "another string from the sample"

    condition:
        // MZ header (a Windows executable) and at least 2 of the strings
        uint16(0) == 0x5A4D and 2 of them
}
