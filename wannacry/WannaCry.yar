rule Ransom_WannaCry_Strings
{
    meta:
        author      = "https://github.com/RYO-1313"
        description = "Detects WannaCry-related artifacts based on strings from public analysis"
        reference   = "https://bazaar.abuse.ch/"
        reference2  = "https://0xg4br.github.io/malware%20analysis/WannaCry/#strings"
        sha256_1    = "43fe9dde201aa613382486afacd94af75cd45de3ee1aaa2a49442e850acd9da9"
        sha256_2    = "4436f92229f527236c0847564351ef5147b2458a120f3402b0dd1b58a6a84f0a"

    strings:
        $kill_switch = "iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea" ascii wide
        $marker      = "WANACRY!" ascii
        $name        = "WanaCrypt0r" ascii wide
        $dropped     = "tasksche.exe" ascii wide
        $export      = "PlayGame" ascii

    condition:
        uint16(0) == 0x5A4D and
        ( $kill_switch or $marker or $name or
          ( $dropped and $export ) )
}
