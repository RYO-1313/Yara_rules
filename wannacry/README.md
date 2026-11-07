# WannaCry

> A YARA rule that detects WannaCry ransomware components using distinctive strings (marker text, malware name, kill-switch domain) and a combined filename-plus-export clause.

## Threat Overview

WannaCry is ransomware that encrypts files on infected Windows systems and demands a Bitcoin payment. In the May 2017 outbreak it spread across networks as a worm by exploiting the SMBv1 vulnerability known as EternalBlue (MS17-010). Its self-propagation, and the damage it caused to organizations worldwide, made it one of the most studied ransomware families, which makes it a good subject for learning static analysis and rule writing.

## MITRE ATT&CK Mapping

The mapping below comes from public reporting on WannaCry, not from dynamic analysis of the samples in this repository. Verify each technique against the references before relying on it.

| Technique | Name | Relevance |
|-----------|------|-----------|
| `T1486` | Data Encrypted for Impact | Core ransomware behavior: encrypts user files and demands payment |
| `T1210` | Exploitation of Remote Services | Worm propagation through the SMBv1 EternalBlue vulnerability |
| `T1543.003` | Create or Modify System Process: Windows Service | Public reports describe the dropper installing itself as a service (service name `mssecsvc2.0`) |
| `T1490` | Inhibit System Recovery | Public reports describe deletion of shadow copies and backups |
| `T1105` | Ingress Tool Transfer | The dropper writes and launches an embedded payload (`tasksche.exe`); both samples import `WriteFile` and `CreateProcessA` |

## Detection Approach

The rule is string-based and applies to PE files only (`uint16(0) == 0x5A4D`, the "MZ" header at offset 0). Strings are split by strength:

**Strong indicators :**
- `$kill_switch`: the nonsense domain WannaCry checks before running, per public reports. Neither tested sample contained it, so it is currently untested against a real match.
- `$marker` (`WANACRY!`): a marker string found in the EXE sample.
- `$name` (`WanaCrypt0r`): the malware's name, stored as UTF-16 in the EXE sample, so it is searched as `ascii wide`.

**Weak indicators (must appear together):**
- `$dropped` (`tasksche.exe`): the dropped component's filename. It looks like a legitimate Windows name, so it is never used alone.
- `$export` (`PlayGame`): an unusual export name present in both the DLL and the EXE samples. It is also an ordinary English phrase, so it is never used alone.

**Excluded on purpose:** `WriteFile` and `CreateProcessA`. Both samples import them, but they are extremely common in legitimate software and carry almost no detection value.

**Condition:**

```
uint16(0) == 0x5A4D and
( $kill_switch or $marker or $name or ( $dropped and $export ) )
```

The combined clause (`$dropped and $export`) exists so that the DLL, which carries none of the strong strings, is still detected without letting a filename alone trigger the rule.

## Testing

| Sample (SHA256) | Source | Expected | Result |
|-----------------|--------|----------|--------|
| `43fe9dde201aa613382486afacd94af75cd45de3ee1aaa2a49442e850acd9da9` (EXE) | MalwareBazaar | Match | Match: `$marker`, `$name`, `$dropped` (x2), `$export` |
| `4436f92229f527236c0847564351ef5147b2458a120f3402b0dd1b58a6a84f0a` (DLL) | MalwareBazaar | Match | Match: `$dropped`, `$export` (combined clause) |
| Clean files in `C:\Windows\System32` | Local Windows install | No match | No match (registry hives and other locked files could not be opened and were not scanned) |
| AsyncRAT sample (negative control) | MalwareBazaar | No match | [TODO: not yet run] |
| Third WannaCry sample | MalwareBazaar | Match | [TODO: hash and result not recorded] |
| Clean files in `C:\Program Files` | Local Windows install | No match | [TODO: not yet run with this version of the rule] |

> No live samples are stored in this repository. Reference hashes only.

## Usage

```bash
yara -s Wanacry.yar /path/to/sample
```

On Windows:

```
yara64.exe -s Wanacry.yar C:\path\to\sample.exe
```

Recursive scan of a directory:

```
yara64.exe -r Wanacry.yar C:\path\to\folder
```

`-s` prints the matched strings and their offsets, which shows whether a hit came from a strong string or from the combined clause.

## Limitations and False Positives

- **Very small test set.** The rule was built and validated on two samples, so it shows consistency on those files, not coverage of the family.
- **Kill-switch string untested.** It was not present in either sample, so its encoding and exact form have not been confirmed by a real match.
- **DLL detection is weak.** It relies on a filename plus a common English word. Other software or other malware could contain both strings.
- **`PlayGame` appears at three offsets per sample.** An export name should appear once in the export table, so the other hits are unexplained. The string's stability across builds has not been confirmed.
- **Variants and repacked builds may be missed.** Samples that are packed, modified, or that keep these strings only inside an encrypted or compressed resource will not match, because the rule inspects static bytes only.
- **Possible false positives:** security tools, analysis reports, or sandbox artifacts that contain the marker strings; any software that references `tasksche.exe` together with `PlayGame`.
- **Not run against a large clean corpus.** Only `C:\Windows\System32` has been tested so far.

## References

- MalwareBazaar: https://bazaar.abuse.ch/
- WannaCry analysis (strings): https://0xg4br.github.io/malware%20analysis/WannaCry/#strings
