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
| `T1105` | Ingress Tool Transfer | The dropper writes and launches an embedded payload (`tasksche.exe`); the first two samples analyzed import `WriteFile` and `CreateProcessA` |

## Detection Approach

The rule is string-based and applies to PE files only (`uint16(0) == 0x5A4D`, the "MZ" header at offset 0). Strings are split by strength:

**Strong indicators (any one is sufficient):**
- `$kill_switch`: the nonsense domain WannaCry checks before running, per public reports. Found as plain ASCII in 2 of the 6 tested samples (one EXE, one DLL).
- `$marker` (`WANACRY!`): a marker string found in 4 of the 6 samples.
- `$name` (`WanaCrypt0r`): the malware's name, found in the same 4 samples. It is stored as UTF-16, so it is searched as `ascii wide`.

**Weak indicators (must appear together):**
- `$dropped` (`tasksche.exe`): the dropped component's filename. It looks like a legitimate Windows name, so it is never used alone.
- `$export` (`PlayGame`): an unusual export name present in all 6 samples. It is also an ordinary English phrase, so it is never used alone.

**Excluded on purpose:** `WriteFile` and `CreateProcessA`. The first two samples analyzed import them, but they are extremely common in legitimate software and carry almost no detection value.

**Condition:**

```
uint16(0) == 0x5A4D and
( $kill_switch or $marker or $name or ( $dropped and $export ) )
```

The combined clause (`$dropped and $export`) exists so that samples carrying none of the strong strings are still detected without letting a filename alone trigger the rule. Two of the six samples (one EXE and one DLL) matched only through this clause.

## Testing

All six WannaCry samples were scanned with `yara64.exe -s Wanacry.yar <file>`.

| Sample (SHA256) | Source | Expected | Result |
|-----------------|--------|----------|--------|
| `14e1dd3f1ab9b60277b0f5ea15ce926ffb9bfd5b2dcfb0186729f6f487c33348` (EXE) | MalwareBazaar | Match | Match (combined clause): `$dropped`, `$export` |
| `43fe9dde201aa613382486afacd94af75cd45de3ee1aaa2a49442e850acd9da9` (EXE) | MalwareBazaar | Match | Match: `$marker`, `$name`, `$dropped` (x2), `$export` |
| `930ba0ab96e5cfd4c3dc3cab78a3fa5514acd88c0ddcf32e73af7c2c31bd335c` (EXE) | MalwareBazaar | Match | Match: `$kill_switch`, `$marker`, `$name`, `$dropped` (x2), `$export` |
| `dbdf262ca964e3115e1e07a0d5bbc12e8aafe17f71ce0621b9ba6b15aeb9777d` (EXE) | MalwareBazaar | Match | Match: `$marker`, `$name`, `$dropped` (x2), `$export` |
| `4436f92229f527236c0847564351ef5147b2458a120f3402b0dd1b58a6a84f0a` (DLL) | MalwareBazaar | Match | Match (combined clause): `$dropped`, `$export` |
| `f45ed649c6b28cc6957d36fd448ae4d9c5eaa4b3c06a2532bc50eed035869f3f` (DLL) | MalwareBazaar | Match | Match: `$kill_switch`, `$marker`, `$name`, `$dropped` (x2), `$export` |
| Clean files in `C:\Windows\System32` | Local Windows install | No match | No match (registry hives and other locked files could not be opened and were not scanned) |

Result: 6 of 6 WannaCry samples matched.

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

- **Small test set.** The rule was built and validated on six samples (four EXEs, two DLLs), all of which matched. This shows consistency on those files, not coverage of the family or resistance to false positives.
- **Two of six samples rely on the weak clause.** Their detection rests on a filename plus a common English word, which other software or other malware could also contain.
- **Kill-switch string only partly validated.** It matched in 2 of 6 samples, so it is confirmed as a working string, but four samples do not contain it in plain form.
- **`PlayGame` appears at three offsets per sample.** An export name should appear once in the export table, so the other hits are unexplained. The offsets repeat across samples of the same type (the same three in the EXEs, the same three in the DLLs), which suggests shared code or data, but this has not been investigated.
- **Variants and repacked builds may be missed.** Samples that are packed, modified, or that keep these strings only inside an encrypted or compressed resource will not match, because the rule inspects static bytes only.
- **Possible false positives:** security tools, analysis reports, or sandbox artifacts that contain the marker strings; any software that references `tasksche.exe` together with `PlayGame`.
- **Not run against a large clean corpus.** Only `C:\Windows\System32` has been tested so far.

## References

- MalwareBazaar: https://bazaar.abuse.ch/
- WannaCry analysis (strings): https://0xg4br.github.io/malware%20analysis/WannaCry/#strings
