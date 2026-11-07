# YARA Rules Collection

![YARA](https://img.shields.io/badge/YARA-Detection%20Rules-blue)
![Malware Analysis](https://img.shields.io/badge/Focus-Malware%20Detection-red)
![Status](https://img.shields.io/badge/Status-Actively%20Growing-brightgreen)
![License](https://img.shields.io/badge/License-MIT-lightgrey)

A growing library of YARA rules for identifying malware families, each organized in its own folder with the rule, documentation, and testing notes.

---

## Objective

YARA is a pattern-matching tool used by SOC analysts, malware researchers, and DFIR teams to classify files and memory artifacts based on strings, byte sequences, and structural traits. This repository collects hand-written YARA rules targeting well-known threats, with the goal of showing practical detection engineering: what a rule matches, why those indicators were chosen, and how it was validated.

---

## Rule Index

| # | Folder | Malware Family | Type | MITRE ATT&CK | Status |
|---|--------|----------------|------|--------------|--------|
| 1 | [`wannacry/`](./wannacry) | WannaCry (WannaCrypt) | Ransomware / Worm | T1486, T1210, T1490 | ✅ Complete |

> **Adding a rule?** Append a new row to this table (see [Adding a New Rule](#adding-a-new-rule)).

---

## Repository Structure

```text
Yara_rules/
├── README.md                  # This file: project hub and rule index
├── LICENSE
├── _template/                 # Copy this folder to start a new rule
│   ├── README.md              # Per-rule documentation template
│   └── rule_name.yar          # Rule skeleton with standard metadata
└── wannacry/
    ├── wannacry.yar           # [TODO: confirm filename]
    └── README.md              # [TODO: optional, rule-specific notes]
```

**Convention:** one folder per malware family or threat, named in lowercase with hyphens (e.g. `emotet`, `cobalt-strike`, `lockbit-3`). Each folder is self-contained.

---

## Rule Spotlight: WannaCry

| Field | Detail |
|-------|--------|
| **Threat** | WannaCry ransomware, a self-propagating worm that encrypts files and demands Bitcoin payment |
| **Origin** | Global outbreak in May 2017 |
| **Propagation** | Exploits the SMBv1 vulnerability MS17-010 (EternalBlue) |
| **Rule location** | [`wannacry/`](./wannacry) |

**MITRE ATT&CK mapping** *(verify against the final rule logic)*

| Technique | Name | Relevance |
|-----------|------|-----------|
| `T1486` | Data Encrypted for Impact | Core ransomware behavior |
| `T1210` | Exploitation of Remote Services | SMB worm-style spread |
| `T1490` | Inhibit System Recovery | Deletion of shadow copies and backups |

**Detection approach:** `[TODO: summarize what the rule matches, e.g. strings, kill-switch domain, ransom note text, embedded resources, PE characteristics]`

---

## Usage

**Install YARA**

```bash
# Debian / Ubuntu / Kali
sudo apt install yara

# macOS
brew install yara
```

**Scan a file or directory**

```bash
# Single file
yara wannacry/wannacry.yar /path/to/sample

# Recursive directory scan
yara -r wannacry/wannacry.yar /path/to/samples/

# Scan every rule in the repo
yara -r $(find . -name "*.yar" ! -path "./_template/*") /path/to/samples/
```

**Useful flags:** `-s` print matched strings · `-m` print rule metadata · `-w` suppress warnings

> ⚠️ **Safety:** Only test against samples inside an isolated VM or sandbox. Never execute live malware on a host machine.

---

## Adding a New Rule

1. **Copy the template:** `cp -r _template/ new-family-name/`
2. **Rename** `rule_name.yar` to match the family and write the rule.
3. **Fill in the metadata block** (author, date, description, reference, hash).
4. **Document** the detection logic in the folder's `README.md`.
5. **Test** against known-good and known-bad samples to check for false positives.
6. **Update the Rule Index** table in this file with a new row.

### Standard rule metadata

Every rule should carry a consistent `meta` block so the collection stays searchable:

```yara
rule Family_Name_Variant
{
    meta:
        description = "Detects <what it detects>"
        author      = "RYO-1313"
        date        = "YYYY-MM-DD"
        reference   = "<report or analysis URL>"
        hash        = "<SHA256 of reference sample>"
        mitre_attack = "T1486"
        version     = "1.0"

    strings:
        $s1 = "example string"

    condition:
        uint16(0) == 0x5A4D and any of them
}
```

### Per-rule README checklist

- What the malware does (2–3 sentences)
- Indicators used and why they were chosen
- Sample hashes tested against (SHA256 only, no live samples in the repo)
- Known false-positive risks and limitations
- References and sources

---

## Roadmap

- [x] WannaCry ransomware
- [ ] `[TODO: next rule]`
- [ ] `[TODO: next rule]`
- [ ] Add automated rule syntax checks (CI)

---

## Disclaimer

These rules are provided for **defensive and educational purposes**. They may produce false positives or miss variants, so validate before using in production. No malware samples are stored in this repository.

---

## Author

**RYO-1313** · [GitHub](https://github.com/RYO-1313)
