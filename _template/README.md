# [Malware Family Name]

> One-sentence summary of the threat and what this rule detects.

## Threat Overview

[TODO: 2–3 sentences on what the malware does, how it spreads, and why it matters.]

## MITRE ATT&CK Mapping

| Technique | Name | Relevance |
|-----------|------|-----------|
| `TXXXX` | [Technique name] | [Why it applies] |

## Detection Approach

[TODO: Explain the indicators the rule uses (strings, byte patterns, PE traits, imports) and why they were chosen.]

## Testing

| Sample (SHA256) | Source | Expected | Result |
|-----------------|--------|----------|--------|
| `[hash]` | [MalwareBazaar / VirusTotal / etc.] | Match | [TODO] |

> No live samples are stored in this repository. Reference hashes only.

## Usage

```bash
yara -s rule_name.yar /path/to/sample
```

## Limitations and False Positives

- [TODO: known variants missed, benign files that might match]

## References

- [TODO: report or analysis URL]
