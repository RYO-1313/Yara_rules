# Yara_rules

My YARA practice repo. I'm teaching myself malware detection, and this is where I keep the rules I write, the notes behind them, and how I tested each one.

I'm aiming for an entry-level SOC analyst role, with DFIR as the longer-term direction. Writing detection rules from scratch forces me to understand how a piece of malware actually behaves, which reading reports alone never did.

## Rules

| Folder | Family | Type | MITRE ATT&CK | Status |
|--------|--------|------|--------------|--------|
| [`wannacry/`](./wannacry) | WannaCry | Ransomware worm | T1486, T1210, T1490 | Done |

New rules go in as I learn each family. Each one gets its own folder.

## Running a rule

```bash
sudo apt install yara
yara -s wannacry/wannacry.yar /path/to/sample
```

`-s` prints the strings that matched, which helps when a rule fires on something unexpected. I only run samples inside an isolated VM. No malware is stored in this repo, only hashes.

## What's in each folder

```text
family-name/
├── family-name.yar    the rule
└── README.md          short notes on the rule
```

`_template/` has a blank version of both files for starting a new rule.

## What I'm working on

- More families, starting with ones that have good public write-ups
- Testing each rule against clean files to catch false positives

## License

MIT. Rules are for defensive and educational use. Test before trusting them in production, because they will miss variants and can false-positive.
