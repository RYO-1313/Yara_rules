# Family Name

**What it is:** One or two sentences on the malware.

**What the rule looks for:** The strings or traits it matches, and why you picked them.

**Tested on:** SHA256 hashes of the samples you ran it against. Add a clean file too, to check for false positives.

**Limits:** What it misses, or what could trigger it by mistake.

**Sources:** Links to the reports you used.

**Run it:**

```bash
yara -s rule_name.yar /path/to/sample
```
