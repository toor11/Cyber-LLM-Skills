# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`password-cracking-and-wordlists`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Entry points verified against current releases. Impacket, Certipy and netexec rename subcommands between minor versions; check `--help` before scripting.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `hashcat` | `hashcat -m 13100 -a 0 tgs.txt wordlist.txt -r rules/best64.rule --status --status-timer 30` | Dictionary plus rules against RC4 service tickets | Linux / Windows |
| `john` | `john --format=krb5tgs --wordlist=wordlist.txt tgs.txt` | CPU recovery where no GPU is available | Linux / macOS |
| `hashid` | `hashid '<hash>'` | Identify the hash type before choosing a mode | Linux / macOS |
| `Get-ADDefaultDomainPasswordPolicy` | `Get-ADDefaultDomainPasswordPolicy` | Policy bounds on the search space | Windows |
| `hashcat --show` | `hashcat -m 13100 tgs.txt --show` | Recovered plaintext for the run, reproducible from the potfile | Linux / Windows |

## Minimal Lab Validation Script

Classify hashes by header and report the mode and estimated cost, so a decision not to run is documented rather than implied.

```python
PATTERNS = [
    ("$krb5tgs$23$", "13100", "RC4 service ticket, fast"),
    ("$krb5tgs$17$", "19600", "AES128 service ticket, slow"),
    ("$krb5tgs$18$", "19700", "AES256 service ticket, slow"),
    ("$krb5asrep$23$", "18200", "RC4 AS-REP, fast"),
    ("$krb5asrep$17$", "19800", "AES128 AS-REP, slow"),
    ("$krb5asrep$18$", "19900", "AES256 AS-REP, slow"),
]

def classify(line):
    for prefix, mode, note in PATTERNS:
        if line.startswith(prefix):
            return mode, note
    if len(line.strip()) == 32 and all(c in "0123456789abcdefABCDEF" for c in line.strip()):
        return "1000", "NTLM, fast"
    return "unknown", "unclassified"

for sample in open("tgs.txt", encoding="utf-8", errors="ignore"):
    if sample.strip():
        print(classify(sample.strip()))
        break
```

## Flag Notes

- `--status-timer 30` gives periodic progress so a long run can be judged against the cost budget.
- `-r rules/best64.rule` is a rule set, not a magic step; the rules define the actual search space.
- `--show` reads results from the potfile, so a run can be reported without re-cracking.
