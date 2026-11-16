# Cyber Monster

**The ultimate cyber skill for an AI agent.** One folder. One registered skill. A full red-team and blue-team arsenal behind it: offense, defense, forensics, detection, and the tools that build both.

Point your agent at it and the right procedure shows up on demand: the sink to check, the evidence that counts, and the fix or detection to write. No guessing. No fabricated CVEs. No wall of context.

## What is inside

**785 self-contained sub-skills across 19 families** &mdash; **571** red-team (10 families) and **214** blue-team (9 families). The root `SKILL.md` is the only file you register. It opens one sub-skill for a focused task, or chains several in order when the job spans layers, stages, or a red-to-blue handoff &mdash; while the rest of the library stays untouched on disk.

| Red Team | Skills | | Blue Team | Skills |
|---|---|---|---|---|
| web-and-application | 184 | | security-automation-and-tool-development | 32 |
| binary-and-exploit-development | 104 | | detection-and-monitoring | 29 |
| network-ad-and-endpoint | 95 | | digital-forensics | 27 |
| cryptography-attacks | 33 | | application-security | 25 |
| cloud-container-supply-chain | 32 | | incident-response | 25 |
| mobile-hardware-wireless-ics | 31 | | vulnerability-and-hardening | 23 |
| security-assessment-tooling-and-automation | 28 | | malware-analysis | 22 |
| osint-and-red-operations | 26 | | threat-intelligence-and-hunting | 19 |
| blockchain | 22 | | purple-team-and-program | 12 |
| ai-and-llm | 16 | | | |

This is the working set for a real security job, not a single cheat sheet: web and API review, network and Active Directory, binary and memory-safety analysis, cryptography, cloud and supply chain, AI and LLM systems, smart contracts, mobile and ICS, OSINT, detection engineering, hunting, incident response, forensics, malware analysis, vulnerability management, secure code review, and security-tool development. Red and blue live in the same tree, so one question moves from finding a bug to detecting it without a second library.

Each sub-skill is a folder. Its `SKILL.md` is the procedure: the sink, the preconditions, a baseline-versus-probe differential, a stop condition, false-positive traps, and the shape of the answer. Companions carry the detail and open only when the procedure calls for them:

- Every skill: `TOOLS.md`, `SCENARIOS.md`, `CASES.md`.
- Red-team skills add `PAYLOADS.md` and `DETECTION.md`.
- Blue-team skills add `QUERIES.md` and `PLAYBOOK.md`.

## How to use it

Extract the archive and add only the main `cyber-monster` folder to your AI. That is the one skill. Everything else stays nested inside it, and the agent reads what it needs.

## Why it beats working from memory

An agent with no skill is guessing. It mixes sibling bugs, invents CVE numbers, and falls back on "sanitize the input." Cyber Monster hands it the file for that exact job: the preconditions, the case that is *not* this bug, the evidence that counts, and the output shape. The investigation starts at the sink instead of a blank page. Fewer wrong turns. Fewer fabricated citations. Less time spent repairing a bad first answer.

And it scales from a single check to a full chain without bloating context. A focused question loads one sub-skill; a multi-stage job loads each stage's sub-skill as it reaches it &mdash; SSRF into cloud IAM, prompt injection into MCP tool abuse, or finding a bug on the red side and chaining straight into its blue-team fix and Sigma detection &mdash; passing verified findings from one stage to the next while companions stay closed unless needed.

On the same benchmark job, with the skill versus without it:

| | Result |
|---|---|
| Tokens | **26% fewer** |
| Time | **40% faster** (about **65% more throughput**) |

The method is already written, so the agent spends the turn on the work &mdash; check the target, record the evidence, write the fix or detection &mdash; instead of inventing a procedure or answering twice.

## How it was built

The collections and projects below were read once, stripped of duplicates, and rewritten into these skills:

1. A record was kept only if it carried a technique, a vulnerable-versus-fixed contrast, a detection, a tool, a case, or a false-positive trap.
2. Overlapping writeups of the same idea were merged into one skill, never copied twice.
3. A compiler laid down the first tree: one `SKILL.md` plus companions per technique, grouped into the 19 families.
4. A second pass rewrote every skill with a technique-specific procedure, a baseline-versus-probe differential, a stop condition, and real false-positive traps, checked against public 2025-2026 standards and tool APIs.
5. The technique text lives in the skill file. The agent never goes back to a dataset to finish an answer.

### Sources

- [IQSeC-Lab/LAMDA](https://huggingface.co/datasets/IQSeC-Lab/LAMDA)
- [morinoppp/CYBER_CPT](https://huggingface.co/datasets/morinoppp/CYBER_CPT)
- [scthornton/securecode-web](https://huggingface.co/datasets/scthornton/securecode-web)
- [XuanwuAI/SecEval](https://huggingface.co/datasets/XuanwuAI/SecEval)
- [tandevllc/offsec_redteam_codes](https://huggingface.co/datasets/tandevllc/offsec_redteam_codes)
- [WNT3D/Ultimate-Offensive-Red-Team](https://huggingface.co/datasets/WNT3D/Ultimate-Offensive-Red-Team)
- [tomvaillant/osint-tool-database](https://huggingface.co/datasets/tomvaillant/osint-tool-database)
- [bouddah/osint-ctf-corpus-fr](https://huggingface.co/datasets/bouddah/osint-ctf-corpus-fr)
- [Vyber07/cyber-security](https://huggingface.co/datasets/Vyber07/cyber-security)
- [Rootkit7/pentest-redteam-steering](https://huggingface.co/datasets/Rootkit7/pentest-redteam-steering)
- [TrueNix/ctf-solver-dataset](https://huggingface.co/datasets/TrueNix/ctf-solver-dataset)
- [PentesterFlow/OffsecCyber](https://huggingface.co/datasets/PentesterFlow/OffsecCyber)
- [AYI-NEDJIMI/bug-bounty-pentest-en](https://huggingface.co/datasets/AYI-NEDJIMI/bug-bounty-pentest-en)
- [0xn0cta/bugbounty-hunter-v1](https://huggingface.co/datasets/0xn0cta/bugbounty-hunter-v1)
- [Hacker0x01/hackerone_disclosed_reports](https://huggingface.co/datasets/Hacker0x01/hackerone_disclosed_reports)
- [darkknight25/Forensic_Toolkit_Dataset](https://huggingface.co/datasets/darkknight25/Forensic_Toolkit_Dataset)
- [HackTricks](https://github.com/HackTricks-wiki/hacktricks)
- [HackTricks Cloud](https://github.com/HackTricks-wiki/hacktricks-cloud)
- [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma)
- [projectdiscovery/nuclei-templates](https://github.com/projectdiscovery/nuclei-templates)
- [redcanaryco/atomic-red-team](https://github.com/redcanaryco/atomic-red-team)
- [mitre-attack/attack-stix-data](https://github.com/mitre-attack/attack-stix-data)
- [github/securitylab](https://github.com/github/securitylab)
- [Zyrexnn/Cybermes](https://github.com/Zyrexnn/Cybermes)
- [shellphish/how2heap](https://github.com/shellphish/how2heap)
- [swisskyrepo/PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
- [sqlmapproject/sqlmap](https://github.com/sqlmapproject/sqlmap)
- [GTFOBins/GTFOBins.github.io](https://github.com/GTFOBins/GTFOBins.github.io)
- [LOLBAS-Project/LOLBAS](https://github.com/LOLBAS-Project/LOLBAS)
- [magicsword-io/LOLDrivers](https://github.com/magicsword-io/LOLDrivers)
- [vulhub/vulhub](https://github.com/vulhub/vulhub)
- [danielmiessler/SecLists](https://github.com/danielmiessler/SecLists)
- [rapid7/metasploit-framework](https://github.com/rapid7/metasploit-framework)
- [ctf-wiki/ctf-wiki](https://github.com/ctf-wiki/ctf-wiki)
- [cdk-team/CDK](https://github.com/cdk-team/CDK)
- [cyberark/Kubesploit](https://github.com/cyberark/Kubesploit)
- [RhinoSecurityLabs/cloudgoat](https://github.com/RhinoSecurityLabs/cloudgoat)
- [madhuakula/kubernetes-goat](https://github.com/madhuakula/kubernetes-goat)
- [chaitin/xray](https://github.com/chaitin/xray)
- [nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [PeiQi0/PeiQi-WIKI-Book](https://github.com/PeiQi0/PeiQi-WIKI-Book)
- [kbandla/APTnotes](https://github.com/kbandla/APTnotes)
- [ytisf/theZoo](https://github.com/ytisf/theZoo)
- [mandiant/commando-vm](https://github.com/mandiant/commando-vm)
- [qazbnm456/awesome-web-security](https://github.com/qazbnm456/awesome-web-security)
- [trickest/cve](https://github.com/trickest/cve)
- [joshhighet/ransomwatch](https://github.com/joshhighet/ransomwatch)
- [scadastrangelove/SCADAPASS](https://github.com/scadastrangelove/SCADAPASS)
- [vz-risk/VCDB](https://github.com/vz-risk/VCDB)
- [projectdiscovery/nuclei](https://github.com/projectdiscovery/nuclei)

## Safety

These skills are for authorized review, detection, hardening, and non-destructive verification. They name techniques and impacts; they do not ship exploit source.

## Credit

Created by [W4L33Dx](https://solo.to/w4l33dx).
