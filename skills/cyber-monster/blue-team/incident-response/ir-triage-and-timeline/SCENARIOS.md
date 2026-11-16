# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`ir-triage-and-timeline`](SKILL.md) | Family: **Incident Response**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: TryHackMe / IR Timeline Analysis / WriteUp

- **Provenance:** Source: `CYBER_CPT/L5/ctf_search`
- **Context / Surface:** High-depth analysis (ctf_search, edu=4)
- **Root Cause / Analysis:** TryHackMe / IR Timeline Analysis / WriteUp Learn about timeline analysis using various tools and scenarios. Task 1 Introduction In digital investigations, the more forensic data you have, the more complex things will be to process and analyze.
- **Actionable Takeaway:** Validate root-cause preconditions and apply defense-in-depth controls.

## Case 2: HTB Sherlock: BFT

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-778`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** BFT is all about analysis of a Master File Table (MFT). I’ll use Zimmerman tools MFTECmd and Timeline Explorer to find where a Zip archive was downloaded from Google Drive. It is then unzipped to get another zip, which is unzipped to get another zip. That final zip has a Windows
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: TryHackMe / IR Timeline Analysis / WriteUp

- **Provenance:** Source: `CYBER_CPT/ctf_search` | CWE: `CWE-778`
- **Context / Surface:** Source: ctf_search (en)
- **Root Cause / Analysis:** # TryHackMe / IR Timeline Analysis / WriteUp ## Learn about timeline analysis using various tools and scenarios. Task 1 Introduction In digital investigations, the more forensic data you have, the more complex things will be to process and analyze. It is, therefore, important to
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: HTB: Mailroom

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-778`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** ![Mailroom] (/img/mailroom-cover.png) Mailroom has a contact us form that I can use to get cross site sripting against an admin user. I’ll use this XSS to exploit a NoSQL injection vulnerability in a private site, brute forcing the user’s password and exfiling it back to myself. F
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: Powershell变量的作用域 20

- **Provenance:** Source: `CYBER_CPT/pstips` | CWE: `CWE-778`
- **Context / Surface:** Source: pstips (zh)
- **Root Cause / Analysis:** # Powershell变量的作用域 Powershell所有的变量都有一个决定变量是否可用的作用域。Powershell支持四个作用域：全局、当前、私有和脚本。有了这些作用域就可以限制变量的可见性了，尤其是在函数和脚本中。 如果我们对变量不做特别的声明，Powershell解释器会自动处理和限制变量的作用域。将下面的内容命令保存着至test1.ps1 $windows = $env:windir “Windows Folder: $windows” 然后在控制台给变量$windows赋值，并调用Test.ps1脚本。 'powershell PS>
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: From an Out-of-Scope Bug to Unlocking Lifetime Premium Accounts in Mozilla

- **Provenance:** Source: `CYBER_CPT/ctf_search` | CWE: `CWE-778`
- **Context / Surface:** Source: ctf_search (en)
- **Root Cause / Analysis:** # From an Out-of-Scope Bug to Unlocking Lifetime Premium Accounts in Mozilla I’m Amr Kadry, a penetration tester and bug hunter recognized by over 45 companies, including Mozilla, CrowdStrike, Canva, and Vimeo. Today, I’m excited to share an intriguing discovery: a business logic
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 7: gix-path uses local config across repos when it is the highest scope

- **Provenance:** Source: `CYBER_CPT/gh_advisories` | CWE: `CWE-778`
- **Context / Surface:** Source: gh_advisories (en)
- **Root Cause / Analysis:** ### Summary 'gix-path' executes 'git' to find the path of a configuration file that belongs to the 'git' installation itself, but mistakenly treats the local repository's configuration as system-wide if no higher scoped configuration is found. In rare cases, this causes a less tr
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
