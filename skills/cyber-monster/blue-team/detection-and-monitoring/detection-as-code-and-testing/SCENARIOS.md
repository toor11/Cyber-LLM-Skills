# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`detection-as-code-and-testing`](SKILL.md) | Family: **Detection and Monitoring**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: Git repository found

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Git metadata directory (.git) was found in this folder. An attacker can extract sensitive information by requesting the hidden metadata directory that version control tool Git creates.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 2: 3690/tcp - Pentesting Subversion (SVN) Server

- **Provenance:** Source: `CYBER_CPT/hacktricks`
- **Context / Surface:** Security Assessment Guide (en)
- **Root Cause / Analysis:** 3690/tcp - Pentesting Subversion (SVN) Server {{#include ../banners/hacktricks-training.md}} Basic Information **Subversion (SVN)** is a centralized **version control system** (Apache license) used for software versioning and revision control. **Default port:** '3690/tcp' (svnserve).
- **Actionable Takeaway:** Cross-check preconditions and telemetry before applying to the target.

## Case 3: Pentesting CI/CD Methodology

- **Provenance:** Source: `CYBER_CPT/hacktricks_cloud`
- **Context / Surface:** Cloud Security Guide (en)
- **Root Cause / Analysis:** Pentesting CI/CD Methodology VCS VCS stands for **Version Control System**, this systems allows developers to **manage their source code**. The most common one is **git** and you will usually find companies using it in one of the following **platforms**: - Github - Gitlab - Bitbucket - Gitea -...
- **Actionable Takeaway:** Cross-check preconditions and telemetry before applying to the target.

## Case 4: TryHackme / AtomicRedTeam WriteUp

- **Provenance:** Source: `CYBER_CPT/L5/ctf_search`
- **Context / Surface:** High-depth analysis (ctf_search, edu=4)
- **Root Cause / Analysis:** TryHackme / AtomicRedTeam WriteUp Leveraging the Atomic Red Team Framework to strengthen the Security Operations’ detection capabilities. Task 1 Introduction In this room, we will learn how to utilize Atomic Red Team from the perspective of Blue Teamers, understanding how exactly threat actors run their TTPs and how...
- **Actionable Takeaway:** Validate root-cause preconditions and apply defense-in-depth controls.

## Case 5: TryHackme — Advent of cyber 2024-Day 4

- **Provenance:** Source: `CYBER_CPT/L5/ctf_search`
- **Context / Surface:** High-depth analysis (ctf_search, edu=4)
- **Root Cause / Analysis:** TryHackMe — Advent of Cyber 2024 - Day 4 In this section we shall learn: * Learn how to identify malicious techniques using the MITRE ATT&CK framework. * Learn about how to use Atomic Red Team tests to conduct attack simulations. * Understand how to create alerting and detection rules from the attack tests.
- **Actionable Takeaway:** Validate root-cause preconditions and apply defense-in-depth controls.

## Case 6: Walkthrough Information disclosure in version control history — Portswigger Lab

- **Provenance:** Source: `CYBER_CPT/ctf_search` | CWE: `CWE-778`
- **Context / Surface:** Source: ctf_search (en)
- **Root Cause / Analysis:** # Walkthrough Information disclosure in version control history — Portswigger Information disclosure is when a website unintentionally reveals sensitive information to its users. As the lab says, we need to find some information on the git history on that website. It looks like a
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 7: Git Extraction – Abusing version control systems

- **Provenance:** Source: `CYBER_CPT/pentest_partners` | CWE: `CWE-778`
- **Context / Surface:** Source: pentest_partners (en)
- **Root Cause / Analysis:** For those who have heard of me you might have read my articles on cirt.net (on [SVN Pristine Extractor] (http://www.cirt.net/svnpristine) and [Mercurial Extractor] (http://www.cirt.net/hg-decode)) about abusing various revision and version control systems when they are being used t
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 8: Webcast: Let’s Talk About ELK Baby, Let’s Talk About You and AD

- **Provenance:** Source: `CYBER_CPT/blackhills` | CWE: `CWE-778`
- **Context / Surface:** Source: blackhills (en)
- **Root Cause / Analysis:** # Webcast: Let’s Talk About ELK Baby, Let’s Talk About You and AD Slides for this webcast can be found here: https://www.blackhillsinfosec.com/wp-content/uploads/2020/09/SLIDES\_LetsTalkAboutELKBaby.pdf - Why Are We Doing This? - AT7: The Logs You Are Looking For - AD Best Practi
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
