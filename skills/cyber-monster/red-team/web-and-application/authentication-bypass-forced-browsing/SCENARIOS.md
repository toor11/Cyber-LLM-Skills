# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`authentication-bypass-forced-browsing`](SKILL.md) | Family: **Web and Application**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: HackerOne SAML signup domain enforcement bypass results in unauthorized access to HackerOne PullRequest o

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** **Summary:** SAML signup domain enforcement for new signups that belong to a SAML-enabled organization can be bypassed with trailing control characters.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 2: Unauthorized access to GovSlack

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Head to slack.com (I use firefox), login as a user that hasn't used slack, create a workspace, copy the payload as fetch. In my case: await fetch("https://slack.com/api/signup.createTeam?_x_id=noversion-1667355054.372", { "credentials": "include", "headers": { "User-Agent":...
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 3: Unauthorized Access to Offline Publication Cover Pages via SOURCE_DOCUMENT_ID

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** I discovered a vulnerability that is related to accessing publication cover pages via a specific request using **sourceDocumentId**. When sending a request with the **source ID**, the system responds with a URL to the cover page of that publication.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 4: Unauthorized access to private project security dashboard

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Summary User with guest permissions can't view security dashboard of the private project. However, this is not applied when user permission changes from maintainer to guest.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 5: Unauthorized access to Zookeeper on http://locutus-zk3.ec2.shopify.com:2181

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** What is Zookeeper? ==================== Zookeeper is a coordination service for distributed applications. It allows common services such as naming, synchronisation, configuration management and group services to be managed by a simple interface and It uses a data model of File...
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 6: Credential Stuffing . Web Exploitation . Day 4, Advent of Cyber 3 (2021) . TryHackMe Walkthrough

- **Provenance:** Source: `CYBER_CPT/L5/ctf_search`
- **Context / Surface:** High-depth analysis (ctf_search, edu=4)
- **Root Cause / Analysis:** Credential Stuffing . Web Exploitation . Day 4, Advent of Cyber 3 (2021) Explore Broken Authentication, API2:2023 vulnerability using Credential Stuffing technique and gaining unauthorized access to an application.
- **Actionable Takeaway:** Validate root-cause preconditions and apply defense-in-depth controls.

## Case 7: TryHackMe — Blue 🟦CTF Writeup/Walkthrough

- **Provenance:** Source: `CYBER_CPT/L5/ctf_search`
- **Context / Surface:** High-depth analysis (ctf_search, edu=4)
- **Root Cause / Analysis:** TryHackMe — Blue CTF Writeup/Walkthrough The Blue room on TryHackMe is focused on exploiting a Windows machine with a well-known vulnerability to gain unauthorized access. This is a common scenario in the world of penetration testing. by this work through you will learn all the commands and tools with explanations.
- **Actionable Takeaway:** Validate root-cause preconditions and apply defense-in-depth controls.

## Case 8: Devtron Attributes API Unauthorized Access Leading to API Token Signing Key Leakage

- **Provenance:** Source: `CYBER_CPT/gh_advisories` | CWE: `CWE-287`
- **Context / Surface:** Source: gh_advisories (en)
- **Root Cause / Analysis:** # Devtron Attributes API Unauthorized Access Leading to API Token Signing Key Leakage ## Summary This vulnerability exists in Devtron's Attributes API interface, allowing any authenticated user (including low-privileged CI/CD Developers) to obtain the global API Token signing key
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
