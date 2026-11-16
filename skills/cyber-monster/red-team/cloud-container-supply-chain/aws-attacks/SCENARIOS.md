# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`aws-attacks`](SKILL.md) | Family: **Cloud, Container and Supply Chain**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: AWS Credentials leaked: access to production database backups, SSL certs and more

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** I found a public accessible Jenkins instance: https://██████jenkins.██████.com This instance requires login, however, it is possible to register an account using the signup page: https://██████jenkins.██████.com/signup Arbitrary file reads From there it is possible to use the...
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 2: Let’s try to crack some AWS credentials

- **Provenance:** Source: `CYBER_CPT/L5/ctf_search`
- **Context / Surface:** High-depth analysis (ctf_search, edu=4)
- **Root Cause / Analysis:** Let’s try to crack some AWS credentials In this article, we will do a deep dive into the security credentials of Amazon Web Services (AWS) and examine the feasibility of cracking them. Programmatic access allows AWS users to interact with AWS resources through a custom application or a third-party tool.
- **Actionable Takeaway:** Validate root-cause preconditions and apply defense-in-depth controls.

## Case 3: Enter Access Key ID

- **Provenance:** Source: `CYBER_CPT/cloudgoat` | CWE: `CWE-269`
- **Context / Surface:** Source: cloudgoat (en)
- **Root Cause / Analysis:** 1. **Analyze the Request:** * **Role:** Master cybersecurity educator. * **Target Audience:** Bright but novice security learner. * **Goal:** Deeply elucidate, make complex intuitive, make implicit explicit. * **UNBREAKABLE RULES:** * (a) Technical Correctness: Preserve all detai
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: Enter the provided Access Key, Secret Key, and region (us-east-1)

- **Provenance:** Source: `CYBER_CPT/cloudgoat` | CWE: `CWE-269`
- **Context / Surface:** Source: cloudgoat (en)
- **Root Cause / Analysis:** 1. **Analyze the Request:** * **Role:** Master cybersecurity educator. * **Target Audience:** Bright but novice security learner. * **Goal:** Deeply elucidate, make complex intuitive, implicit explicit. * **UNBREAKABLE RULES:** * (a) Technical Correctness: Preserve all details, m
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: Let’s try to crack some AWS credentials

- **Provenance:** Source: `CYBER_CPT/ctf_search` | CWE: `CWE-269`
- **Context / Surface:** Source: ctf_search (en)
- **Root Cause / Analysis:** # Let’s try to crack some AWS credentials In this article, we will do a deep dive into the security credentials of Amazon Web Services (AWS) and examine the feasibility of cracking them. Programmatic access allows AWS users to interact with AWS resources through a custom applicat
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: Enter the provided Access Key, Secret Key, and region (us-east-1)

- **Provenance:** Source: `CYBER_CPT/cloudgoat` | CWE: `CWE-269`
- **Context / Surface:** Source: cloudgoat (en)
- **Root Cause / Analysis:** ## Cheat Sheet - federated_console_takeover This guide walks through a classic cloud attack chain: gaining a foothold in an AWS environment, pivoting to an EC2 instance, stealing its temporary credentials, and using those stolen credentials to log into the AWS Web Console. This i
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 7: AWS: Assuming Access Key Compromise

- **Provenance:** Source: `CYBER_CPT/blackhills` | CWE: `CWE-269`
- **Context / Surface:** Source: blackhills (en)
- **Root Cause / Analysis:** # AWS: Assuming Access Key Compromise In this scenario, we are assuming the role of an attacker who has obtained an AWS access key, a secret key, and potentially a '.pem' key from a careless network user who left these credentials exposed. Think of an access key and secret key as
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 8: Craft CMS: save_images_Asset graphql mutation can be abused to exfiltrate AWS credentials of underly

- **Provenance:** Source: `CYBER_CPT/gh_advisories` | CWE: `CWE-269`
- **Context / Surface:** Source: gh_advisories (en)
- **Root Cause / Analysis:** ### Summary - The save_images_Asset graphql mutation allows a user to give a url of an image to download. (Url must use a domain, not a raw IP.) - Attacker sets up domain attacker.domain with an A record of something like 169.254.169.254 (special AWS metadata IP) - Attacker invok
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
