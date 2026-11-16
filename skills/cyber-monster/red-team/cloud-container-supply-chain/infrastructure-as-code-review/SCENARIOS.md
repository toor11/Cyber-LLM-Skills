# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`infrastructure-as-code-review`](SKILL.md) | Family: **Cloud, Container and Supply Chain**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: Az - ARM Templates / Deployments

- **Provenance:** Source: `CYBER_CPT/hacktricks_cloud`
- **Context / Surface:** Cloud Security Guide (en)
- **Root Cause / Analysis:** Az - ARM Templates / Deployments Basic Information From the docs: To implement **infrastructure as code for your Azure solutions**, use Azure Resource Manager templates (ARM templates).
- **Actionable Takeaway:** Cross-check preconditions and telemetry before applying to the target.

## Case 2: TryHackMe / Intro to IaC / WriteUp

- **Provenance:** Source: `CYBER_CPT/L5/ctf_search`
- **Context / Surface:** High-depth analysis (ctf_search, edu=4)
- **Root Cause / Analysis:** TryHackMe / Intro to IaC / WriteUp An introduction to infrastructure as code Find the room here: https://tryhackme.com/room/introtoiac Task 1 Introduction If you aim to get into DevOps/DevSecOps, you may have encountered the term infrastructure as code (IaC).
- **Actionable Takeaway:** Validate root-cause preconditions and apply defense-in-depth controls.

## Case 3: TryHackMe / Cloud-based IaC / WriteUp

- **Provenance:** Source: `CYBER_CPT/L5/ctf_search`
- **Context / Surface:** High-depth analysis (ctf_search, edu=4)
- **Root Cause / Analysis:** TryHackMe / Cloud-based IaC / WriteUp Learn about infrastructure as code (IaC) using tools for cloud deployment. Task 1 Introduction Explore the fundamentals of infrastructure as code (IaC) and its crucial role in modern cloud computing.
- **Actionable Takeaway:** Validate root-cause preconditions and apply defense-in-depth controls.

## Case 4: TryHackMe / On-Premises IaC / WriteUp

- **Provenance:** Source: `CYBER_CPT/L5/ctf_search`
- **Context / Surface:** High-depth analysis (ctf_search, edu=4)
- **Root Cause / Analysis:** TryHackMe / On-Premises IaC / WriteUp This room provides security guidance for on-premises infrastructure as code deployments. Task 1 Introduction In this room, you will learn about on-premises infrastructure as code (IaC) deployments.
- **Actionable Takeaway:** Validate root-cause preconditions and apply defense-in-depth controls.

## Case 5: Terraform Security

- **Provenance:** Source: `CYBER_CPT/hacktricks_cloud` | CWE: `CWE-1188`
- **Context / Surface:** Source: hacktricks_cloud (en)
- **Root Cause / Analysis:** # Terraform Security ## Basic Information [From the docs:] (https://developer.hashicorp.com/terraform/intro) HashiCorp Terraform is an **infrastructure as code tool** that lets you define both **cloud and on-prem resources** in human-readable configuration files that you can versi
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: Texas Chainsaw Massacre: Tokyo Drift (Huntress CTF 2023 Challenge Writeup)

- **Provenance:** Source: `CYBER_CPT/ctf_search` | CWE: `CWE-1188`
- **Context / Surface:** Source: ctf_search (en)
- **Root Cause / Analysis:** # Texas Chainsaw Massacre: Tokyo Drift (Huntress CTF 2023 Challenge Writeup) Let’s see what we have here. Scrolling through the logs I came across this one regarding the installation of the Texas Chainsaw Massacre. If we switch over to the Details tab, there’s code in hex that we
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 7: 📝 Checkov - Kubernetes Goat Report

- **Provenance:** Source: `CYBER_CPT/kubernetes_goat` | CWE: `CWE-1188`
- **Context / Surface:** Source: kubernetes_goat (en)
- **Root Cause / Analysis:** # 📝 Checkov - Kubernetes Goat Report Checkov is a static code analysis tool for infrastructure-as-code. ## 🙌 Overview Checkov scan results: - Kubernetes issues: **263** - Dockerfiles issues: **39** - Helm charts issues: **36** Kubernetes Manifests: - **Failed checks: 263** - Pass
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 8: Infrastructure as Code (IaC)

- **Provenance:** Source: `CYBER_CPT/github_security_md` | CWE: `CWE-1188`
- **Context / Surface:** Source: github_security_md (en)
- **Root Cause / Analysis:** # Infrastructure as Code (IaC) ## Quick start Simply specify a directory containing IaC files such as Terraform, CloudFormation and Dockerfile. 'bash $ trivy config [YOUR_IaC_DIRECTORY] ' Trivy will automatically fetch the managed policies and will keep them up-to-date in fut
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
