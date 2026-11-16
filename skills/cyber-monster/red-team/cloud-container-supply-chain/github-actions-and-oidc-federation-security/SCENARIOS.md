# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`github-actions-and-oidc-federation-security`](SKILL.md) | Family: **Cloud, Container and Supply Chain**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: Azure – Federation Abuse (GitHub Actions OIDC / Workload Identity)

- **Provenance:** Source: `CYBER_CPT/hacktricks_cloud`
- **Context / Surface:** Cloud Security Guide (en)
- **Root Cause / Analysis:** Azure – Federation Abuse (GitHub Actions OIDC / Workload Identity) Overview GitHub Actions can federate to Azure Entra ID (formerly Azure AD) using OpenID Connect (OIDC). A GitHub workflow requests a short‑lived GitHub ID token (JWT) that encodes details about the run.
- **Actionable Takeaway:** Cross-check preconditions and telemetry before applying to the target.
