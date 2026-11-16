# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`tls-and-header-compliance-scanner-scripting`](SKILL.md) | Family: **Security Assessment Tooling and Automation**

Two worked shapes for this technique. Identifiers are placeholders for the engagement's own assets; no incident below is a fabricated advisory.

## Case 1: Legacy Protocol Still Negotiable

- **Surface & Preconditions:** The policy forbids TLS 1.0, and the assessment must show whether the server still accepts it.
- **Root Cause & Impact:** A default-context handshake negotiates TLS 1.3 and says nothing about support for older versions.
- **Verification & Fix:** Attempt one pinned handshake per version, record which complete, and report the negotiated cipher for each accepted version.

## Case 2: Header Missing Only on the Redirect

- **Surface & Preconditions:** HSTS appears absent because the capture was of a 301 to the canonical host.
- **Root Cause & Impact:** The policy is applied on the final response, so the absence is an artefact of which response was inspected.
- **Verification & Fix:** Capture headers with and without redirect following, compare the sets, and report the header state on the final response.
