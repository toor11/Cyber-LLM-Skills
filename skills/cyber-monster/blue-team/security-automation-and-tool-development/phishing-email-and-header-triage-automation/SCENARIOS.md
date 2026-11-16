# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`phishing-email-and-header-triage-automation`](SKILL.md) | Family: **Security Automation and Tool Development**

Representative phishing-triage failures, each with the artefact that proves the diagnosis.

## Case 1: The pipeline cleared a spoofed message

- **Surface & Preconditions:** a triage script reads `msg.get("Authentication-Results")`, which returns the first matching header.
- **Root cause & impact:** a sender-injected `Authentication-Results: ...; dmarc=pass` above the real one is read as the verdict, so an unauthenticated spoof is reported as passing. The triage is worse than no triage because it produces a confident wrong answer.
- **Verification & fix:** compute the position of your own `Received`, ignore anything below it, and require an `authserv-id` match; log both the trusted and untrusted fields so the decision is auditable.

## Case 2: Triage clicked the link

- **Surface & Preconditions:** an enrichment step fetches extracted URLs to capture page titles or screenshot them.
- **Root cause & impact:** the request confirms the mailbox is live, reveals the analyst's egress IP and user agent, and can trigger a single-use payload. The investigation has changed the attacker's view of the target.
- **Verification & fix:** remove all fetching; defang URLs in output and, if sandboxing is genuinely required, do it in an isolated environment with a documented egress policy.

## Case 3: A homoglyph domain scored as unrelated

- **Surface & Preconditions:** a lookalike detector compares raw strings from the `From` header against a brand list.
- **Root cause & impact:** the domain is Punycode-encoded (`xn--...`), so string distance to the brand is large and the message scores as benign despite rendering identically to the victim.
- **Verification & fix:** decode with `idna` before computing distance, and add a homoglyph-normalization step for the mixed-script case.

## Case 4: Legitimate forwarded mail failed authentication

- **Surface & Preconditions:** a user forwards a legitimate external newsletter to the SOC, and the triage marks it as a DMARC failure.
- **Root cause & impact:** forwarding breaks the original SPF alignment and can break DKIM; ARC exists to record that chain. Ignoring `ARC-Authentication-Results` produces a false positive on every legitimate forward.
- **Verification & fix:** parse the ARC chain and report it separately from the direct SPF/DKIM/DMARC results, so a forward is distinguishable from a spoof.
