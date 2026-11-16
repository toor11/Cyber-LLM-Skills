# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`signature-and-mac-attacks`](SKILL.md) | Family: **Cryptography Attacks**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: Email Verification bypass on signup

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Summary: This bug is related to wordpress.com. There is feature in wordpress.com which allow users to invite people. We have to enter email address to invite that particular person but the invite link and invite key is also available to the person who invited.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 2: Node.js: TLS session reuse can lead to hostname verification bypass

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** The Node.js TLS library supports client side reuse of TLS sessions when multiple connections to the same server are opened. Code that wants to use this feature can listen for the 'session' event (https://nodejs.org/api/tls.html#tls_event_session) on a tls.TLSSocket to get...
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 3: Email Verification Bypass Allows Users to Add & verify Any Email As Guardians Email

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** 1. Go to https://www.khanacademy.org/signup and signup as learner keeping date of birth below 13 years. {F1821117} 2. Now keep victims email as parent's email for example here I am keeping info@khanacademy.org as parents email and click on signup. ████ 3.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 4: HTB: Response

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-347`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** Response truly lived up to the insane rating, and was quite masterfully crafted. To start, I’ll construct a HTTP proxy that can abuse an SSRF vulnerability and a HMAC digest oracle to proxy traffic into the inner network and a chat application. With access as guest, I’ll find bob
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: HTB: Arkham

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-347`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** In my opinion, Arkham was the most difficult Medium level box on HTB, as it could have easily been Hard and wouldn’t have been out of place at Insane. But it is still a great box. I’ll start with an encrypted LUKZ disk image, which I have to crack. On it I’ll find the config for
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: How JWT Libraries Block Algorithm Confusion: Key Lessons for Code Review

- **Provenance:** Source: `CYBER_CPT/pentesterlab` | CWE: `CWE-347`
- **Context / Surface:** Source: pentesterlab (en)
- **Root Cause / Analysis:** # How JWT Libraries Block Algorithm Confusion: Key Lessons for Code Review When I wrote the first lab on algorithm confusion, I remember spending a bit of time trying to find a vulnerable library. As an attacker, you need a few things to go wrong to be able to exploit algorithm c
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 7: Why HMAC should be used for hash calculation for your shared secret?

- **Provenance:** Source: `CYBER_CPT/ctf_search` | CWE: `CWE-347`
- **Context / Surface:** Source: ctf_search (en)
- **Root Cause / Analysis:** # Why HMAC should be used for hash calculation for your shared secret? Recently I was trying out a ‘capture the flag’(CFT) event wherein I was given a source file. It’s a simple PHP file that validates the secret passed from the client by creating a hash of the query string with
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 8: phpseclib has a variable-time HMAC comparison in SSH2::get_binary_packet() using != instead of hash_

- **Provenance:** Source: `CYBER_CPT/gh_advisories` | CWE: `CWE-347`
- **Context / Surface:** Source: gh_advisories (en)
- **Root Cause / Analysis:** # phpseclib SSH2: Variable-time comparison in HMAC verification ## Summary 'phpseclib\Net\SSH2::get_binary_packet()' uses PHP's '!=' operator to compare a received SSH packet HMAC against the locally computed HMAC. '!=' on equal-length binary strings in PHP uses 'memcmp()', which
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
