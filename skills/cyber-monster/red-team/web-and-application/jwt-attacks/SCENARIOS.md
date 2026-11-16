# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`jwt-attacks`](SKILL.md) | Family: **Web and Application**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: [Urgent] Invalidating OAuth2 Bearer token makes TweetDeck unavailable

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** First of all, really sorry for the unintentional DoS :( I was testing it with a fresh bearer token but copied the production one accidentally.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 2: Able to steal bearer token from deep link

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Pre-requisities Prior to exploitation you would be required to know the "account id" of the user that you are attacking. Whilst this makes it difficult to attack an application in a generic way - the account is not secret information as it is included in any links to a user's...
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 3: JWT Vulnerabilities (Json Web Tokens)

- **Provenance:** Source: `CYBER_CPT/hacktricks` | CWE: `CWE-347`
- **Context / Surface:** Source: hacktricks (en)
- **Root Cause / Analysis:** # JWT Vulnerabilities (Json Web Tokens) **Part of this post is based in the awesome post:** [**https://github.com/ticarpi/jwt_tool/wiki/Attack-Methodology**] (https://github.com/ticarpi/jwt_tool/wiki/Attack-Methodology)\ **Author of the great tool to pentest JWTs** [**https://gith
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: JWT

- **Provenance:** Source: `CYBER_CPT/ctf_search` | CWE: `CWE-347`
- **Context / Surface:** Source: ctf_search (en)
- **Root Cause / Analysis:** # JWT Hacking # Introduction JWTs or JSON Web Tokens are most commonly used to identify an authenticated user. In most cases it is used as a “session token” or a “session cookie”. Usually it’s used in APIs but is used for all types of web apps. Format The format it’s like this: I
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: Hacking JWT

- **Provenance:** Source: `CYBER_CPT/ctf_search` | CWE: `CWE-347`
- **Context / Surface:** Source: ctf_search (en)
- **Root Cause / Analysis:** # Hacking JWT This article is all about pentesting JWT. You can practice all of these techniques on vulnerable target availabe at burp Suite webacademy labs. I will try to make the article as easy as possible and will try to make you understand in very layman language. _What is J
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: Username

- **Provenance:** Source: `CYBER_CPT/ctftime` | CWE: `CWE-347`
- **Context / Surface:** Source: ctftime (en)
- **Root Cause / Analysis:** # Web: Username This is a web challenge I created for the WolvSec club CTF event hosted March 2024. ## Description Please register your username. Have fun! **Note:** Automated tools like sqlmap and dirbuster are not allowed (and will not be helpful anyway). **Hint Provided**: The
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 7: Didactic Octo Paddles

- **Provenance:** Source: `CYBER_CPT/ctftime` | CWE: `CWE-347`
- **Context / Surface:** Source: ctftime (en)
- **Root Cause / Analysis:** # Didactic Octo Paddles ## Background You have been hired by the Intergalactic Ministry of Spies to retrieve a powerful relic that is believed to be hidden within the small paddle shop, by the river. You must hack into the paddle shop's system to obtain information on the relic's
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 8: JSON Web Token Cheat Sheet for Java

- **Provenance:** Source: `CYBER_CPT/github_security_md` | CWE: `CWE-347`
- **Context / Surface:** Source: github_security_md (en)
- **Root Cause / Analysis:** # JSON Web Token Cheat Sheet for Java ## Introduction Many applications use **JSON Web Tokens** (JWT) to allow the client to indicate its identity for further exchange after authentication. From [JWT.IO] (https://jwt.io/introduction): > JSON Web Token (JWT) is an open standard (RF
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
