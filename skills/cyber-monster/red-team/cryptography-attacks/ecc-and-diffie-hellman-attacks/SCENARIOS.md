# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`ecc-and-diffie-hellman-attacks`](SKILL.md) | Family: **Cryptography Attacks**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: Elliptic Curve

- **Provenance:** Source: `CYBER_CPT/ctftime` | CWE: `CWE-327`
- **Context / Surface:** Source: ctftime (en)
- **Root Cause / Analysis:** # Proving Grounds Practice — Bratarina This is an Easy box on Offsec’s PG Practice but the community has rated it as ‘intermediate’ difficulty. https://portal.offsec.com/labs/practice Start with a Nmap scan: 'bash sudo nmap -Pn -n $IP -sC -sV -p- --open ' I start nearly every
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 2: CTF Crypto - Elliptic Curve Attacks

- **Provenance:** Source: `CYBER_CPT/github_security_md` | CWE: `CWE-327`
- **Context / Surface:** Source: github_security_md (en)
- **Root Cause / Analysis:** # CTF Crypto - Elliptic Curve Attacks ## Small Subgroup Attacks - Check curve order for small factors - Pohlig-Hellman: solve DLP in small subgroups, combine with CRT 'python # SageMath ECC basics E = EllipticCurve(GF(p), [a, b]) G = E.gens()[0] # generator order = E.order() '
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: Private key recovery via invalid curve point in github.com/ecies/go/v2

- **Provenance:** Source: `CYBER_CPT/osv` | CWE: `CWE-327`
- **Context / Surface:** Source: osv (en)
- **Root Cause / Analysis:** # Private key recovery via invalid curve point in github.com/ecies/go/v2 - **OSV ID**: GO-2023-2380 - **CVE**: CVE-2023-49292 - **Published**: 2023-12-11T15:30:30Z - **Modified**: 2024-05-20T16:03:47Z - **Affected Packages**: github.com/ecies/go/v2 - **Ecosystem**: Go An attacker
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: distress-signal

- **Provenance:** Source: `CYBER_CPT/ctftime` | CWE: `CWE-327`
- **Context / Surface:** Source: ctftime (en)
- **Root Cause / Analysis:** We can use Sage to do most of the heavy lifting: 'sage E = EllipticCurve(GF(8011), [-43, 166]) sage: E.lift\_x(59).order() 8043 sage: E.lift\_x(752).order() 2681 sage: E.lift\_x(318).order() 1149 G = E.lift\_x(59) Q = E.lift\_x(273) k = 3 y0 = k \* G c1 = (k\*Q)[0]\*19 c2 = (k\
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: blinder

- **Provenance:** Source: `CYBER_CPT/ctftime` | CWE: `CWE-327`
- **Context / Surface:** Source: ctftime (en)
- **Root Cause / Analysis:** # * Linux * Security * Write-ups * CTF HackTheBox TryHackMe * Tags * Categories * About * Authors noraj Inventory Write-up Factory THTT Domains * Language * FR 🇫🇷 EN 🇬🇧 # writeups # Saudi and Oman National Cyber Security CTF 2019 Quals Write-ups Sunday 10 February 2019 (2019-02-1
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: Invalid Curve Attack in openpgp

- **Provenance:** Source: `CYBER_CPT/gh_advisories` | CWE: `CWE-327`
- **Context / Surface:** Source: gh_advisories (en)
- **Root Cause / Analysis:** Versions of 'openpgp' prior to 4.3.0 are vulnerable to an Invalid Curve Attack. The package's implementation of ECDH fails to verify the validity of the communication partner's public key. The package calculates the resulting key secret based on an altered curve instead of the sp
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
