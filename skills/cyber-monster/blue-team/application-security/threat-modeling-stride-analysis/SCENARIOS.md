# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`threat-modeling-stride-analysis`](SKILL.md) | Family: **Application Security**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: ImageMagick (WriteBMPImage): 32-bit integer overflow when writing BMP scanline stride → heap buffer

- **Provenance:** Source: `CYBER_CPT/gh_advisories` | CWE: `CWE-20`
- **Context / Surface:** Source: gh_advisories (en)
- **Root Cause / Analysis:** ## Summary A 32-bit integer overflow in the BMP encoder’s scanline-stride computation collapses 'bytes_per_line' (stride) to a tiny value while the per-row writer still emits '3 × width' bytes for 24-bpp images. The row base pointer advances using the (overflowed) stride, so the
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 2: Trust Boundary Violation due to Incomplete Blacklist in Test Failure Processing in Ares

- **Provenance:** Source: `CYBER_CPT/osv` | CWE: `CWE-20`
- **Context / Surface:** Source: osv (en)
- **Root Cause / Analysis:** # Trust Boundary Violation due to Incomplete Blacklist in Test Failure Processing in Ares Trust Boundary Violation due to Incomplete Blacklist in Test Failure Processing in Ares - **OSV ID**: GHSA-883x-6fch-6wjx - **CVE**: CVE-2024-23683 - **CVSS**: CVSS:3.1/AV:L/AC:L/PR:L/UI:R/S
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: Scott Manktelow Design Stride 1.0 Courses - 'detail.php' Multiple SQL Injections

- **Provenance:** Source: `CYBER_CPT/expku` | CWE: `CWE-20`
- **Context / Surface:** Source: expku (en)
- **Root Cause / Analysis:** # Web Fundamentals — TryHackMe ![\\"Papadopejk\\"] (\\"https://miro.medium.com/v2/resize:fill:88:88/1*_gsMDEKfpKacrgVY- xpkXA.jpeg\\") Papadopejk · Follow 4 min read · Jul 1, 2020 23 2 Listen Share Hello my fellow hackers. Today we are going to take a walk-through inside a TryHack
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: Scott Manktelow Design Stride 1.0 - 'Content Management System main.php' SQL Injection

- **Provenance:** Source: `CYBER_CPT/expku` | CWE: `CWE-20`
- **Context / Surface:** Source: expku (en)
- **Root Cause / Analysis:** # TryHackMe: Introductory Researching ![\\"Megha] (\\"https://miro.medium.com/v2/resize:fill:88:88/1*bkRAl70nH5HylrRHufMZYA.jpeg\\") Megha Kumari · Follow 3 min read · Jul 1, 2020 4 Listen Share ![\\"\\"] (\\"https://miro.medium.com/v2/resize:fit:700/0*GdH3MyTJN4oJiZyk.png\\") [Tas
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: Trust Boundary Violation due to Incomplete Blacklist in Test Failure Processing in Ares

- **Provenance:** Source: `CYBER_CPT/gh_advisories` | CWE: `CWE-20`
- **Context / Surface:** Source: gh_advisories (en)
- **Root Cause / Analysis:** ### Impact This allows an attacker to create special subclasses of 'InvocationTargetException' that escape the exception sanitization because JUnit extracts the cause in a trusted context before the exception reaches Ares. This means that arbitrary student code can be executed in
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: Tensorflow is an Open Source Machine Learning Framework. The estimator for the cost of some convolut

- **Provenance:** Source: `CYBER_CPT/go_exploitdb` | CWE: `CWE-20`
- **Context / Surface:** Source: go_exploitdb (en)
- **Root Cause / Analysis:** # Tensorflow is an Open Source Machine Learning Framework. The estimator for the cost of some convolution operations can be made to execute a division by 0. The function fails to check that the stride a - **CVE**: CVE-2022-21725 - **Exploit Type**: InTheWild - **Exploit ID**: InT
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
