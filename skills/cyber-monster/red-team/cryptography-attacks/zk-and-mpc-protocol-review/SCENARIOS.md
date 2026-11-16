# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`zk-and-mpc-protocol-review`](SKILL.md) | Family: **Cryptography Attacks**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: Commitment Issues ( PicoCTF )

- **Provenance:** Source: `CYBER_CPT/ctf_search` | CWE: `CWE-327`
- **Context / Surface:** Source: ctf_search (en)
- **Root Cause / Analysis:** # Commitment Issues ( PicoCTF ) ## Description I accidentally wrote the flag down. Good thing I deleted it! They provided us with a zip file, let’s download it. 'bash wget http://example.com/example.zip $ unzip challenge.zip Archive: challenge.zip creating: drop-in/ creating: d
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 2: gnark's Groth16 commitment extension unsound for more than one commitment

- **Provenance:** Source: `CYBER_CPT/osv` | CWE: `CWE-327`
- **Context / Surface:** Source: osv (en)
- **Root Cause / Analysis:** # gnark's Groth16 commitment extension unsound for more than one commitment - **OSV ID**: GHSA-q3hw-3gm4-w5cr - **CVE**: CVE-2024-45039 - **CVSS**: CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N - **Published**: 2024-09-06T19:53:20Z - **Modified**: 2024-11-20T19:26:02Z - **Affected
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: gnark's Groth16 commitment extension unsound for more than one commitment

- **Provenance:** Source: `CYBER_CPT/gh_advisories` | CWE: `CWE-327`
- **Context / Surface:** Source: gh_advisories (en)
- **Root Cause / Analysis:** ### Description The summary is that the proof of knowledge associated to a commitment is crucial to bind the commitment to the actual circuit variables that were supposed to be committed. However, the same σ is used for all proofs of knowledge for the commitments, which allows mi
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: Walks up the {effect} chain to find a witness that provides map

- **Provenance:** Source: `CYBER_CPT/exploitdb` | CWE: `CWE-327`
- **Context / Surface:** Source: exploitdb (en)
- **Root Cause / Analysis:** # Walks up the {effect} chain to find a witness that provides map Google Chrome V8 - Turbofan JSCallReducer::ReduceArrayIndexOfIncludes Out-of-Bounds Read/Write - **ExploitDB ID**: 46837 - **Author**: Google Security Research - **Platform**: multiple - **Type**: dos - **URL**: ht
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: AWS SDK for PHP's S3 Encryption Client has a Key Commitment Issue

- **Provenance:** Source: `CYBER_CPT/gh_advisories` | CWE: `CWE-327`
- **Context / Surface:** Source: gh_advisories (en)
- **Root Cause / Analysis:** ## Summary S3 Encryption Client for PHP is an open-source client-side encryption library used to facilitate writing and reading encrypted records to S3. When the encrypted data key (EDK) is stored in an "Instruction File" instead of S3's metadata record, the EDK is exposed to an
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: go-witness is Vulnerable to Improper Verification of AWS EC2 Identity Documents

- **Provenance:** Source: `CYBER_CPT/gh_advisories` | CWE: `CWE-327`
- **Context / Surface:** Source: gh_advisories (en)
- **Root Cause / Analysis:** ### Impact This vulnerability only affects users of the AWS attestor. Users of the AWS attestor could have unknowingly received a forged identity document. While this may seem unlikely, AWS recently issued a security bulletin about IMDS (Instance Metadata Service) impersonation.
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
