# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`aws-attacks-iam-and-role-chaining`](SKILL.md) | Family: **Cloud, Container and Supply Chain**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: AWS STS AssumeRole Misuse

- **Provenance:** Source: `CYBER_CPT/sigmahq` | CWE: `CWE-269`
- **Context / Surface:** Source: sigmahq (en)
- **Root Cause / Analysis:** # AWS STS AssumeRole Misuse Identifies the suspicious use of AssumeRole. Attackers could move laterally and escalate privileges. - **Level**: N/A - **Status**: test - **Author**: Austin Songer @austinsonger - **Date**: 2021-07-24 - **Category**: Cloud ## Rule 'yaml title: AWS S
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 2: AssumeRole [![Slack] (https://slack.min.io/slack?type=svg)] (https://slack.min.io)

- **Provenance:** Source: `CYBER_CPT/github_security_md` | CWE: `CWE-269`
- **Context / Surface:** Source: github_security_md (en)
- **Root Cause / Analysis:** # AssumeRole [![Slack] (https://slack.min.io/slack?type=svg)] (https://slack.min.io) ## Introduction Returns a set of temporary security credentials that you can use to access MinIO resources. AssumeRole requires authorization credentials for an existing user on MinIO. The advantag
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: AWS Amplify CLI has incorrect trust policy management

- **Provenance:** Source: `CYBER_CPT/osv` | CWE: `CWE-269`
- **Context / Surface:** Source: osv (en)
- **Root Cause / Analysis:** # AWS Amplify CLI has incorrect trust policy management AWS Amplify CLI has incorrect trust policy management - **OSV ID**: GHSA-846g-p7hm-f54r - **CVE**: CVE-2024-28056 - **CVSS**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H - **Published**: 2024-04-15T18:30:51Z - **Modified**:
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: AWS Amplify CLI has incorrect trust policy management

- **Provenance:** Source: `CYBER_CPT/gh_advisories` | CWE: `CWE-269`
- **Context / Surface:** Source: gh_advisories (en)
- **Root Cause / Analysis:** Amazon AWS Amplify CLI before 12.10.1 incorrectly configures the role trust policy of IAM roles associated with Amplify projects. When the Authentication component is removed from an Amplify project, a Condition property is removed but "Effect":"Allow" remains present, and conseq
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: Jenkins Bitbucket Branch Source Plugin has incorrect trust policy behavior for pull requests

- **Provenance:** Source: `CYBER_CPT/gh_advisories` | CWE: `CWE-269`
- **Context / Surface:** Source: gh_advisories (en)
- **Root Cause / Analysis:** In Jenkins Bitbucket Branch Source Plugin 866.vdea_7dcd3008e and earlier, except 848.850.v6a_a_2a_234a_c81, when discovering pull requests from forks, the trust policy "Forks in the same account" allows changes to Jenkinsfiles from users without write access to the project when u
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
