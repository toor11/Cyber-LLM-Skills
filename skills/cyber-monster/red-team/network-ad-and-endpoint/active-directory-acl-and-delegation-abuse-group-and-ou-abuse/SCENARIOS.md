# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`active-directory-acl-and-delegation-abuse-group-and-ou-abuse`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: AddMember

- **Provenance:** Source: `CYBER_CPT/hacker_recipes` | CWE: `CWE-269`
- **Context / Surface:** Source: hacker_recipes (en)
- **Root Cause / Analysis:** --- authors: CravateRouge, ShutdownRepo, sckdev, 0xblank, jamarir category: ad --- # AddMember This abuse can be carried out when controlling an object that has a 'GenericAll', 'GenericWrite', 'Self', 'AllExtendedRights' or 'Self-Membership', over the target group. ::: tabs === U
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 2: qibosoft V7.0 allows CSRF via admin/index.php?lfj=member&action=addmember to add a user account.

- **Provenance:** Source: `CYBER_CPT/go_exploitdb` | CWE: `CWE-269`
- **Context / Surface:** Source: go_exploitdb (en)
- **Root Cause / Analysis:** # qibosoft V7.0 allows CSRF via admin/index.php?lfj=member&action=addmember to add a user account. - **CVE**: CVE-2018-18201 - **Exploit Type**: InTheWild - **Exploit ID**: InTheWild-1a9c16582be4c352f3fe2f923678ffe0 - **URL**: https://github.com/yanchongchong/swallow/issues/2 qib
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
