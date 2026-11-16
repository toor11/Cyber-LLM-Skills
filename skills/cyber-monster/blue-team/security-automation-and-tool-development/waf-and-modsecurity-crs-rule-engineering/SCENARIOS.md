# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`waf-and-modsecurity-crs-rule-engineering`](SKILL.md) | Family: **Security Automation and Tool Development**

Representative WAF tuning failures, each with the artefact that proves the diagnosis.

## Case 1: The rule was disabled instead of scoped

- **Surface & Preconditions:** a customer-facing form triggers rule 942100 on one endpoint, and the operator runs `SecRuleRemoveById 942100`.
- **Root cause & impact:** SQL-injection detection is now off for the entire application, including the login and search endpoints, to fix one field. The control still reports as "enabled" in configuration reviews.
- **Verification & fix:** replace the global removal with `ctl:ruleRemoveTargetById=942100;ARGS:<field>` inside a rule scoped to that URI, and add a regression case proving an injection attempt on the same endpoint still blocks.

## Case 2: The ctl did nothing

- **Surface & Preconditions:** an exclusion for a body argument was placed in a phase 1 rule, matching only the `REQUEST_URI`.
- **Root cause & impact:** body arguments do not exist in phase 1, so the `ctl` names a target that is not populated. It executes without error and removes nothing, and the false positive persists while the change record says it was excluded.
- **Verification & fix:** move the rule to phase 2, verify with a request that reproduces the original alert, and check the audit log for the excluded rule no longer appearing.

## Case 3: Paranoia lowered to silence one rule

- **Surface & Preconditions:** a site runs at PL2 and one PL2 rule is noisy, so the operator drops `tx.blocking_paranoia_level` to 1.
- **Root cause & impact:** every PL2 detection across the whole application stops contributing score — dozens of rules disabled to fix one. The change looks like a single variable edit in review.
- **Verification & fix:** keep the blocking level and exclude the specific rule's target, or use `tx.detection_paranoia_level` to evaluate the higher PL without its score contributing.

## Case 4: Low-score block after a tuning change

- **Surface & Preconditions:** a threshold was lowered, or a severity increment raised, without re-running the suite.
- **Root cause & impact:** requests that previously scored below the threshold now block, so legitimate traffic fails in production while the individual rules behave exactly as before.
- **Verification & fix:** treat threshold and increment changes as rule changes; run the full regression suite plus a production-shaped request set and compare block rates before and after.
