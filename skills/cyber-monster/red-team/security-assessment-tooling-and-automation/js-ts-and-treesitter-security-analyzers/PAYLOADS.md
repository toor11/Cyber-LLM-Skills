# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`js-ts-and-treesitter-security-analyzers`](SKILL.md) | Family: **Security Assessment Tooling and Automation**

Probes for `js-ts-and-treesitter-security-analyzers`. Each group names the baseline it is compared against and the differential that counts. Run every probe twice; a one-off difference is not proof.

## Capture-set baseline

Baseline: the negative sample produces zero filtered captures. Probe: the positive sample produces exactly one. Differential: any extra capture is a rule defect.

```python
tree = parser.parse(open('sample_negative.js','rb').read())
print(len(list(QueryCursor(query).captures(tree.root_node))))
```

## ESLint rule fixture

Baseline: valid fixture yields no errors. Probe: invalid fixture yields the configured message id. Differential: both must match the RuleTester expectation.

```javascript
const { RuleTester } = require('eslint');
const tester = new RuleTester({ languageOptions: { ecmaVersion: 2022 } });
tester.run('no-raw-html', rule, { valid: [], invalid: [] });
```

## Usage Rules

- Baseline first, probe second, same scope and same credentials for both runs.
- Stop at the first confirmed differential; do not expand the probe once it fires.
- Pair every confirmed finding with the structural remediation in [`SKILL.md`](SKILL.md).
