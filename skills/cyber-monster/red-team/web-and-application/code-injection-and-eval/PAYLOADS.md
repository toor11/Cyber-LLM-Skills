# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`code-injection-and-eval`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `code-injection-and-eval`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### Arithmetic reachability differential

**Expected differential:** the computed value appears for the expression form and not for the inert literal, and reverts when input is pinned to a closed grammar

```text
formula=1336 (inert literal baseline, expect it echoed unchanged)
formula=668%2B669 (benign addition, expect the computed 1337)
formula=191*7 (benign product, expect the computed 1337)
```

### Dialect identification by compile error

**Expected differential:** an unbalanced token raises a language-specific syntax or compile error for the evaluator dialect, distinct from a generic 400

```text
formula=(1 (unterminated parenthesis, expect a parser error not a 400)
formula='a'.'b' (PHP string concatenation probe, expect ab or a parse error)
```

### Non-destructive presence check

**Expected differential:** a reference to a benign builtin resolves or is rejected, distinguishing a pass-through literal from a live evaluator

```text
formula=len('abc') (expect 3 only if a Python evaluator runs it)
formula=Math.max(2,3) (expect 3 only if a JS evaluator runs it)
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
