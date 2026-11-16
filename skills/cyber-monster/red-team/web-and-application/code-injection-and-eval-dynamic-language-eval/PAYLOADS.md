# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`code-injection-and-eval-dynamic-language-eval`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `code-injection-and-eval-dynamic-language-eval`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### Boolean truth-value differential

**Expected differential:** the response or row set follows the boolean and collapses to one outcome once a structured parser replaces the interpreter call

```text
filter=len('dyneval')==7 (true branch, expect the normal result set)
filter=len('dyneval')==1 (false branch, expect an empty or reduced set)
```

### Interpreter identification

**Expected differential:** a benign runtime-specific builtin resolves only on its own interpreter, naming PHP, Python, Ruby, or Node

```text
filter=''.__class__.__name__ (expect 'str' only on a live Python eval)
filter=[].class.name (Ruby receiver probe, expect 'Array' or a parse error)
```

### Sandbox introspection presence check

**Expected differential:** a non-destructive dunder access resolves rather than raising NameError, proving the object graph is reachable

```text
filter=row.__class__ is not None (expect True if object introspection survives)
filter=(1).__class__.__base__ is object (expect True on an unsealed Python sandbox)
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
