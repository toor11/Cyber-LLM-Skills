# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`insecure-deserialization-python-and-ruby-gadgets`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `insecure-deserialization-python-and-ruby-gadgets`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### Pickle opcode presence probe

**Expected differential:** a JSON body is accepted as data while a pickle stream of a builtin tuple is reconstructed only by pickle.loads; a benign marker confirms the loader ran without a chain

```text
state=<base64 pickle protocol-2 of the tuple (1, 2)>
state={"a": 1} as JSON (control)
```

### YAML tag discriminator

**Expected differential:** a plain YAML scalar loads under any loader while a !!python/object/apply tag is instantiated only by an unsafe loader, isolating which loader is in use

```text
config: {name: test}
config: !!python/object/apply:tuple [[1, 2]]
```

### Ruby Marshal magic probe

**Expected differential:** a JSON body is treated as data while a Marshal stream beginning 04 08 rebuilds a plain Hash only under Marshal.load, proving Ruby Marshal on untrusted input

```text
data=<base64 Marshal of a plain Hash, magic 0408>
data={"k":"v"} as JSON (control)
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
