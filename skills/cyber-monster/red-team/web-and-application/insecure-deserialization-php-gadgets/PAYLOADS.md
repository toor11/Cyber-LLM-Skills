# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`insecure-deserialization-php-gadgets`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `insecure-deserialization-php-gadgets`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### Object-instantiation oracle (benign class)

**Expected differential:** a scalar value and a benign object string differ only if unserialize instantiates the object; a whitelisted class with an observable but harmless __wakeup confirms instantiation

```text
prefs=O:8:"stdClass":0:{}
prefs=benign-scalar-value (control)
```

### phar stream-wrapper presence probe

**Expected differential:** pointing a metadata function at a phar:// path triggers metadata deserialization on the phar path but not on a plain path, proving the wrapper reaches the sink

```text
avatar=phar://<assessor-controlled-path>/benign.phar/test.txt
avatar=/uploads/benign.txt (control)
```

### allowed_classes differential

**Expected differential:** an object string naming an unexpected class decodes into __PHP_Incomplete_Class when allowed_classes is false, versus a live object when it is not set

```text
prefs=O:4:"User":0:{} (expected class)
prefs=O:11:"ArrayObject":0:{} (unexpected class)
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
