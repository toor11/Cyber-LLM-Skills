# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`webshell-management-and-interaction`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `webshell-management-and-interaction`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### Served-bytes baseline

**Expected differential:** a plain text marker is uploaded and requested; it returns verbatim, establishing what a non-executing path looks like

```text
upload wshell-marker.txt with body: WSHELL-STATIC-7a19
GET /uploads/wshell-marker.txt  -> expect literal WSHELL-STATIC-7a19
```

### Execution-context marker (benign, static output)

**Expected differential:** a marker that only emits a fixed string when interpreted returns the computed value instead of its source bytes, proving the interpreter ran

```text
upload wshell-probe.php with body: <?php echo 'WSHELL-EXEC-' . (6*7); ?>
GET /uploads/wshell-probe.php  -> computed output proves execution, source bytes prove inert
```

### Handler-mapping extension sweep

**Expected differential:** the same benign marker under alternate extensions reveals which forms the handler interprets versus serves as data

```text
GET /uploads/wshell-probe.phtml
GET /uploads/wshell-probe.phar
GET /uploads/wshell-probe.php.jpg
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
