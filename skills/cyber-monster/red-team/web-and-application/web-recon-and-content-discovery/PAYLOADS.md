# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`web-recon-and-content-discovery`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `web-recon-and-content-discovery`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### Known-absent baseline

**Expected differential:** definitely-absent paths establish the not-here signature of status, length, and redirect

```text
GET /wrcd-absent-a1b2 (expect 404 baseline)
GET /wrcd-absent-c3d4/ (second absent control)
```

### Backup and source-map hunt

**Expected differential:** a map or backup suffix returns 200 and distinct content versus the baseline

```text
GET /static/app.js.map (expect source map if exposed)
GET /config.php.bak (expect backup if exposed)
```

### Virtual-host and robots disclosure

**Expected differential:** a different Host or a robots entry reveals unlinked surface

```text
GET / with Host: internal.target.example
GET /robots.txt (read Disallow entries for unlinked paths)
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
