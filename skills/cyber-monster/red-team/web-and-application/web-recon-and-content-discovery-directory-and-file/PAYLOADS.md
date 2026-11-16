# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`web-recon-and-content-discovery-directory-and-file`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `web-recon-and-content-discovery-directory-and-file`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### Bulk-404 baseline capture

**Expected differential:** several guaranteed-missing paths return a stable status and length that become the comparison floor; any later divergence is the signal

```text
GET /dirfile-baseline-does-not-exist-9f3a HTTP/1.1
GET /dirfile-baseline-also-missing-7b2c/ HTTP/1.1
```

### Backup and VCS artefact probe

**Expected differential:** the artefact path returns a status or length that diverges from the bulk-404 baseline, proving the file is served inside the root

```text
GET /.git/config HTTP/1.1
GET /config.php.bak HTTP/1.1
GET /site-backup.zip HTTP/1.1
```

### Extension fuzz against a known base name

**Expected differential:** swapping only the extension on a confirmed base name reveals which trailing form the server stores, with the base response as control

```text
GET /app.old HTTP/1.1  (base: /app.php)
GET /app.php~ HTTP/1.1  (editor swap file)
```

### Virtual-host differential

**Expected differential:** the same path with a fuzzed Host header returns different length, proving the surface is the Host namespace rather than the path

```text
GET / HTTP/1.1\r\nHost: dirfile-vhost-probe.<target-domain>
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
