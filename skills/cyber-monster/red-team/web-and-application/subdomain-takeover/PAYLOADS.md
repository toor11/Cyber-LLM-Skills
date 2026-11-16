# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`subdomain-takeover`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `subdomain-takeover`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### Record-type and chain resolution

**Expected differential:** the CNAME chain terminates at a provider host or NXDOMAIN rather than an owned address, categorizing the dangling record

```text
dig +noall +answer CNAME assets-legacy.<target-domain>
dig +noall +answer A assets-legacy.<target-domain>
dig NS legacy-zone.<target-domain>
```

### Provider fingerprint fetch

**Expected differential:** the subdomain returns the provider unclaimed-resource body while an owned subdomain returns live content

```text
curl -sS -H 'Host: assets-legacy.<target-domain>' https://<provider-edge-host>/
curl -sS https://assets-legacy.<target-domain>/ | grep -i 'NoSuchBucket'
```

### Claimability check (read-only)

**Expected differential:** the provider API reports the resource name as available to register, confirming the dangling record is claimable without serving content

```text
aws s3api head-bucket --bucket assets-legacy (expect 404 Not Found)
gcloud storage buckets describe gs://assets-legacy (expect NotFound)
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
