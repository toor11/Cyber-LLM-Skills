# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`subdomain-takeover-cname-fingerprints`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `subdomain-takeover-cname-fingerprints`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### CNAME target extraction

**Expected differential:** the terminal CNAME resolves to a known provider host, selecting the fingerprint class

```text
dig +short CNAME marketing.<target-domain>
host -t CNAME blog.<target-domain>
```

### Provider signature match

**Expected differential:** the HTTP body matches a provider unclaimed-resource signature while an owned baseline does not

```text
curl -sS https://marketing.<target-domain>/ | grep -i 'github pages site'
curl -sS https://files.<target-domain>/ | grep -i 'NoSuchBucket'
```

### Read-only availability check

**Expected differential:** the provider API reports the extracted resource name as unregistered, confirming claimability without creating it

```text
aws s3api head-bucket --bucket files-legacy 2>&1 | grep -i 'Not Found'
curl -sS -o /dev/null -w '%{http_code}' https://marketing-legacy.github.io/
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
