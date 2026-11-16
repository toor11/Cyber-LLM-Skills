# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`ssrf-cloud-metadata`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `ssrf-cloud-metadata`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### Reachability baseline (non-sensitive key)

**Expected differential:** the instance-id path returns data while an off-instance control does not, proving link-local reachability

```text
url=http://169.254.169.254/latest/meta-data/instance-id
url=http://169.254.169.254/latest/meta-data/placement/region
```

### IMDSv2 header contract

**Expected differential:** a header-bearing request returns a token while the plain GET is refused, proving the client can satisfy IMDSv2

```text
X-aws-ec2-metadata-token-ttl-seconds: 60
X-aws-ec2-metadata-token: <token-from-put>
```

### Provider header probes (GCP and Azure)

**Expected differential:** the provider-required header returns metadata while its absence is refused

```text
Metadata-Flavor: Google
Metadata: true
```

### Role enumeration (read-only)

**Expected differential:** the role name lists under security-credentials without fetching the secret body

```text
url=http://169.254.169.254/latest/meta-data/iam/security-credentials/
url=http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
