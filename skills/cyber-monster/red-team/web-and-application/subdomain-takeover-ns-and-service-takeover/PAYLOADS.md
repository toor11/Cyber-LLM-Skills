# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`subdomain-takeover-ns-and-service-takeover`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `subdomain-takeover-ns-and-service-takeover`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### Delegation comparison

**Expected differential:** the parent NS set and the delegated nameservers answers disagree, or the delegated nameservers return SERVFAIL, marking a lame delegation

```text
dig NS legacy.<target-domain> @<parent-nameserver>
dig +norecurse SOA legacy.<target-domain> @<delegated-nameserver>
dig NS legacy.<target-domain> +trace
```

### Nameserver and service registrability (read-only)

**Expected differential:** the delegated nameserver domain or service identifier is reported available to register, confirming re-acquisition without taking authority

```text
whois ns1.<lapsed-dns-provider> | grep -i 'No match'
curl -sS -o /dev/null -w '%{http_code}' https://<expired-service-domain>/
```

### Unallocated address check

**Expected differential:** the A-record address falls in a cloud elastic range and is not currently held by the organization account

```text
dig +short A app.<target-domain>
aws ec2 describe-addresses --public-ips <released-ip> 2>&1 | grep -i 'InvalidAddress'
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
