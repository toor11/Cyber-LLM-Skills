# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`stix-taxii-and-misp-ioc-pipeline-scripting`](SKILL.md) | Family: **Security Automation and Tool Development**

Representative IOC pipeline failures, each with the artifact that proves the diagnosis.

## Case 1: The pipeline blocked its own VPN concentrator

- **Surface & Preconditions:** a feed contains an indicator for a shared cloud range, and the pipeline pushes it to the perimeter blocklist.
- **Root cause & impact:** the range also hosts the organization's VPN endpoint. Remote access fails for everyone, and the incident is larger than the one being responded to.
- **Verification & fix:** filter non-routable, own-domain, resolver, and shared-CDN values before enforcement; keep the shared-range list under change control; add the range as a permanent fixture.

## Case 2: Indicators never matched anything

- **Surface & Preconditions:** the feed delivers defanged values (`evil[.]example`) and the pipeline compares them verbatim against live DNS logs.
- **Root cause & impact:** a defanged string cannot equal a real hostname, so every indicator silently matches nothing and the pipeline looks like it is working — it stores data and blocks nothing.
- **Verification & fix:** refang first, then canonicalize (lowercase, strip trailing dot, normalize IP form) on both feed and telemetry sides; assert with a fixture whose refanged form must match.

## Case 3: A year-old indicator still blocking traffic

- **Surface & Preconditions:** indicators are published without `valid_until` and the pipeline has no sweeper.
- **Root cause & impact:** blocks accumulate permanently. When the domain later changes hands to a legitimate business, traffic to it stays blocked and nobody can say why.
- **Verification & fix:** set an explicit validity window, run a scheduled sweeper that removes expired entries, and record the removal so a future "why is this blocked" question has an answer.

## Case 4: Confidence treated as constant

- **Surface & Preconditions:** every indicator from a feed is enforced at the feed's stated confidence regardless of age.
- **Root cause & impact:** a domain that was malicious two years ago and is now parked keeps full enforcement weight, so the blocklist grows without becoming more accurate.
- **Verification & fix:** decay confidence by age before comparing to the enforcement threshold, and keep the decayed value in the record so threshold changes are auditable.
