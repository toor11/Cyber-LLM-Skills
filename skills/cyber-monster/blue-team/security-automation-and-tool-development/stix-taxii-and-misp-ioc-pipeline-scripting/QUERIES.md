# Detection Queries and Telemetry Artifacts

> Sub-skill: [`stix-taxii-and-misp-ioc-pipeline-scripting`](SKILL.md) | Family: **Security Automation and Tool Development**

Ingest, filter, and expiry artifacts owned by this slug. Confirm STIX object shapes and MISP attribute types against the installed client versions before deployment.

## Observable Signals

| # | Indicator / Artifact | Confidence | Proves |
|---|---|---|---|
| 1 | `pattern_type` == `stix` with a parseable pattern | High | The pattern is in the language being interpreted |
| 2 | Refanged and canonicalized value | High | The indicator can match live telemetry and dedupe consistently |
| 3 | Self-harm filter decision recorded with a reason | High | No internal or shared-infrastructure value reached enforcement |
| 4 | `valid_until` in the past | High | The sweeper must remove the indicator from enforcement |
| 5 | Decayed confidence below the enforcement floor | High | Age reduced the indicator's weight; it is stored but not enforced |

## Detection Artifacts

```text
[stix-taxii-and-misp-ioc-pipeline-scripting:rule-spec] refang -> canonicalize -> self-harm filter -> confidence decay -> enforce or store
[stix-taxii-and-misp-ioc-pipeline-scripting:filter-fp] private, loopback, own-domain, resolver, and shared-CDN values never reach a blocklist
[stix-taxii-and-misp-ioc-pipeline-scripting:correlate] indicator id + valid_from/valid_until answers "why is this blocked" and "until when"
```

Reading a TAXII collection with paging, so a large collection is not truncated to its first page (Python invoked from PowerShell 5.1):

```python
from taxii2client.v21 import Collection, as_pages

collection = Collection("https://taxii.example.internal/api1/collections/91a7b528/", user="u", password="p")
total = 0
for bundle in as_pages(collection.get_objects, per_request=50):
    for obj in bundle.get("objects", []):
        if obj.get("type") == "indicator":
            total += 1
print(f"indicators={total}")
```

Building a compliant indicator with an explicit validity window:

```python
import datetime as dt

from stix2 import Indicator

now = dt.datetime.now(dt.timezone.utc)
indicator = Indicator(
    name="Malicious payload host",
    pattern_type="stix",
    pattern="[domain-name:value = 'evil.example']",
    valid_from=now,
    valid_until=now + dt.timedelta(days=30),
    confidence=70,
    labels=["malicious-activity"],
)
print(indicator.serialize(pretty=True))
```

Self-harm filter checks that must all be True for the sample set:

```python
import ipaddress

def self_harm(addr: str) -> bool:
    ip = ipaddress.ip_address(addr)
    return ip.is_private or ip.is_loopback or ip.is_link_local

for probe in ["10.1.2.3", "127.0.0.1", "169.254.10.10", "203.0.113.9"]:
    print(probe, self_harm(probe))
```

Publishing to MISP with a restricted distribution for exercise data:

```python
from pymisp import MISPEvent, PyMISP

misp = PyMISP("https://misp.example.internal", "api-key-from-secret-store", ssl=True, timeout=30)
draft = MISPEvent()
draft.info = "IOC pipeline test event"
draft.distribution = 0
draft.threat_level_id = 4
draft.analysis = 0
draft.published = False
draft.add_attribute("domain", "evil.example", to_ids=False)
print(misp.add_event(draft, pythonify=True).uuid)
```

## Deployment Gates

- Validate against >=1 positive replay and a 7-day benign production baseline.
- Document known benign admin tools or scanners before enabling alerting.
- Keep the own-domain and shared-range lists in version control and review changes like firewall rules.
- Run the expiry sweeper on a schedule and alert if it stops; unexpired indicators accumulate into permanent blocks.
