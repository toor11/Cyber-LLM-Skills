# Detection Signals and Blue-Team Handoff

> Sub-skill: [`ssrf-internal-service-pivot`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- Flow logs showing the web tier connecting to internal service ports such as 2375, 6379, 9200, 8500, or 10250 with no documented dependency.
- Kubernetes API audit events whose source IP is an application pod using the default service account unexpectedly.
- Docker daemon access logs on 2375 originating from a web application host.
- source or url parameters containing internal hostnames such as kubernetes.default or names ending in .internal.
- Elasticsearch or datastore query logs with requests from the web subnet outside normal integration paths.
- A spike of connection attempts from one app host across many internal ports in a short window.
- Split-horizon DNS lookups for internal-only names originating from the application tier.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`cloud-detection-and-logging`](../../../blue-team/detection-and-monitoring/cloud-detection-and-logging/SKILL.md) | Detection queries, triage, and hardening for this technique |
