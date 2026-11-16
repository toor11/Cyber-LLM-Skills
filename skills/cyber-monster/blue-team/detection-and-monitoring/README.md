# Detection and Monitoring

> Tree: `blue-team/detection-and-monitoring` | **29 sub-skills** | Root router: [`../../SKILL.md`](../../SKILL.md)

**Weak-Model Rule:** Pick the **1 best matching** sub-skill below (`flagship` or `core` first unless a variant profile matches exactly), read its `SKILL.md`, and answer directly using its *Strict Output Contract*.

| Sub-skill | Tier | Focus & When to Use |
|---|---|---|
| [`detection-engineering`](detection-engineering/SKILL.md) | **flagship** | Builds and maintains detections: identifying observable behaviours, writing and validating rules, mapping to ATT&CK, and managing the detection l |
| [`alert-tuning-and-false-positive-reduction`](alert-tuning-and-false-positive-reduction/SKILL.md) | **core** | Reduces alert noise: measuring precision, identifying benign patterns, adding filters without blinding the rule, and tracking tuning outcomes |
| [`atomic-red-team-validation`](atomic-red-team-validation/SKILL.md) | **core** | Validates detections with Atomic Red Team and controlled emulation: test selection, safe execution, and confirming both detection firing and tele |
| [`cloud-detection-and-logging`](cloud-detection-and-logging/SKILL.md) | **core** | Detects malicious cloud activity: audit log coverage, control plane versus data plane events, identity-based detections and multi-cloud log norma |
| [`detection-as-code-and-testing`](detection-as-code-and-testing/SKILL.md) | **core** | Manages detections as code: version control, CI validation, automated rule testing and safe deployment pipelines |
| [`dns-and-beacon-analytics`](dns-and-beacon-analytics/SKILL.md) | **core** | Detects command and control through DNS and beaconing: entropy analysis, beacon periodicity, DGA detection and tunnelling indicators |
| [`email-security-monitoring`](email-security-monitoring/SKILL.md) | **core** | Monitors email for threats: authentication results, sender reputation, attachment and link analysis, and BEC indicators |
| [`endpoint-detection-and-edr-operations`](endpoint-detection-and-edr-operations/SKILL.md) | **core** | Operates endpoint detection: understanding EDR telemetry, writing endpoint queries, triaging endpoint alerts and validating sensor coverage |
| [`ics-and-ot-passive-network-monitoring`](ics-and-ot-passive-network-monitoring/SKILL.md) | **core** | Monitors OT/ICS Purdue Level 0-3 networks passively without active polling: Modbus/S7comm/DNP3/OPC-UA function-code allowlisting, unauthorized PL |
| [`identity-and-authentication-monitoring`](identity-and-authentication-monitoring/SKILL.md) | **core** | Monitors identity systems for attack patterns: impossible travel, MFA fatigue, token replay, password spray and privilege changes |
| [`kubernetes-audit-log-and-runtime-detection`](kubernetes-audit-log-and-runtime-detection/SKILL.md) | **core** | Detects cluster compromise via Kubernetes API Audit Logs and Falco/Tetragon eBPF runtime events: `pods/exec` and `pods/attach`, anonymous/system: |
| [`log-source-onboarding-and-parsing`](log-source-onboarding-and-parsing/SKILL.md) | **core** | Onboards log sources correctly: identifying required event types, parsing and normalization, field mapping to a schema and validating coverage |
| [`mitre-attack-mapping`](mitre-attack-mapping/SKILL.md) | **core** | Maps activity and coverage to MITRE ATT&CK: technique identification, sub-technique selection, and using ATT&CK for coverage assessment |
| [`network-detection-and-ids`](network-detection-and-ids/SKILL.md) | **core** | Detects malicious network activity: IDS rule writing, traffic baselining, protocol anomaly detection and encrypted traffic analysis |
| [`security-metrics-and-detection-coverage`](security-metrics-and-detection-coverage/SKILL.md) | **core** | Measures security operations performance: MTTD and MTTR, coverage percentages, alert quality metrics and reporting to stakeholders |
| [`siem-query-and-log-analysis`](siem-query-and-log-analysis/SKILL.md) | **core** | Queries SIEM platforms effectively: KQL, SPL and Elastic DSL patterns, field extraction, aggregation and threat hunting queries |
| [`sigma-rule-authoring`](sigma-rule-authoring/SKILL.md) | **core** | Writes and validates Sigma rules: log source selection, field mapping, condition logic, filters and conversion to backend query languages |
| [`yara-rule-authoring`](yara-rule-authoring/SKILL.md) | **core** | Writes and validates YARA rules for files and memory: string selection, modifiers, condition design and false-positive control |
| [`data-loss-prevention-monitoring`](data-loss-prevention-monitoring/SKILL.md) | **leaf** | Monitors for data exfiltration: DLP policy design, egress baselining, unusual transfer detection and alert triage |
| [`detection-engineering-behaviour-to-observable`](detection-engineering-behaviour-to-observable/SKILL.md) | **leaf** | Behaviour to observable translation |
| [`detection-engineering-rule-lifecycle`](detection-engineering-rule-lifecycle/SKILL.md) | **leaf** | Detection rule lifecycle management |
| [`dns-and-beacon-analytics-beacon-periodicity`](dns-and-beacon-analytics-beacon-periodicity/SKILL.md) | **leaf** | Beacon periodicity and jitter analysis |
| [`dns-and-beacon-analytics-dga-and-tunneling`](dns-and-beacon-analytics-dga-and-tunneling/SKILL.md) | **leaf** | DGA and DNS tunnelling detection |
| [`siem-query-and-log-analysis-elastic-and-eql`](siem-query-and-log-analysis-elastic-and-eql/SKILL.md) | **leaf** | Elastic and EQL queries |
| [`siem-query-and-log-analysis-kql-and-sentinel`](siem-query-and-log-analysis-kql-and-sentinel/SKILL.md) | **leaf** | KQL and Microsoft Sentinel queries |
| [`siem-query-and-log-analysis-splunk-spl`](siem-query-and-log-analysis-splunk-spl/SKILL.md) | **leaf** | Splunk SPL query patterns |
| [`sigma-rule-authoring-cloud-and-network-rules`](sigma-rule-authoring-cloud-and-network-rules/SKILL.md) | **leaf** | Sigma rules for cloud and network sources |
| [`sigma-rule-authoring-windows-event-rules`](sigma-rule-authoring-windows-event-rules/SKILL.md) | **leaf** | Sigma rules for Windows event logs |
| [`waf-and-web-monitoring`](waf-and-web-monitoring/SKILL.md) | **leaf** | Monitors web traffic for attacks: WAF log review, attack pattern recognition, tuning blocked versus allowed rules and identifying successful bypa |
