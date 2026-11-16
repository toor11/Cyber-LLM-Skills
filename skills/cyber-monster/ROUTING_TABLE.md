# Routing Table

Complete sub-skill trigger index across all 19 families. Match the task to a trigger cell and open that `SKILL.md` — or select an ordered sequence of `SKILL.md` files when the task spans multiple stages, protocols, or a red-to-blue handoff. No script is required. If the task is a whole family rather than one technique, open that family's `README.md` first.

## blue-team / Application Security

| Sub-skill | Tier | Triggers |
|---|---|---|
| [`ai-and-llm-application-defense`](blue-team/application-security/ai-and-llm-application-defense/SKILL.md) | core | llm defense, ai application security defense, prompt injection mitigation |
| [`api-security-review`](blue-team/application-security/api-security-review/SKILL.md) | core | api security review, api design review, api authz design |
| [`authentication-and-session-design-review`](blue-team/application-security/authentication-and-session-design-review/SKILL.md) | core | authentication design review, session design, mfa design review |
| [`cryptography-design-review`](blue-team/application-security/cryptography-design-review/SKILL.md) | core | crypto design review, cryptography review, algorithm selection review |
| [`dependency-and-package-risk-review`](blue-team/application-security/dependency-and-package-risk-review/SKILL.md) | core | dependency risk, third party review, package provenance |
| [`django-security-patterns`](blue-team/application-security/django-security-patterns/SKILL.md) | core | django security, drf has_object_permission, mark_safe xss, rawsql django, django code review |
| [`dotnet-aspnet-core-security`](blue-team/application-security/dotnet-aspnet-core-security/SKILL.md) | core | aspnet core security, ef core fromsqlraw, iauthorizationservice, c# secure code review |
| [`express-and-fastify-security`](blue-team/application-security/express-and-fastify-security/SKILL.md) | core | express security, fastify security, nodejs code review, execfile vs exec, nosql object guard |
| [`flask-and-fastapi-security`](blue-team/application-security/flask-and-fastapi-security/SKILL.md) | core | fastapi security, flask security review, pydantic mass assignment, depends authz fastapi |
| [`go-net-http-and-gin-security`](blue-team/application-security/go-net-http-and-gin-security/SKILL.md) | core | golang web security, gin security review, readheadertimeout go, net.dialer.control ssrf, os.root go |
| [`java-spring-security-architecture`](blue-team/application-security/java-spring-security-architecture/SKILL.md) | core | spring security 6 review, securityfilterchain order, preauthorize spel, jackson jsontypeinfo |
| [`logging-and-monitoring-requirements`](blue-team/application-security/logging-and-monitoring-requirements/SKILL.md) | leaf | application logging requirements, security logging design, log integrity |
| [`react-nextjs-and-spa-security-architecture`](blue-team/application-security/react-nextjs-and-spa-security-architecture/SKILL.md) | core | nextjs server actions security, react rsc data leak, dangerouslysetinnerhtml, spa bff auth |
| [`ruby-on-rails-security`](blue-team/application-security/ruby-on-rails-security/SKILL.md) | leaf | rails security, strong parameters rails, constantize rce, activerecord sql injection, pundit policy_scope |
| [`secrets-management-and-key-custody`](blue-team/application-security/secrets-management-and-key-custody/SKILL.md) | core | secrets management, key custody, vault, kms |
| [`secure-code-review`](blue-team/application-security/secure-code-review/SKILL.md) | flagship | secure code review, code audit, source review, sast review |
| [`secure-code-review-access-control-review`](blue-team/application-security/secure-code-review-access-control-review/SKILL.md) | leaf | code review access control, authz review code, idor code review |
| [`secure-code-review-injection-and-data-flow`](blue-team/application-security/secure-code-review-injection-and-data-flow/SKILL.md) | leaf | code review injection, taint tracing review, sink review |
| [`secure-code-review-language-specific-review`](blue-team/application-security/secure-code-review-language-specific-review/SKILL.md) | leaf | language security review, framework pitfall, orm injection review |
| [`secure-design-patterns`](blue-team/application-security/secure-design-patterns/SKILL.md) | core | secure design, design pattern security, fail safe default |
| [`secure-sdlc-and-security-requirements`](blue-team/application-security/secure-sdlc-and-security-requirements/SKILL.md) | core | secure sdlc, security requirements, security gate |
| [`security-testing-in-ci-cd`](blue-team/application-security/security-testing-in-ci-cd/SKILL.md) | core | sast, dast in ci, dependency scan ci, security gate pipeline |
| [`threat-modeling`](blue-team/application-security/threat-modeling/SKILL.md) | core | threat modeling, stride, attack tree, design review threat, model threats, threat model a service |
| [`threat-modeling-attack-tree-and-misuse-cases`](blue-team/application-security/threat-modeling-attack-tree-and-misuse-cases/SKILL.md) | leaf | attack tree, misuse case, adversary goal |
| [`threat-modeling-stride-analysis`](blue-team/application-security/threat-modeling-stride-analysis/SKILL.md) | leaf | stride threat model, stride analysis |

## blue-team / Detection and Monitoring

| Sub-skill | Tier | Triggers |
|---|---|---|
| [`alert-tuning-and-false-positive-reduction`](blue-team/detection-and-monitoring/alert-tuning-and-false-positive-reduction/SKILL.md) | core | alert tuning, false positive reduction, reduce noise, detection precision |
| [`atomic-red-team-validation`](blue-team/detection-and-monitoring/atomic-red-team-validation/SKILL.md) | core | atomic red team, detection validation, emulation test, purple test detection |
| [`cloud-detection-and-logging`](blue-team/detection-and-monitoring/cloud-detection-and-logging/SKILL.md) | core | cloud detection, cloudtrail detection, azure activity log, gcp audit log |
| [`data-loss-prevention-monitoring`](blue-team/detection-and-monitoring/data-loss-prevention-monitoring/SKILL.md) | leaf | dlp monitoring, data exfiltration detection, egress monitoring |
| [`detection-as-code-and-testing`](blue-team/detection-and-monitoring/detection-as-code-and-testing/SKILL.md) | core | detection as code, rule testing, detection ci, atomic test validation |
| [`detection-engineering`](blue-team/detection-and-monitoring/detection-engineering/SKILL.md) | flagship | detection engineering, write detection, detection rule, detection lifecycle, detection coverage |
| [`detection-engineering-behaviour-to-observable`](blue-team/detection-and-monitoring/detection-engineering-behaviour-to-observable/SKILL.md) | leaf | observable telemetry, behaviour detection, sensor coverage |
| [`detection-engineering-rule-lifecycle`](blue-team/detection-and-monitoring/detection-engineering-rule-lifecycle/SKILL.md) | leaf | detection lifecycle, rule retirement, rule governance |
| [`dns-and-beacon-analytics`](blue-team/detection-and-monitoring/dns-and-beacon-analytics/SKILL.md) | core | dns analytics, beacon detection, dga detection, dns tunneling detection |
| [`dns-and-beacon-analytics-beacon-periodicity`](blue-team/detection-and-monitoring/dns-and-beacon-analytics-beacon-periodicity/SKILL.md) | leaf | beacon analysis, periodicity detection, jitter detection |
| [`dns-and-beacon-analytics-dga-and-tunneling`](blue-team/detection-and-monitoring/dns-and-beacon-analytics-dga-and-tunneling/SKILL.md) | leaf | dga detection, dns tunnel detection, entropy analysis |
| [`email-security-monitoring`](blue-team/detection-and-monitoring/email-security-monitoring/SKILL.md) | core | email security monitoring, phishing detection, bec detection, spf dkim dmarc |
| [`endpoint-detection-and-edr-operations`](blue-team/detection-and-monitoring/endpoint-detection-and-edr-operations/SKILL.md) | core | edr operations, endpoint detection, edr query, edr alert triage |
| [`ics-and-ot-passive-network-monitoring`](blue-team/detection-and-monitoring/ics-and-ot-passive-network-monitoring/SKILL.md) | core | ot network monitoring, ics anomaly detection, modbus function code alert, passive ot ids |
| [`identity-and-authentication-monitoring`](blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) | core | identity monitoring, authentication monitoring, impossible travel, mfa fatigue detection |
| [`kubernetes-audit-log-and-runtime-detection`](blue-team/detection-and-monitoring/kubernetes-audit-log-and-runtime-detection/SKILL.md) | core | kubernetes audit log detection, falco rule k8s, tetragon runtime, pods exec detection |
| [`log-source-onboarding-and-parsing`](blue-team/detection-and-monitoring/log-source-onboarding-and-parsing/SKILL.md) | core | log onboarding, log parsing, normalization, field mapping, telemetry coverage |
| [`mitre-attack-mapping`](blue-team/detection-and-monitoring/mitre-attack-mapping/SKILL.md) | core | mitre attack, attack mapping, attack coverage, technique mapping |
| [`network-detection-and-ids`](blue-team/detection-and-monitoring/network-detection-and-ids/SKILL.md) | core | network detection, ids rule, suricata, snort, traffic anomaly |
| [`security-metrics-and-detection-coverage`](blue-team/detection-and-monitoring/security-metrics-and-detection-coverage/SKILL.md) | core | security metrics, mttd, mttr, detection coverage metric, soc metrics |
| [`siem-query-and-log-analysis`](blue-team/detection-and-monitoring/siem-query-and-log-analysis/SKILL.md) | core | siem query, splunk query, kql, elastic query, log analysis |
| [`siem-query-and-log-analysis-elastic-and-eql`](blue-team/detection-and-monitoring/siem-query-and-log-analysis-elastic-and-eql/SKILL.md) | leaf | elastic query, eql, kibana query, elasticsearch dsl |
| [`siem-query-and-log-analysis-kql-and-sentinel`](blue-team/detection-and-monitoring/siem-query-and-log-analysis-kql-and-sentinel/SKILL.md) | leaf | kql, sentinel query, defender query, kusto |
| [`siem-query-and-log-analysis-splunk-spl`](blue-team/detection-and-monitoring/siem-query-and-log-analysis-splunk-spl/SKILL.md) | leaf | splunk spl, spl query, tstats |
| [`sigma-rule-authoring`](blue-team/detection-and-monitoring/sigma-rule-authoring/SKILL.md) | core | sigma rule, sigma authoring, write sigma, sigma conversion |
| [`sigma-rule-authoring-cloud-and-network-rules`](blue-team/detection-and-monitoring/sigma-rule-authoring-cloud-and-network-rules/SKILL.md) | leaf | sigma cloud, sigma network, sigma proxy |
| [`sigma-rule-authoring-windows-event-rules`](blue-team/detection-and-monitoring/sigma-rule-authoring-windows-event-rules/SKILL.md) | leaf | sigma windows, sysmon sigma, event id sigma |
| [`waf-and-web-monitoring`](blue-team/detection-and-monitoring/waf-and-web-monitoring/SKILL.md) | leaf | waf monitoring, web attack detection, waf log analysis |
| [`yara-rule-authoring`](blue-team/detection-and-monitoring/yara-rule-authoring/SKILL.md) | core | yara rule, yara authoring, write yara, yara signature |

## blue-team / Digital Forensics

| Sub-skill | Tier | Triggers |
|---|---|---|
| [`anti-forensics-detection`](blue-team/digital-forensics/anti-forensics-detection/SKILL.md) | core | anti forensics, timestomping detection, log tampering detection |
| [`browser-and-application-forensics`](blue-team/digital-forensics/browser-and-application-forensics/SKILL.md) | core | browser forensics, chrome history forensics, browser artifacts |
| [`cloud-forensics-and-acquisition`](blue-team/digital-forensics/cloud-forensics-and-acquisition/SKILL.md) | core | cloud forensics, cloud acquisition, snapshot evidence |
| [`container-and-kubernetes-forensics`](blue-team/digital-forensics/container-and-kubernetes-forensics/SKILL.md) | leaf | container forensics, kubernetes forensics, container image analysis |
| [`database-forensics`](blue-team/digital-forensics/database-forensics/SKILL.md) | leaf | database forensics, transaction log analysis, db audit |
| [`disk-forensics-and-artifacts`](blue-team/digital-forensics/disk-forensics-and-artifacts/SKILL.md) | core | disk forensics, disk image analysis, filesystem forensics, deleted file recovery |
| [`email-forensics`](blue-team/digital-forensics/email-forensics/SKILL.md) | leaf | email forensics, header analysis email, mailbox forensics |
| [`file-carving-and-recovery`](blue-team/digital-forensics/file-carving-and-recovery/SKILL.md) | leaf | file carving, deleted file recovery, data carving |
| [`forensic-imaging-and-tooling`](blue-team/digital-forensics/forensic-imaging-and-tooling/SKILL.md) | leaf | forensic imaging, write blocker, acquisition tooling, image verification |
| [`linux-forensics`](blue-team/digital-forensics/linux-forensics/SKILL.md) | core | linux forensics, linux artifacts, bash history forensics, systemd forensics |
| [`log-and-timeline-analysis`](blue-team/digital-forensics/log-and-timeline-analysis/SKILL.md) | core | timeline analysis, super timeline, log correlation, event sequencing |
| [`macos-forensics`](blue-team/digital-forensics/macos-forensics/SKILL.md) | core | macos forensics, unified log, fsevents, launchd forensics |
| [`memory-forensics`](blue-team/digital-forensics/memory-forensics/SKILL.md) | flagship | memory forensics, volatility, ram analysis, memory dump analysis |
| [`memory-forensics-network-and-credential-artifacts`](blue-team/digital-forensics/memory-forensics-network-and-credential-artifacts/SKILL.md) | leaf | memory network artifacts, credential extraction memory |
| [`memory-forensics-process-and-injection-analysis`](blue-team/digital-forensics/memory-forensics-process-and-injection-analysis/SKILL.md) | leaf | memory injection detection, process hollowing memory, volatility process |
| [`mobile-device-forensics`](blue-team/digital-forensics/mobile-device-forensics/SKILL.md) | core | mobile forensics, android forensics, ios forensics, phone acquisition |
| [`network-forensics-and-pcap`](blue-team/digital-forensics/network-forensics-and-pcap/SKILL.md) | core | network forensics, pcap analysis, packet capture forensics, flow analysis |
| [`network-forensics-and-pcap-malicious-traffic-identification`](blue-team/digital-forensics/network-forensics-and-pcap-malicious-traffic-identification/SKILL.md) | leaf | malicious traffic analysis, c2 in pcap, exfil detection pcap |
| [`network-forensics-and-pcap-protocol-reconstruction`](blue-team/digital-forensics/network-forensics-and-pcap-protocol-reconstruction/SKILL.md) | leaf | pcap protocol reconstruction, http reconstruct, smb session analysis |
| [`registry-and-file-system-forensics`](blue-team/digital-forensics/registry-and-file-system-forensics/SKILL.md) | core | registry analysis, mft analysis, hive parsing, filesystem timeline |
| [`saas-workspace-and-entra-unified-audit-forensics`](blue-team/digital-forensics/saas-workspace-and-entra-unified-audit-forensics/SKILL.md) | core | unified audit log forensics, mailitemsaccessed, google workspace token audit, entra signin forensics |
| [`usb-and-peripheral-forensics`](blue-team/digital-forensics/usb-and-peripheral-forensics/SKILL.md) | leaf | usb forensics, removable media forensics, device history |
| [`windows-artifact-forensics`](blue-team/digital-forensics/windows-artifact-forensics/SKILL.md) | flagship | windows forensics, windows artifacts, prefetch, shimcache, usn journal, registry forensics |
| [`windows-artifact-forensics-event-log-artifacts`](blue-team/digital-forensics/windows-artifact-forensics-event-log-artifacts/SKILL.md) | leaf | event log forensics, sysmon analysis, windows event ids |
| [`windows-artifact-forensics-execution-artifacts`](blue-team/digital-forensics/windows-artifact-forensics-execution-artifacts/SKILL.md) | leaf | prefetch analysis, shimcache, amcache, srum |
| [`windows-artifact-forensics-file-system-artifacts`](blue-team/digital-forensics/windows-artifact-forensics-file-system-artifacts/SKILL.md) | leaf | mft forensics, usn journal analysis, recycle bin forensics |
| [`windows-artifact-forensics-registry-artifacts`](blue-team/digital-forensics/windows-artifact-forensics-registry-artifacts/SKILL.md) | leaf | registry forensics, ntuser.dat analysis, registry persistence |

## blue-team / Incident Response

| Sub-skill | Tier | Triggers |
|---|---|---|
| [`botnet-and-application-ddos-mitigation`](blue-team/incident-response/botnet-and-application-ddos-mitigation/SKILL.md) | core | ddos mitigation playbook, l7 http flood defense, origin ip shield, cache bypass ddos |
| [`business-email-compromise-response`](blue-team/incident-response/business-email-compromise-response/SKILL.md) | core | bec response, business email compromise, mailbox takeover, payment fraud |
| [`cloud-incident-response`](blue-team/incident-response/cloud-incident-response/SKILL.md) | core | cloud incident response, aws ir, azure ir, cloud compromise |
| [`cloud-incident-response-audit-reconstruction`](blue-team/incident-response/cloud-incident-response-audit-reconstruction/SKILL.md) | leaf | cloud audit reconstruction, cloudtrail timeline, activity log timeline |
| [`cloud-incident-response-identity-containment`](blue-team/incident-response/cloud-incident-response-identity-containment/SKILL.md) | leaf | cloud identity containment, revoke access key, disable principal |
| [`compromised-credentials-and-token-revocation-playbook`](blue-team/incident-response/compromised-credentials-and-token-revocation-playbook/SKILL.md) | core | token revocation playbook, krbtgt double reset, revoke refresh tokens, identity containment order |
| [`containment-and-eradication`](blue-team/incident-response/containment-and-eradication/SKILL.md) | core | containment, eradication, isolate host, remediation incident |
| [`crisis-communication-and-escalation`](blue-team/incident-response/crisis-communication-and-escalation/SKILL.md) | leaf | incident communication, crisis escalation, stakeholder update |
| [`denial-of-service-response`](blue-team/incident-response/denial-of-service-response/SKILL.md) | leaf | dos response, ddos mitigation, availability incident |
| [`evidence-handling-and-chain-of-custody`](blue-team/incident-response/evidence-handling-and-chain-of-custody/SKILL.md) | core | chain of custody, evidence handling, forensic acquisition order |
| [`incident-response-playbooks`](blue-team/incident-response/incident-response-playbooks/SKILL.md) | flagship | incident response, ir playbook, incident handling, response procedure |
| [`insider-threat-investigation`](blue-team/incident-response/insider-threat-investigation/SKILL.md) | core | insider threat, insider investigation, data theft employee |
| [`ir-triage-and-timeline`](blue-team/incident-response/ir-triage-and-timeline/SKILL.md) | core | incident triage, ir timeline, scope incident, initial triage |
| [`legal-and-regulatory-notification`](blue-team/incident-response/legal-and-regulatory-notification/SKILL.md) | leaf | breach notification, regulatory notification, gdpr breach, legal obligation |
| [`post-incident-review-and-lessons`](blue-team/incident-response/post-incident-review-and-lessons/SKILL.md) | core | post incident review, lessons learned, after action review |
| [`raas-extortion-and-negotiation-triage`](blue-team/incident-response/raas-extortion-and-negotiation-triage/SKILL.md) | core | raas extortion, double extortion response, ofac ransomware check, data exfiltration scoping |
| [`ransomware-response`](blue-team/incident-response/ransomware-response/SKILL.md) | flagship | ransomware response, ransomware attack, locked files, encryption event |
| [`ransomware-response-containment-and-scoping`](blue-team/incident-response/ransomware-response-containment-and-scoping/SKILL.md) | leaf | ransomware containment, ransomware scope, stop spread |
| [`ransomware-response-recovery-and-restore`](blue-team/incident-response/ransomware-response-recovery-and-restore/SKILL.md) | leaf | ransomware recovery, backup restore, restore validation |
| [`ransomware-response-strain-and-actor-identification`](blue-team/incident-response/ransomware-response-strain-and-actor-identification/SKILL.md) | leaf | ransomware strain, ransom note analysis, actor identification ransomware |
| [`supply-chain-incident-response`](blue-team/incident-response/supply-chain-incident-response/SKILL.md) | leaf | supply chain incident, dependency compromise response, vendor breach |
| [`tabletop-exercise-design`](blue-team/incident-response/tabletop-exercise-design/SKILL.md) | leaf | tabletop exercise, ttx design, incident simulation |
| [`web-app-incident-access-log-exploitation-analysis`](blue-team/incident-response/web-app-incident-access-log-exploitation-analysis/SKILL.md) | leaf | access log analysis, exploitation reconstruction, web log forensics |
| [`web-application-incident-response`](blue-team/incident-response/web-application-incident-response/SKILL.md) | core | web incident response, webshell incident, web compromise, application breach |
| [`web-application-incident-response-webshell-discovery`](blue-team/incident-response/web-application-incident-response-webshell-discovery/SKILL.md) | leaf | webshell discovery, find webshell, web shell analysis |

## blue-team / Malware Analysis

| Sub-skill | Tier | Triggers |
|---|---|---|
| [`android-static-malware-feature-engineering`](blue-team/malware-analysis/android-static-malware-feature-engineering/SKILL.md) | core | android malware static, lamda android features, dexclassloader malware, suspiciousapilist apk |
| [`c2-traffic-analysis`](blue-team/malware-analysis/c2-traffic-analysis/SKILL.md) | core | c2 traffic analysis, c2 protocol, beacon analysis |
| [`fileless-and-living-off-the-land-detection`](blue-team/malware-analysis/fileless-and-living-off-the-land-detection/SKILL.md) | core | fileless malware, lolbin detection, script based attack detection |
| [`fileless-and-living-off-the-land-detection-script-telemetry`](blue-team/malware-analysis/fileless-and-living-off-the-land-detection-script-telemetry/SKILL.md) | leaf | script block logging, command line auditing, powershell logging |
| [`fileless-living-off-the-land-parent-child-behaviour`](blue-team/malware-analysis/fileless-living-off-the-land-parent-child-behaviour/SKILL.md) | leaf | parent child anomaly, lolbin behaviour detection, process ancestry |
| [`golang-and-rust-compiled-malware-triage`](blue-team/malware-analysis/golang-and-rust-compiled-malware-triage/SKILL.md) | leaf | golang malware analysis, rust malware reversing, gopclntab, goresym, non-null string table |
| [`loader-and-implant-analysis`](blue-team/malware-analysis/loader-and-implant-analysis/SKILL.md) | leaf | loader analysis, implant analysis, stager analysis |
| [`macros-and-document-malware`](blue-team/malware-analysis/macros-and-document-malware/SKILL.md) | leaf | macro malware, malicious document, vba analysis, dropper document |
| [`malware-analysis-dynamic`](blue-team/malware-analysis/malware-analysis-dynamic/SKILL.md) | core | dynamic malware analysis, sandbox analysis, malware behaviour |
| [`malware-analysis-dynamic-behaviour-observation`](blue-team/malware-analysis/malware-analysis-dynamic-behaviour-observation/SKILL.md) | leaf | behaviour monitoring, procmon malware, api logging |
| [`malware-analysis-dynamic-sandbox-configuration`](blue-team/malware-analysis/malware-analysis-dynamic-sandbox-configuration/SKILL.md) | leaf | sandbox setup, analysis vm, malware lab |
| [`malware-analysis-static`](blue-team/malware-analysis/malware-analysis-static/SKILL.md) | core | static malware analysis, pe analysis, malware strings, sample analysis |
| [`malware-concept-drift-and-temporal-evaluation`](blue-team/malware-analysis/malware-concept-drift-and-temporal-evaluation/SKILL.md) | core | malware concept drift, temporal split evaluation, area under time aut, ml detector drift, lamda drift |
| [`malware-config-and-ioc-extraction`](blue-team/malware-analysis/malware-config-and-ioc-extraction/SKILL.md) | core | malware config extraction, c2 extraction, ioc from malware |
| [`malware-config-and-ioc-extraction-family-config-formats`](blue-team/malware-analysis/malware-config-and-ioc-extraction-family-config-formats/SKILL.md) | leaf | malware config format, c2 config decrypt, family config |
| [`malware-config-and-ioc-extraction-indicator-generation`](blue-team/malware-analysis/malware-config-and-ioc-extraction-indicator-generation/SKILL.md) | leaf | malware indicators, ioc generation malware, network indicator |
| [`malware-family-profiling`](blue-team/malware-analysis/malware-family-profiling/SKILL.md) | leaf | malware family, family profiling, malware clustering |
| [`malware-triage-for-ir`](blue-team/malware-analysis/malware-triage-for-ir/SKILL.md) | core | malware triage, suspicious file triage, malware quick analysis |
| [`sample-handling-and-safety`](blue-team/malware-analysis/sample-handling-and-safety/SKILL.md) | leaf | malware sample handling, analysis environment safety, sample possession |
| [`sandbox-evasion-in-malware`](blue-team/malware-analysis/sandbox-evasion-in-malware/SKILL.md) | leaf | malware sandbox evasion, evasive malware analysis, anti-sandbox sample |
| [`script-and-powershell-malware`](blue-team/malware-analysis/script-and-powershell-malware/SKILL.md) | leaf | powershell malware, malicious script analysis, script obfuscation |
| [`unpacking-and-deobfuscation`](blue-team/malware-analysis/unpacking-and-deobfuscation/SKILL.md) | core | malware unpacking, unpack sample, deobfuscate malware |

## blue-team / Purple Team and Program

| Sub-skill | Tier | Triggers |
|---|---|---|
| [`compliance-mapping-and-reporting`](blue-team/purple-team-and-program/compliance-mapping-and-reporting/SKILL.md) | core | compliance mapping, control mapping, regulatory reporting |
| [`control-testing-and-audit-evidence`](blue-team/purple-team-and-program/control-testing-and-audit-evidence/SKILL.md) | core | control testing, audit evidence, control effectiveness |
| [`purple-teaming-and-adversary-emulation`](blue-team/purple-team-and-program/purple-teaming-and-adversary-emulation/SKILL.md) | core | purple team, purple teaming, adversary emulation validation, detection validation, validate detection, test our detection, ... |
| [`purple-teaming-and-adversary-emulation-execution-and-validation`](blue-team/purple-team-and-program/purple-teaming-and-adversary-emulation-execution-and-validation/SKILL.md) | leaf | purple execution, detection validation run, emulation outcome |
| [`purple-teaming-and-adversary-emulation-technique-selection`](blue-team/purple-team-and-program/purple-teaming-and-adversary-emulation-technique-selection/SKILL.md) | leaf | purple technique selection, emulation scope, coverage gap selection |
| [`remediation-tracking-and-verification`](blue-team/purple-team-and-program/remediation-tracking-and-verification/SKILL.md) | core | remediation tracking, retest, fix verification, sla tracking |
| [`risk-assessment-and-treatment`](blue-team/purple-team-and-program/risk-assessment-and-treatment/SKILL.md) | core | risk assessment, risk register, risk treatment, risk analysis |
| [`security-architecture-review`](blue-team/purple-team-and-program/security-architecture-review/SKILL.md) | core | security architecture review, design assessment, architecture security |
| [`security-awareness-and-training-program`](blue-team/purple-team-and-program/security-awareness-and-training-program/SKILL.md) | leaf | security awareness, phishing simulation, training program |
| [`security-program-and-control-frameworks`](blue-team/purple-team-and-program/security-program-and-control-frameworks/SKILL.md) | core | security framework, nist csf, iso 27001, cis controls, control framework |
| [`soc-operations-and-shift-process`](blue-team/purple-team-and-program/soc-operations-and-shift-process/SKILL.md) | core | soc operations, shift handover, alert queue, soc process |
| [`third-party-and-vendor-risk`](blue-team/purple-team-and-program/third-party-and-vendor-risk/SKILL.md) | core | third party risk, vendor assessment, supplier security |

## blue-team / Security Automation and Tool Development

| Sub-skill | Tier | Triggers |
|---|---|---|
| [`auditd-and-ebpf-telemetry-collector-scripting`](blue-team/security-automation-and-tool-development/auditd-and-ebpf-telemetry-collector-scripting/SKILL.md) | leaf | ebpf security script, bpftrace execve, auditd parser python, linux telemetry script |
| [`ci-cd-security-gate-and-sarif-tooling`](blue-team/security-automation-and-tool-development/ci-cd-security-gate-and-sarif-tooling/SKILL.md) | core | ci security gate script, sarif diff blocker, pr security annotation, baseline waiver expiry |
| [`cis-benchmark-and-baseline-compliance-scripting`](blue-team/security-automation-and-tool-development/cis-benchmark-and-baseline-compliance-scripting/SKILL.md) | leaf | cis audit script, testinfra security, baseline drift checker, readonly hardening audit |
| [`custom-secret-scanner-detector-engineering`](blue-team/security-automation-and-tool-development/custom-secret-scanner-detector-engineering/SKILL.md) | core | gitleaks rule toml, custom secret scanner, shannon entropy secret, redacted secret hash |
| [`detection-coverage-and-mitre-gap-analyzer-scripting`](blue-team/security-automation-and-tool-development/detection-coverage-and-mitre-gap-analyzer-scripting/SKILL.md) | leaf | detection gap script, sigma coverage analyzer, logsource coverage python, mitre matrix script |
| [`edr-api-triage-and-containment-scripting`](blue-team/security-automation-and-tool-development/edr-api-triage-and-containment-scripting/SKILL.md) | leaf | edr api script, falconpy triage, defender api python, guarded host isolation script |
| [`iac-rego-opa-and-checkov-policy-development`](blue-team/security-automation-and-tool-development/iac-rego-opa-and-checkov-policy-development/SKILL.md) | core | opa rego policy, conftest terraform, custom checkov check, opa test rego, tfplan security |
| [`llm-input-output-guardrail-middleware-development`](blue-team/security-automation-and-tool-development/llm-input-output-guardrail-middleware-development/SKILL.md) | core | llm guardrail middleware, mcp tool policy script, rag untrusted wrapper, agent tool allowlist |
| [`malware-config-and-string-decoder-scripting`](blue-team/security-automation-and-tool-development/malware-config-and-string-decoder-scripting/SKILL.md) | core | malware config extractor python, static string decoder, unicorn bounded emulation, defang ioc |
| [`ocsf-and-ecs-log-normalizer-development`](blue-team/security-automation-and-tool-development/ocsf-and-ecs-log-normalizer-development/SKILL.md) | flagship | ocsf normalizer, ecs log parser, vector vrl security, security log etl, schema normalization |
| [`ole-pdf-and-office-triage-scripting`](blue-team/security-automation-and-tool-development/ole-pdf-and-office-triage-scripting/SKILL.md) | leaf | olevba python script, maldoc triage script, pdfid parser, external template detector |
| [`osquery-extension-and-pack-development`](blue-team/security-automation-and-tool-development/osquery-extension-and-pack-development/SKILL.md) | core | osquery pack, osquery extension python, osquery table plugin, osquery differential query |
| [`pcap-and-netflow-beacon-analysis-scripting`](blue-team/security-automation-and-tool-development/pcap-and-netflow-beacon-analysis-scripting/SKILL.md) | core | pcap analysis script, dpkt streaming, beacon jitter python, dns entropy script, pcapreader |
| [`phishing-email-and-header-triage-automation`](blue-team/security-automation-and-tool-development/phishing-email-and-header-triage-automation/SKILL.md) | core | phishing triage script, eml parser python, spf dkim dmarc parser, extract urls eml |
| [`purple-team-telemetry-validation-harnesses`](blue-team/security-automation-and-tool-development/purple-team-telemetry-validation-harnesses/SKILL.md) | core | purple team harness, telemetry validation script, attack navigator json generator, detection latency test |
| [`sbom-cyclonedx-and-cve-reachability-tooling`](blue-team/security-automation-and-tool-development/sbom-cyclonedx-and-cve-reachability-tooling/SKILL.md) | core | cyclonedx python, sbom parser script, osv api batch, epss kev enricher, purl parser |
| [`siem-query-transpiler-and-enrichment-scripting`](blue-team/security-automation-and-tool-development/siem-query-transpiler-and-enrichment-scripting/SKILL.md) | core | siem enrichment script, kql python sdk, splunk sdk query, alert hydration script |
| [`sigma-pipeline-and-backend-development`](blue-team/security-automation-and-tool-development/sigma-pipeline-and-backend-development/SKILL.md) | flagship | pysigma, sigma pipeline python, sigma backend compiler, detection as code ci, processingpipeline |
| [`soar-playbook-and-webhook-connector-development`](blue-team/security-automation-and-tool-development/soar-playbook-and-webhook-connector-development/SKILL.md) | flagship | soar playbook script, soc webhook connector, automated containment safety, idempotent soar |
| [`sqlite-wal-and-browser-artifact-scripting`](blue-team/security-automation-and-tool-development/sqlite-wal-and-browser-artifact-scripting/SKILL.md) | core | forensic sqlite python, history-wal sqlite, webkit timestamp python, browser history parser, sqlite wal snapshot |
| [`static-pe-elf-apk-feature-extractor-scripting`](blue-team/security-automation-and-tool-development/static-pe-elf-apk-feature-extractor-scripting/SKILL.md) | core | pefile feature extractor, apk static feature script, imphash python, capa rule runner, lamda features |
| [`stix-taxii-and-misp-ioc-pipeline-scripting`](blue-team/security-automation-and-tool-development/stix-taxii-and-misp-ioc-pipeline-scripting/SKILL.md) | core | stix2 python, taxii2 client script, pymisp automation, ioc pipeline allowlist, ioc confidence decay |
| [`super-timeline-and-plaso-postprocessing-scripting`](blue-team/security-automation-and-tool-development/super-timeline-and-plaso-postprocessing-scripting/SKILL.md) | leaf | plaso postprocessing, timeline slicer script, timesketch python, macb timeline filter |
| [`suricata-lua-and-rule-qa-tooling`](blue-team/security-automation-and-tool-development/suricata-lua-and-rule-qa-tooling/SKILL.md) | leaf | suricata lua script, suricata-verify, ids rule linter, fast_pattern check, eve.json parser |
| [`syslog-and-cloudtrail-stream-parsers`](blue-team/security-automation-and-tool-development/syslog-and-cloudtrail-stream-parsers/SKILL.md) | core | cloudtrail parser python, cef syslog parser, gcp audit log script, azure signin parser |
| [`velociraptor-vql-artifact-development`](blue-team/security-automation-and-tool-development/velociraptor-vql-artifact-development/SKILL.md) | core | velociraptor vql, write velociraptor artifact, vql query, velociraptor yaml |
| [`volatility3-plugin-and-memory-triage-scripting`](blue-team/security-automation-and-tool-development/volatility3-plugin-and-memory-triage-scripting/SKILL.md) | core | volatility3 plugin, volatility3 python api, treegrid volatility, memory triage script |
| [`waf-and-modsecurity-crs-rule-engineering`](blue-team/security-automation-and-tool-development/waf-and-modsecurity-crs-rule-engineering/SKILL.md) | leaf | modsecurity rule, owasp crs tuning, go-ftw waf test, ruleRemoveTargetById |
| [`windows-evtx-and-powershell-audit-scripting`](blue-team/security-automation-and-tool-development/windows-evtx-and-powershell-audit-scripting/SKILL.md) | core | python evtx parser, get-winevent script, event 4104 reassembly, evtx to jsonl |
| [`windows-forensic-artifact-parser-development`](blue-team/security-automation-and-tool-development/windows-forensic-artifact-parser-development/SKILL.md) | flagship | forensic parser python, regipy script, mft parser python, prefetch parser, chain of custody hash |
| [`yara-and-yara-x-scanner-engineering`](blue-team/security-automation-and-tool-development/yara-and-yara-x-scanner-engineering/SKILL.md) | core | yara-python, yara-x scanner, yara performance lint, yara ci pipeline |
| [`zeek-script-and-notice-development`](blue-team/security-automation-and-tool-development/zeek-script-and-notice-development/SKILL.md) | core | zeek script, write bro script, zeek notice framework, sumstats zeek, zeek btest |

## blue-team / Threat Intelligence and Hunting

| Sub-skill | Tier | Triggers |
|---|---|---|
| [`adversary-tracking-and-attribution`](blue-team/threat-intelligence-and-hunting/adversary-tracking-and-attribution/SKILL.md) | leaf | adversary tracking, attribution, threat actor profiling, campaign tracking |
| [`ai-agent-and-llm-telemetry-hunting`](blue-team/threat-intelligence-and-hunting/ai-agent-and-llm-telemetry-hunting/SKILL.md) | leaf | hunt llm abuse, ai agent telemetry hunting, mcp tool anomaly, rag exfiltration hunt |
| [`cti-collection-and-enrichment`](blue-team/threat-intelligence-and-hunting/cti-collection-and-enrichment/SKILL.md) | core | cti collection, threat feed, enrichment, ioc enrichment |
| [`darkweb-and-underground-monitoring`](blue-team/threat-intelligence-and-hunting/darkweb-and-underground-monitoring/SKILL.md) | leaf | darkweb monitoring, underground monitoring, leaked credentials monitoring |
| [`diamond-model-and-campaign-clustering`](blue-team/threat-intelligence-and-hunting/diamond-model-and-campaign-clustering/SKILL.md) | leaf | diamond model cti, analysis of competing hypotheses, intrusion set clustering, estimative language cti |
| [`hypothesis-driven-hunting`](blue-team/threat-intelligence-and-hunting/hypothesis-driven-hunting/SKILL.md) | core | hunt hypothesis, hypothesis driven, structured hunting |
| [`indicator-lifecycle-and-ioc-management`](blue-team/threat-intelligence-and-hunting/indicator-lifecycle-and-ioc-management/SKILL.md) | core | ioc management, indicator lifecycle, ioc scoring, blocklist management |
| [`indicator-lifecycle-ioc-deployment-retirement`](blue-team/threat-intelligence-and-hunting/indicator-lifecycle-ioc-deployment-retirement/SKILL.md) | leaf | ioc deployment, ioc retirement, blocklist hygiene |
| [`indicator-lifecycle-ioc-validation-scoring`](blue-team/threat-intelligence-and-hunting/indicator-lifecycle-ioc-validation-scoring/SKILL.md) | leaf | ioc validation, ioc confidence, indicator scoring |
| [`osint-for-defenders`](blue-team/threat-intelligence-and-hunting/osint-for-defenders/SKILL.md) | core | defensive osint, external exposure monitoring, brand monitoring defense |
| [`sector-threat-landscape-analysis`](blue-team/threat-intelligence-and-hunting/sector-threat-landscape-analysis/SKILL.md) | leaf | threat landscape, sector threat, industry targeting |
| [`threat-hunting`](blue-team/threat-intelligence-and-hunting/threat-hunting/SKILL.md) | core | threat hunting, hunt hypothesis, proactive hunting, hunting methodology |
| [`threat-hunting-detection-conversion`](blue-team/threat-intelligence-and-hunting/threat-hunting-detection-conversion/SKILL.md) | leaf | hunt to detection, convert hunt, detection from hunt |
| [`threat-hunting-hunt-execution-and-triage`](blue-team/threat-intelligence-and-hunting/threat-hunting-hunt-execution-and-triage/SKILL.md) | leaf | hunt execution, hunt triage, hunt results |
| [`threat-hunting-hypothesis-and-scoping`](blue-team/threat-intelligence-and-hunting/threat-hunting-hypothesis-and-scoping/SKILL.md) | leaf | hunt scoping, hunt hypothesis formulation |
| [`threat-intelligence-and-cti`](blue-team/threat-intelligence-and-hunting/threat-intelligence-and-cti/SKILL.md) | core | threat intelligence, cti, cyber threat intel, intelligence cycle |
| [`threat-intelligence-and-cti-strategic-intelligence`](blue-team/threat-intelligence-and-hunting/threat-intelligence-and-cti-strategic-intelligence/SKILL.md) | leaf | strategic threat intel, executive threat briefing, risk intelligence |
| [`threat-intelligence-and-cti-tactical-intelligence`](blue-team/threat-intelligence-and-hunting/threat-intelligence-and-cti-tactical-intelligence/SKILL.md) | leaf | tactical threat intel, ioc intelligence, operational indicators |
| [`vulnerability-intelligence-monitoring`](blue-team/threat-intelligence-and-hunting/vulnerability-intelligence-monitoring/SKILL.md) | core | vulnerability intelligence, cve monitoring, exploit availability, advisory tracking |

## blue-team / Vulnerability and Hardening

| Sub-skill | Tier | Triggers |
|---|---|---|
| [`asset-inventory-and-cmdb`](blue-team/vulnerability-and-hardening/asset-inventory-and-cmdb/SKILL.md) | leaf | asset inventory, cmdb, asset ownership, inventory coverage |
| [`attack-surface-management`](blue-team/vulnerability-and-hardening/attack-surface-management/SKILL.md) | core | attack surface management, asm, external asset discovery, exposure reduction |
| [`cisa-kev-emergency-triage-workflow`](blue-team/vulnerability-and-hardening/cisa-kev-emergency-triage-workflow/SKILL.md) | core | cisa kev triage, known exploited vulnerability workflow, emergencycve patch, kev compensating control |
| [`configuration-baselines-and-cis`](blue-team/vulnerability-and-hardening/configuration-baselines-and-cis/SKILL.md) | core | cis benchmark, configuration baseline, security baseline |
| [`cvss-epss-and-risk-scoring`](blue-team/vulnerability-and-hardening/cvss-epss-and-risk-scoring/SKILL.md) | core | cvss, epss, risk scoring, vulnerability prioritization scoring, prioritise cves, prioritize vulnerabilities, ... |
| [`exposure-management-and-internet-scanning`](blue-team/vulnerability-and-hardening/exposure-management-and-internet-scanning/SKILL.md) | leaf | exposure management, internet scanning, exposed service validation |
| [`hardening-cloud-and-containers`](blue-team/vulnerability-and-hardening/hardening-cloud-and-containers/SKILL.md) | core | cloud hardening, container hardening, kubernetes hardening |
| [`hardening-cloud-and-containers-identity-and-policy-hardening`](blue-team/vulnerability-and-hardening/hardening-cloud-and-containers-identity-and-policy-hardening/SKILL.md) | leaf | cloud least privilege, permission boundary, standing privilege |
| [`hardening-cloud-and-containers-workload-and-network-hardening`](blue-team/vulnerability-and-hardening/hardening-cloud-and-containers-workload-and-network-hardening/SKILL.md) | leaf | cloud workload hardening, network policy cloud, private endpoint |
| [`hardening-linux-and-macos`](blue-team/vulnerability-and-hardening/hardening-linux-and-macos/SKILL.md) | core | linux hardening, macos hardening, unix hardening |
| [`hardening-windows-and-ad`](blue-team/vulnerability-and-hardening/hardening-windows-and-ad/SKILL.md) | core | windows hardening, ad hardening, tier 0 hardening |
| [`hardening-windows-and-ad-attack-surface-reduction`](blue-team/vulnerability-and-hardening/hardening-windows-and-ad-attack-surface-reduction/SKILL.md) | leaf | asr rules, applocker, wdac |
| [`hardening-windows-and-ad-authentication-hardening`](blue-team/vulnerability-and-hardening/hardening-windows-and-ad-authentication-hardening/SKILL.md) | leaf | windows auth hardening, ntlm disable, kerberos hardening |
| [`hardening-windows-and-ad-privileged-access-hardening`](blue-team/vulnerability-and-hardening/hardening-windows-and-ad-privileged-access-hardening/SKILL.md) | leaf | tier 0 hardening, protected users, laps |
| [`network-segmentation-and-architecture-review`](blue-team/vulnerability-and-hardening/network-segmentation-and-architecture-review/SKILL.md) | core | network segmentation, architecture review, trust boundary, egress control |
| [`patch-management-and-remediation`](blue-team/vulnerability-and-hardening/patch-management-and-remediation/SKILL.md) | core | patch management, remediation workflow, patch deployment |
| [`privileged-access-management`](blue-team/vulnerability-and-hardening/privileged-access-management/SKILL.md) | core | privileged access management, pam, jit access, credential vault |
| [`secure-configuration-review`](blue-team/vulnerability-and-hardening/secure-configuration-review/SKILL.md) | core | configuration review, secure configuration, dangerous default |
| [`vulnerability-false-positive-verification`](blue-team/vulnerability-and-hardening/vulnerability-false-positive-verification/SKILL.md) | core | false positive verification, invalid bug report triage, non-exploitable cve, self-xss triage, scanner noise triage |
| [`vulnerability-management-and-prioritization`](blue-team/vulnerability-and-hardening/vulnerability-management-and-prioritization/SKILL.md) | flagship | vulnerability management, vuln prioritization, patch backlog, vm program |
| [`vulnerability-management-scanning-coverage`](blue-team/vulnerability-and-hardening/vulnerability-management-scanning-coverage/SKILL.md) | leaf | vuln scanning strategy, scan coverage, credentialed scan |
| [`vulnerability-management-triage-exception-handling`](blue-team/vulnerability-and-hardening/vulnerability-management-triage-exception-handling/SKILL.md) | leaf | vuln triage, false positive vuln, risk acceptance |
| [`zero-trust-and-mtls-service-mesh-hardening`](blue-team/vulnerability-and-hardening/zero-trust-and-mtls-service-mesh-hardening/SKILL.md) | leaf | zero trust mtls, spiffe spire, istio authorizationpolicy, service mesh hardening |

## red-team / AI and LLM

| Sub-skill | Tier | Triggers |
|---|---|---|
| [`agentic-ai-and-mcp-security`](red-team/ai-and-llm/agentic-ai-and-mcp-security/SKILL.md) | core | agentic ai security, mcp security, tool abuse agent, confused deputy ai |
| [`ai-application-assessment`](red-team/ai-and-llm/ai-application-assessment/SKILL.md) | core | llm application assessment, ai app pentest, ai threat model, ai security review |
| [`ai-assisted-offensive-tooling`](red-team/ai-and-llm/ai-assisted-offensive-tooling/SKILL.md) | leaf | ai assisted pentest, llm for recon, ai payload generation, automation with llm |
| [`ai-guardrail-and-classifier-bypass`](red-team/ai-and-llm/ai-guardrail-and-classifier-bypass/SKILL.md) | core | guardrail bypass, moderation bypass, classifier evasion, adversarial suffix |
| [`ai-supply-chain-and-plugin-risk`](red-team/ai-and-llm/ai-supply-chain-and-plugin-risk/SKILL.md) | leaf | ai plugin risk, tool integration security, third party ai tool |
| [`fine-tuning-and-lora-alignment-security`](red-team/ai-and-llm/fine-tuning-and-lora-alignment-security/SKILL.md) | leaf | fine tuning security, lora adapter backdoor, alignment degradation, canary memorization test |
| [`llm-data-exfiltration-and-leakage`](red-team/ai-and-llm/llm-data-exfiltration-and-leakage/SKILL.md) | core | system prompt leak, llm data leak, training data extraction, cross tenant llm |
| [`llm-denial-of-service-and-cost`](red-team/ai-and-llm/llm-denial-of-service-and-cost/SKILL.md) | leaf | llm denial of service, token exhaustion, cost abuse llm, unbounded context |
| [`llm-jailbreak-and-guardrails`](red-team/ai-and-llm/llm-jailbreak-and-guardrails/SKILL.md) | core | jailbreak, guardrail bypass, llm safety bypass, refusal bypass, safety filter |
| [`llm-output-handling-and-sinks`](red-team/ai-and-llm/llm-output-handling-and-sinks/SKILL.md) | core | llm output injection, markdown injection chat, generated code execution, output sink |
| [`llm-prompt-injection`](red-team/ai-and-llm/llm-prompt-injection/SKILL.md) | flagship | prompt injection, llm injection, indirect prompt injection, instruction override, ai jailbreak |
| [`mitre-atlas-ml-threat-coverage`](red-team/ai-and-llm/mitre-atlas-ml-threat-coverage/SKILL.md) | core | mitre atlas, ml threat modeling, membership inference, model inversion, ml pipeline security |
| [`ml-adversarial-and-data-poisoning`](red-team/ai-and-llm/ml-adversarial-and-data-poisoning/SKILL.md) | leaf | adversarial example, data poisoning, model backdoor, model extraction |
| [`model-and-artifact-supply-chain`](red-team/ai-and-llm/model-and-artifact-supply-chain/SKILL.md) | leaf | model supply chain, unsafe pickle model, model hub risk, artifact provenance |
| [`multimodal-and-vision-llm-injection`](red-team/ai-and-llm/multimodal-and-vision-llm-injection/SKILL.md) | leaf | multimodal prompt injection, vision llm attack, image ocr injection, cross-modal injection |
| [`rag-and-vector-store-attacks`](red-team/ai-and-llm/rag-and-vector-store-attacks/SKILL.md) | core | rag attack, vector store poisoning, embedding inversion, retrieval poisoning |

## red-team / Binary and Exploit Development

| Sub-skill | Tier | Triggers |
|---|---|---|
| [`anti-analysis-and-packing`](red-team/binary-and-exploit-development/anti-analysis-and-packing/SKILL.md) | core | anti-debugging, packer, unpacking, anti-vm, obfuscated binary, protector |
| [`anti-analysis-and-packing-anti-debugging-defeat`](red-team/binary-and-exploit-development/anti-analysis-and-packing-anti-debugging-defeat/SKILL.md) | leaf | anti-debugging defeat, peb check, timing check debugger |
| [`anti-analysis-and-packing-anti-vm-and-sandbox-traps`](red-team/binary-and-exploit-development/anti-analysis-and-packing-anti-vm-and-sandbox-traps/SKILL.md) | leaf | anti vm, sandbox evasion analysis, virtualization detection |
| [`anti-analysis-and-packing-unpacking-runtime-packers`](red-team/binary-and-exploit-development/anti-analysis-and-packing-unpacking-runtime-packers/SKILL.md) | leaf | unpack, oep, dump process, rebuild imports, upx -d |
| [`binary-recon-and-triage`](red-team/binary-and-exploit-development/binary-recon-and-triage/SKILL.md) | core | binary triage, binary recon, checksec, file analysis, binary analysis start |
| [`binary-recon-and-triage-embedded-architecture-analysis`](red-team/binary-and-exploit-development/binary-recon-and-triage-embedded-architecture-analysis/SKILL.md) | leaf | mips reversing, arm firmware, risc-v analysis, embedded reversing |
| [`binary-recon-and-triage-firmware-extraction`](red-team/binary-and-exploit-development/binary-recon-and-triage-firmware-extraction/SKILL.md) | leaf | firmware extraction, binwalk, firmware image, squashfs extract |
| [`browser-exploitation`](red-team/binary-and-exploit-development/browser-exploitation/SKILL.md) | core | browser exploitation, v8 exploit, jit bug, sandbox escape browser, chrome exploit |
| [`browser-exploitation-renderer-sandbox-escape`](red-team/binary-and-exploit-development/browser-exploitation-renderer-sandbox-escape/SKILL.md) | leaf | browser sandbox escape, ipc exploitation, renderer to os |
| [`browser-exploitation-v8-and-javascript-engine`](red-team/binary-and-exploit-development/browser-exploitation-v8-and-javascript-engine/SKILL.md) | leaf | v8 exploit, addrof, fakeobj, javascript engine exploit |
| [`bytecode-and-vm-reversing`](red-team/binary-and-exploit-development/bytecode-and-vm-reversing/SKILL.md) | leaf | bytecode reversing, vm reversing, il analysis, python bytecode, lua decompile |
| [`bytecode-and-vm-reversing-custom-vm-devirtualization`](red-team/binary-and-exploit-development/bytecode-and-vm-reversing-custom-vm-devirtualization/SKILL.md) | leaf | custom vm, devirtualization, vm handler analysis |
| [`bytecode-and-vm-reversing-jvm-and-dotnet-il`](red-team/binary-and-exploit-development/bytecode-and-vm-reversing-jvm-and-dotnet-il/SKILL.md) | leaf | jvm bytecode, dotnet il, il analysis, bytecode reversing |
| [`bytecode-and-vm-reversing-python-and-script-bytecode`](red-team/binary-and-exploit-development/bytecode-and-vm-reversing-python-and-script-bytecode/SKILL.md) | leaf | python bytecode decompile, lua bytecode, script bytecode |
| [`code-obfuscation-and-deobfuscation`](red-team/binary-and-exploit-development/code-obfuscation-and-deobfuscation/SKILL.md) | core | deobfuscation, obfuscated code, control flow flattening, string decryption, obfuscator |
| [`code-obfuscation-and-deobfuscation-control-flow-deobfuscation`](red-team/binary-and-exploit-development/code-obfuscation-and-deobfuscation-control-flow-deobfuscation/SKILL.md) | leaf | control flow flattening, opaque predicate removal, deobfuscate control flow |
| [`code-obfuscation-and-deobfuscation-script-obfuscation`](red-team/binary-and-exploit-development/code-obfuscation-and-deobfuscation-script-obfuscation/SKILL.md) | leaf | deobfuscate javascript, powershell obfuscation, deobfuscate vba |
| [`code-obfuscation-and-deobfuscation-string-and-data-deobfuscation`](red-team/binary-and-exploit-development/code-obfuscation-and-deobfuscation-string-and-data-deobfuscation/SKILL.md) | leaf | string decryption, data deobfuscation, decode strings |
| [`debugger-and-emulation-tooling`](red-team/binary-and-exploit-development/debugger-and-emulation-tooling/SKILL.md) | leaf | analysis tooling, emulation, qemu analysis, analysis environment setup |
| [`desktop-application-exploitation`](red-team/binary-and-exploit-development/desktop-application-exploitation/SKILL.md) | leaf | desktop exploit, client side exploit, document parser exploit, file format bug |
| [`desktop-application-exploitation-document-and-file-formats`](red-team/binary-and-exploit-development/desktop-application-exploitation-document-and-file-formats/SKILL.md) | leaf | document exploit, file format bug, parser exploitation |
| [`desktop-application-exploitation-update-and-installer-mechanisms`](red-team/binary-and-exploit-development/desktop-application-exploitation-update-and-installer-mechanisms/SKILL.md) | leaf | update mechanism attack, installer abuse, update hijack |
| [`dynamic-reverse-engineering`](red-team/binary-and-exploit-development/dynamic-reverse-engineering/SKILL.md) | core | dynamic analysis, debugging, gdb, x64dbg, tracing, runtime analysis |
| [`dynamic-reverse-engineering-api-and-syscall-tracing`](red-team/binary-and-exploit-development/dynamic-reverse-engineering-api-and-syscall-tracing/SKILL.md) | leaf | api tracing, syscall trace, strace, ltrace |
| [`dynamic-reverse-engineering-debugger-workflows`](red-team/binary-and-exploit-development/dynamic-reverse-engineering-debugger-workflows/SKILL.md) | leaf | debugger scripting, conditional breakpoint, x64dbg script, gdb script |
| [`dynamic-reverse-engineering-instrumentation-and-hooking`](red-team/binary-and-exploit-development/dynamic-reverse-engineering-instrumentation-and-hooking/SKILL.md) | leaf | frida, hooking, instrumentation, intercept function |
| [`exploit-development-workflow`](red-team/binary-and-exploit-development/exploit-development-workflow/SKILL.md) | core | exploit development, exploit writeup, crash to exploit, reliability engineering |
| [`exploit-development-workflow-crash-triage`](red-team/binary-and-exploit-development/exploit-development-workflow-crash-triage/SKILL.md) | leaf | crash triage, fault characterization, bug classification |
| [`exploit-development-workflow-primitive-identification`](red-team/binary-and-exploit-development/exploit-development-workflow-primitive-identification/SKILL.md) | leaf | exploit primitive, read primitive, call primitive, primitive classification |
| [`exploit-development-workflow-reliability-and-heap-grooming`](red-team/binary-and-exploit-development/exploit-development-workflow-reliability-and-heap-grooming/SKILL.md) | leaf | exploit reliability, heap grooming, exploit stability |
| [`exploit-mitigation-inventory`](red-team/binary-and-exploit-development/exploit-mitigation-inventory/SKILL.md) | leaf | mitigation inventory, checksec all, protection assessment |
| [`format-string-exploitation`](red-team/binary-and-exploit-development/format-string-exploitation/SKILL.md) | core | format string, printf vulnerability, %n exploitation, format string bug |
| [`fuzzing-and-harnessing`](red-team/binary-and-exploit-development/fuzzing-and-harnessing/SKILL.md) | core | fuzzing, fuzzer, harness, afl, libfuzzer, coverage guided fuzzing |
| [`fuzzing-and-harnessing-coverage-guided-fuzzing`](red-team/binary-and-exploit-development/fuzzing-and-harnessing-coverage-guided-fuzzing/SKILL.md) | leaf | afl fuzzing, libfuzzer, coverage guided, corpus minimization |
| [`fuzzing-and-harnessing-crash-triage-and-dedup`](red-team/binary-and-exploit-development/fuzzing-and-harnessing-crash-triage-and-dedup/SKILL.md) | leaf | crash triage, crash dedup, exploitability ranking |
| [`fuzzing-and-harnessing-harness-construction`](red-team/binary-and-exploit-development/fuzzing-and-harnessing-harness-construction/SKILL.md) | leaf | fuzz harness, persistent mode, structured fuzzing, dictionary fuzzing |
| [`fuzzing-and-harnessing-protocol-and-stateful-fuzzing`](red-team/binary-and-exploit-development/fuzzing-and-harnessing-protocol-and-stateful-fuzzing/SKILL.md) | leaf | protocol fuzzing, stateful fuzzing, grammar fuzzing |
| [`game-and-application-cheat-research`](red-team/binary-and-exploit-development/game-and-application-cheat-research/SKILL.md) | leaf | anti-cheat research, game security analysis, integrity check analysis |
| [`go-concurrency-slice-and-cgo-security`](red-team/binary-and-exploit-development/go-concurrency-slice-and-cgo-security/SKILL.md) | core | go data race vulnerability, cgo memory safety, go unsafe pointer, go race detector, govulncheck |
| [`heap-exploitation`](red-team/binary-and-exploit-development/heap-exploitation/SKILL.md) | flagship | heap exploitation, heap overflow, use after free, double free, unlink, tcache |
| [`heap-exploitation-glibc-ptmalloc`](red-team/binary-and-exploit-development/heap-exploitation-glibc-ptmalloc/SKILL.md) | leaf | glibc heap, ptmalloc, tcache poisoning, fastbin attack, tcache safe-linking |
| [`heap-exploitation-house-of-techniques`](red-team/binary-and-exploit-development/heap-exploitation-house-of-techniques/SKILL.md) | leaf | house of force, house of spirit, house of lore, heap technique, how2heap |
| [`heap-exploitation-io-file-exploitation`](red-team/binary-and-exploit-development/heap-exploitation-io-file-exploitation/SKILL.md) | leaf | file structure exploit, io file, vtable abuse, fsop |
| [`heap-exploitation-kernel-heap-and-pool`](red-team/binary-and-exploit-development/heap-exploitation-kernel-heap-and-pool/SKILL.md) | leaf | kernel pool, slab exploitation, pool spray, kernel grooming |
| [`heap-exploitation-lfh-and-segment-heap`](red-team/binary-and-exploit-development/heap-exploitation-lfh-and-segment-heap/SKILL.md) | leaf | lfh internals, segment heap internals, windows allocator |
| [`heap-exploitation-pool-and-kernel-allocator`](red-team/binary-and-exploit-development/heap-exploitation-pool-and-kernel-allocator/SKILL.md) | leaf | kernel pool internals, pool spray windows, pool allocator |
| [`heap-exploitation-windows-heap`](red-team/binary-and-exploit-development/heap-exploitation-windows-heap/SKILL.md) | leaf | windows heap, nt heap, segment heap, lfh |
| [`information-leak-and-aslr-defeat`](red-team/binary-and-exploit-development/information-leak-and-aslr-defeat/SKILL.md) | leaf | aslr bypass, address leak, info leak, partial overwrite |
| [`integer-and-type-confusion`](red-team/binary-and-exploit-development/integer-and-type-confusion/SKILL.md) | leaf | integer overflow, type confusion, sign extension, truncation bug |
| [`java-and-dotnet-decompilation`](red-team/binary-and-exploit-development/java-and-dotnet-decompilation/SKILL.md) | leaf | decompile java, decompile dotnet, jar analysis, dnspy, jadx java |
| [`kernel-exploitation`](red-team/binary-and-exploit-development/kernel-exploitation/SKILL.md) | core | kernel exploitation, kernel exploit, lpe kernel, pool overflow, slab |
| [`kernel-exploitation-hypervisor-and-firmware`](red-team/binary-and-exploit-development/kernel-exploitation-hypervisor-and-firmware/SKILL.md) | leaf | hypervisor escape, smm exploit, firmware exploit |
| [`kernel-exploitation-linux-kernel`](red-team/binary-and-exploit-development/kernel-exploitation-linux-kernel/SKILL.md) | leaf | linux kernel exploit, modprobe_path, msg_msg, kernel uaf |
| [`kernel-exploitation-windows-kernel`](red-team/binary-and-exploit-development/kernel-exploitation-windows-kernel/SKILL.md) | leaf | windows kernel exploit, token stealing, smep bypass, kvas |
| [`linux-exploit-mitigations-and-bypass`](red-team/binary-and-exploit-development/linux-exploit-mitigations-and-bypass/SKILL.md) | core | linux mitigations, pie bypass, canary bypass, relro, full relro |
| [`linux-exploit-mitigations-and-bypass-canary-and-fortify`](red-team/binary-and-exploit-development/linux-exploit-mitigations-and-bypass-canary-and-fortify/SKILL.md) | leaf | canary bypass, stack canary leak, fortify bypass |
| [`linux-exploit-mitigations-and-bypass-pie-and-aslr`](red-team/binary-and-exploit-development/linux-exploit-mitigations-and-bypass-pie-and-aslr/SKILL.md) | leaf | pie bypass, linux aslr bypass, partial overwrite pie |
| [`linux-exploit-mitigations-and-bypass-relro-and-got`](red-team/binary-and-exploit-development/linux-exploit-mitigations-and-bypass-relro-and-got/SKILL.md) | leaf | relro bypass, got overwrite, full relro bypass |
| [`network-service-exploitation`](red-team/binary-and-exploit-development/network-service-exploitation/SKILL.md) | core | remote exploit, network service exploit, daemon exploit, pre-auth rce |
| [`network-service-exploitation-pre-auth-and-post-auth-paths`](red-team/binary-and-exploit-development/network-service-exploitation-pre-auth-and-post-auth-paths/SKILL.md) | leaf | pre-auth exploit, post-auth exploit, authenticated attack surface |
| [`network-service-exploitation-protocol-parser-bugs`](red-team/binary-and-exploit-development/network-service-exploitation-protocol-parser-bugs/SKILL.md) | leaf | protocol parser bug, length confusion, parser vulnerability |
| [`network-service-exploitation-remote-reliability-and-bruteforce`](red-team/binary-and-exploit-development/network-service-exploitation-remote-reliability-and-bruteforce/SKILL.md) | leaf | remote exploit reliability, remote heap grooming, exploit bruteforce |
| [`patch-diffing-and-vulnerability-discovery`](red-team/binary-and-exploit-development/patch-diffing-and-vulnerability-discovery/SKILL.md) | core | patch diffing, binary diff, 1-day analysis, patch analysis vulnerability |
| [`patch-diffing-and-vulnerability-discovery-binary-diffing-tools`](red-team/binary-and-exploit-development/patch-diffing-and-vulnerability-discovery-binary-diffing-tools/SKILL.md) | leaf | bindiff, diaphora, binary diff tools |
| [`patch-diffing-source-to-binary-correlation`](red-team/binary-and-exploit-development/patch-diffing-source-to-binary-correlation/SKILL.md) | leaf | source patch correlation, compiled diff, fix identification |
| [`php-interpreter-request-lifecycle`](red-team/binary-and-exploit-development/php-interpreter-request-lifecycle/SKILL.md) | leaf | php-fpm request lifecycle, php interpreter memory safety, upload progress shutdown, php2shell |
| [`reverse-engineering-protocols`](red-team/binary-and-exploit-development/reverse-engineering-protocols/SKILL.md) | leaf | protocol reversing, custom protocol analysis, message format recovery |
| [`rop-and-jop`](red-team/binary-and-exploit-development/rop-and-jop/SKILL.md) | flagship | rop, return oriented programming, jop, gadget, rop chain |
| [`rop-and-jop-calling-conventions-and-arguments`](red-team/binary-and-exploit-development/rop-and-jop-calling-conventions-and-arguments/SKILL.md) | leaf | calling convention gadgets, pop rdi, argument setup rop |
| [`rop-and-jop-gadget-discovery`](red-team/binary-and-exploit-development/rop-and-jop-gadget-discovery/SKILL.md) | leaf | gadget discovery, ropgadget, ropper, gadget search |
| [`rop-and-jop-jop-and-cop`](red-team/binary-and-exploit-development/rop-and-jop-jop-and-cop/SKILL.md) | leaf | jop, call oriented programming, cop chain, jump oriented |
| [`rop-and-jop-ret2dlresolve`](red-team/binary-and-exploit-development/rop-and-jop-ret2dlresolve/SKILL.md) | leaf | ret2dlresolve, dynamic linker resolve, symbol resolve exploit |
| [`rop-and-jop-sigreturn-oriented-programming`](red-team/binary-and-exploit-development/rop-and-jop-sigreturn-oriented-programming/SKILL.md) | leaf | srop, sigreturn oriented, sigreturn frame |
| [`rust-concurrency-and-panic-safety`](red-team/binary-and-exploit-development/rust-concurrency-and-panic-safety/SKILL.md) | leaf | rust panic safety, drop bomb rust, integer overflow release rust, pin projection soundness |
| [`rust-unsafe-and-ffi-security`](red-team/binary-and-exploit-development/rust-unsafe-and-ffi-security/SKILL.md) | core | rust unsafe audit, rust ffi vulnerability, from_raw_parts bug, maybeuninit soundness, rust memory safety |
| [`sandbox-escape`](red-team/binary-and-exploit-development/sandbox-escape/SKILL.md) | leaf | sandbox escape, renderer escape, appcontainer escape, seccomp bypass |
| [`seh-and-egghunter-exploitation`](red-team/binary-and-exploit-development/seh-and-egghunter-exploitation/SKILL.md) | leaf | seh overwrite, egghunter, structured exception exploitation |
| [`shellcode-development`](red-team/binary-and-exploit-development/shellcode-development/SKILL.md) | core | shellcode, shellcode writing, position independent, syscall stub, encoder |
| [`shellcode-development-encoder-and-restricted-charsets`](red-team/binary-and-exploit-development/shellcode-development-encoder-and-restricted-charsets/SKILL.md) | leaf | shellcode encoder, bad characters, alphanumeric shellcode |
| [`shellcode-development-position-independent-stubs`](red-team/binary-and-exploit-development/shellcode-development-position-independent-stubs/SKILL.md) | leaf | pic shellcode, syscall stub, position independent code |
| [`shellcode-development-staged-and-stageless-payloads`](red-team/binary-and-exploit-development/shellcode-development-staged-and-stageless-payloads/SKILL.md) | leaf | staged payload, reflective loader, stager |
| [`stack-buffer-overflow`](red-team/binary-and-exploit-development/stack-buffer-overflow/SKILL.md) | flagship | stack overflow, buffer overflow, eip control, rip control, ret2libc |
| [`stack-buffer-overflow-offset-discovery`](red-team/binary-and-exploit-development/stack-buffer-overflow-offset-discovery/SKILL.md) | leaf | offset discovery, pattern offset, eip offset, cyclic pattern |
| [`stack-buffer-overflow-return-to-libc-and-ret2plt`](red-team/binary-and-exploit-development/stack-buffer-overflow-return-to-libc-and-ret2plt/SKILL.md) | leaf | ret2libc, ret2plt, return to libc, nx bypass |
| [`stack-buffer-overflow-stack-pivots`](red-team/binary-and-exploit-development/stack-buffer-overflow-stack-pivots/SKILL.md) | leaf | stack pivot, leave ret pivot, pivot gadget |
| [`static-reverse-engineering`](red-team/binary-and-exploit-development/static-reverse-engineering/SKILL.md) | flagship | static analysis, disassembly, decompiler, ghidra, ida pro, reverse engineering static |
| [`static-reverse-engineering-ghidra-workflows`](red-team/binary-and-exploit-development/static-reverse-engineering-ghidra-workflows/SKILL.md) | leaf | ghidra, ghidra script, pcode, ghidra decompiler |
| [`static-reverse-engineering-ida-workflows`](red-team/binary-and-exploit-development/static-reverse-engineering-ida-workflows/SKILL.md) | leaf | ida pro, idapython, ida workflow, hexrays |
| [`static-reverse-engineering-signature-and-library-matching`](red-team/binary-and-exploit-development/static-reverse-engineering-signature-and-library-matching/SKILL.md) | leaf | library matching, flirt signature, function identification, symbol recovery |
| [`static-reverse-engineering-type-and-structure-recovery`](red-team/binary-and-exploit-development/static-reverse-engineering-type-and-structure-recovery/SKILL.md) | leaf | struct recovery, type reconstruction, prototype recovery |
| [`symbolic-and-concrete-hybrid-analysis`](red-team/binary-and-exploit-development/symbolic-and-concrete-hybrid-analysis/SKILL.md) | leaf | emulation analysis, taint tracking, hybrid fuzzing, unicorn engine |
| [`symbolic-execution-and-concolic`](red-team/binary-and-exploit-development/symbolic-execution-and-concolic/SKILL.md) | leaf | symbolic execution, angr, concolic, z3, path constraint solving |
| [`symbolic-execution-and-concolic-angr-workflows`](red-team/binary-and-exploit-development/symbolic-execution-and-concolic-angr-workflows/SKILL.md) | leaf | angr, symbolic execution angr, cfg recovery |
| [`symbolic-execution-and-concolic-solver-modelling`](red-team/binary-and-exploit-development/symbolic-execution-and-concolic-solver-modelling/SKILL.md) | leaf | z3, smt solver, constraint modelling |
| [`use-after-free-and-exploit-primitives`](red-team/binary-and-exploit-development/use-after-free-and-exploit-primitives/SKILL.md) | core | use after free, uaf, type confusion, dangling pointer, reclaim object |
| [`vulnerability-root-cause-analysis`](red-team/binary-and-exploit-development/vulnerability-root-cause-analysis/SKILL.md) | core | root cause analysis, vulnerability analysis, crash analysis, bug class |
| [`webassembly-and-wasi-security`](red-team/binary-and-exploit-development/webassembly-and-wasi-security/SKILL.md) | leaf | webassembly security, wasm linear memory overflow, wasi capability escape, wasmtime audit |
| [`windows-exploit-bypass-cet-hardware-mitigations`](red-team/binary-and-exploit-development/windows-exploit-bypass-cet-hardware-mitigations/SKILL.md) | leaf | cet bypass, shadow stack, ibt, hardware mitigation |
| [`windows-exploit-mitigations-and-bypass`](red-team/binary-and-exploit-development/windows-exploit-mitigations-and-bypass/SKILL.md) | core | windows mitigations, aslr bypass windows, dep bypass, cfg bypass, cfi |
| [`windows-exploit-mitigations-and-bypass-aslr-and-dep`](red-team/binary-and-exploit-development/windows-exploit-mitigations-and-bypass-aslr-and-dep/SKILL.md) | leaf | windows aslr bypass, dep bypass windows, virtualprotect rop |
| [`windows-exploit-mitigations-and-bypass-cfg-and-cfi-bypass`](red-team/binary-and-exploit-development/windows-exploit-mitigations-and-bypass-cfg-and-cfi-bypass/SKILL.md) | leaf | cfg bypass, control flow guard bypass, cfi bypass |
| [`write-primitive-to-rce`](red-team/binary-and-exploit-development/write-primitive-to-rce/SKILL.md) | core | write primitive, arbitrary write, got overwrite, hook overwrite, write what where |
| [`write-primitive-to-rce-control-flow-hijack-targets`](red-team/binary-and-exploit-development/write-primitive-to-rce-control-flow-hijack-targets/SKILL.md) | leaf | control flow hijack, got hook vtable, hijack target |
| [`write-primitive-to-rce-data-only-exploitation`](red-team/binary-and-exploit-development/write-primitive-to-rce-data-only-exploitation/SKILL.md) | leaf | data only exploitation, data oriented attack, non control flow exploit |

## red-team / Blockchain

| Sub-skill | Tier | Triggers |
|---|---|---|
| [`access-control-and-initialization`](red-team/blockchain/access-control-and-initialization/SKILL.md) | core | contract access control, uninitialized proxy, upgrade admin, missing modifier |
| [`arithmetic-and-precision-bugs`](red-team/blockchain/arithmetic-and-precision-bugs/SKILL.md) | leaf | solidity arithmetic, rounding exploit, precision loss, unchecked overflow |
| [`bridge-and-cross-chain`](red-team/blockchain/bridge-and-cross-chain/SKILL.md) | leaf | bridge exploit, cross chain attack, message verification, wrapped asset |
| [`defi-attack-patterns`](red-team/blockchain/defi-attack-patterns/SKILL.md) | flagship | defi exploit, flash loan attack, oracle manipulation, amm exploit, mev |
| [`defi-attack-patterns-amm-and-liquidity`](red-team/blockchain/defi-attack-patterns-amm-and-liquidity/SKILL.md) | leaf | amm exploit, liquidity pool attack, donation attack, first depositor |
| [`defi-attack-patterns-lending-and-collateral`](red-team/blockchain/defi-attack-patterns-lending-and-collateral/SKILL.md) | leaf | lending exploit, collateral manipulation, liquidation abuse |
| [`eip712-signature-replay-and-account-abstraction`](red-team/blockchain/eip712-signature-replay-and-account-abstraction/SKILL.md) | core | eip-712 replay, erc-4337 audit, ecrecover zero address, domain_separator chainid, validateuserop |
| [`erc4626-vault-inflation-and-rounding-audit`](red-team/blockchain/erc4626-vault-inflation-and-rounding-audit/SKILL.md) | leaf | erc4626 inflation attack, vault rounding direction, virtual shares offset, fee on transfer accounting |
| [`evm-exploitation-and-tooling`](red-team/blockchain/evm-exploitation-and-tooling/SKILL.md) | core | evm bytecode, foundry, cast, storage layout, calldata crafting |
| [`flash-loan-and-capital-attacks`](red-team/blockchain/flash-loan-and-capital-attacks/SKILL.md) | core | flash loan exploit, capital assumption, atomic attack, governance flash loan |
| [`governance-and-token-attacks`](red-team/blockchain/governance-and-token-attacks/SKILL.md) | leaf | governance attack, vote manipulation, token abuse, proposal exploit |
| [`move-aptos-and-sui-smart-contract-audit`](red-team/blockchain/move-aptos-and-sui-smart-contract-audit/SKILL.md) | leaf | move smart contract audit, sui security, aptos move audit, ability drop store key, hot potato move |
| [`oracle-and-price-manipulation`](red-team/blockchain/oracle-and-price-manipulation/SKILL.md) | core | oracle manipulation, price manipulation, twap attack, spot price |
| [`reentrancy-and-call-ordering`](red-team/blockchain/reentrancy-and-call-ordering/SKILL.md) | core | reentrancy, call ordering, read only reentrancy, cross function reentrancy |
| [`smart-contract-audit`](red-team/blockchain/smart-contract-audit/SKILL.md) | core | smart contract audit, solidity audit, contract review, defi audit |
| [`smart-contract-audit-static-analysis-tooling`](red-team/blockchain/smart-contract-audit-static-analysis-tooling/SKILL.md) | leaf | slither, mythril, solidity static analysis |
| [`smart-contract-audit-testing-and-invariants`](red-team/blockchain/smart-contract-audit-testing-and-invariants/SKILL.md) | leaf | foundry test, echidna, invariant fuzzing, property testing |
| [`solana-anchor-and-svm-program-audit`](red-team/blockchain/solana-anchor-and-svm-program-audit/SKILL.md) | core | solana smart contract audit, anchor security, arbitrary cpi solana, pda bump seed, account closing solana |
| [`wallet-and-key-management-attacks`](red-team/blockchain/wallet-and-key-management-attacks/SKILL.md) | core | wallet attack, private key exposure, approval abuse, signature phishing |
| [`wallet-and-key-management-attacks-approval-and-permit-abuse`](red-team/blockchain/wallet-and-key-management-attacks-approval-and-permit-abuse/SKILL.md) | leaf | approval drain, permit phishing, allowance abuse |
| [`wallet-and-key-management-attacks-key-generation-weakness`](red-team/blockchain/wallet-and-key-management-attacks-key-generation-weakness/SKILL.md) | leaf | wallet weak key, entropy weakness, nonce reuse wallet |
| [`web3-infrastructure-and-rpc`](red-team/blockchain/web3-infrastructure-and-rpc/SKILL.md) | leaf | web3 rpc exposure, dapp frontend attack, node misconfiguration, ens takeover |

## red-team / Cloud, Container and Supply Chain

| Sub-skill | Tier | Triggers |
|---|---|---|
| [`aws-attacks`](red-team/cloud-container-supply-chain/aws-attacks/SKILL.md) | flagship | aws attack, aws pentest, s3 bucket abuse, iam privesc aws, aws credentials |
| [`aws-attacks-compute-and-metadata`](red-team/cloud-container-supply-chain/aws-attacks-compute-and-metadata/SKILL.md) | leaf | ec2 metadata, imdsv1, user data exposure, instance profile |
| [`aws-attacks-iam-and-role-chaining`](red-team/cloud-container-supply-chain/aws-attacks-iam-and-role-chaining/SKILL.md) | leaf | aws iam privesc, role chaining, assume role, aws policy analysis |
| [`aws-attacks-s3-and-storage`](red-team/cloud-container-supply-chain/aws-attacks-s3-and-storage/SKILL.md) | leaf | s3 bucket attack, bucket policy, presigned url, s3 acl |
| [`azure-and-entra-attacks`](red-team/cloud-container-supply-chain/azure-and-entra-attacks/SKILL.md) | core | azure attack, entra id attack, azure pentest, managed identity, service principal abuse |
| [`azure-and-entra-attacks-rbac-and-managed-identity`](red-team/cloud-container-supply-chain/azure-and-entra-attacks-rbac-and-managed-identity/SKILL.md) | leaf | azure rbac abuse, managed identity token, automation account |
| [`azure-and-entra-attacks-token-and-consent-abuse`](red-team/cloud-container-supply-chain/azure-and-entra-attacks-token-and-consent-abuse/SKILL.md) | leaf | entra consent phishing, illicit consent, primary refresh token, device code azure |
| [`ci-cd-and-dependency-attacks`](red-team/cloud-container-supply-chain/ci-cd-and-dependency-attacks/SKILL.md) | core | ci cd attack, pipeline injection, dependency confusion, github actions exploit, artifact tampering |
| [`ci-cd-and-dependency-attacks-dependency-confusion`](red-team/cloud-container-supply-chain/ci-cd-and-dependency-attacks-dependency-confusion/SKILL.md) | leaf | dependency confusion, typosquatting, package substitution |
| [`ci-cd-and-dependency-attacks-pipeline-injection`](red-team/cloud-container-supply-chain/ci-cd-and-dependency-attacks-pipeline-injection/SKILL.md) | leaf | github actions injection, pipeline injection, workflow expression injection |
| [`cloud-iam-privilege-escalation`](red-team/cloud-container-supply-chain/cloud-iam-privilege-escalation/SKILL.md) | core | cloud iam privesc, iam escalation, passrole, trust policy, privilege escalation cloud |
| [`cloud-persistence-and-defense-evasion`](red-team/cloud-container-supply-chain/cloud-persistence-and-defense-evasion/SKILL.md) | leaf | cloud persistence, iam backdoor, cloud defense evasion, audit log gap |
| [`cloud-recon-and-enumeration`](red-team/cloud-container-supply-chain/cloud-recon-and-enumeration/SKILL.md) | core | cloud recon, cloud enumeration, cloud footprint, tenant discovery, public bucket enum |
| [`cloud-storage-and-metadata-abuse`](red-team/cloud-container-supply-chain/cloud-storage-and-metadata-abuse/SKILL.md) | core | cloud storage abuse, public bucket, metadata credential theft, imds abuse |
| [`container-escape`](red-team/cloud-container-supply-chain/container-escape/SKILL.md) | core | container escape, docker escape, privileged container, runtime socket escape |
| [`container-escape-mount-and-socket-escapes`](red-team/cloud-container-supply-chain/container-escape-mount-and-socket-escapes/SKILL.md) | leaf | docker socket escape, hostpath escape, cgroup escape |
| [`container-escape-privileged-and-capabilities`](red-team/cloud-container-supply-chain/container-escape-privileged-and-capabilities/SKILL.md) | leaf | privileged container escape, cap_sys_admin, capability escape |
| [`ebpf-and-cilium-kubernetes-network-policy-audit`](red-team/cloud-container-supply-chain/ebpf-and-cilium-kubernetes-network-policy-audit/SKILL.md) | leaf | kubernetes networkpolicy audit, ciliumnetworkpolicy, default deny k8s, imds egress block k8s |
| [`gcp-attacks`](red-team/cloud-container-supply-chain/gcp-attacks/SKILL.md) | core | gcp attack, gcp pentest, service account abuse, gcs bucket, google cloud attack |
| [`github-actions-and-oidc-federation-security`](red-team/cloud-container-supply-chain/github-actions-and-oidc-federation-security/SKILL.md) | core | github actions oidc, sub claim wildcard iam, pull_request_target, pin actions to sha, gitlab oidc aws |
| [`infrastructure-as-code-review`](red-team/cloud-container-supply-chain/infrastructure-as-code-review/SKILL.md) | leaf | iac review, terraform security, cloudformation review, infrastructure as code |
| [`kubernetes-pentesting`](red-team/cloud-container-supply-chain/kubernetes-pentesting/SKILL.md) | core | kubernetes pentest, k8s attack, rbac kubernetes, service account token, kubelet |
| [`kubernetes-pentesting-admission-and-workload-abuse`](red-team/cloud-container-supply-chain/kubernetes-pentesting-admission-and-workload-abuse/SKILL.md) | leaf | privileged pod, hostpath abuse, admission bypass |
| [`kubernetes-pentesting-node-and-kubelet-access`](red-team/cloud-container-supply-chain/kubernetes-pentesting-node-and-kubelet-access/SKILL.md) | leaf | kubelet access, node escape k8s, control plane access |
| [`kubernetes-pentesting-rbac-and-service-accounts`](red-team/cloud-container-supply-chain/kubernetes-pentesting-rbac-and-service-accounts/SKILL.md) | leaf | k8s rbac abuse, service account token, kubectl auth |
| [`npm-pypi-and-cargo-install-hook-supply-chain`](red-team/cloud-container-supply-chain/npm-pypi-and-cargo-install-hook-supply-chain/SKILL.md) | leaf | npm postinstall security, rust build.rs audit, pip index-url confusion, lockfile integrity check |
| [`oci-container-image-and-registry-supply-chain`](red-team/cloud-container-supply-chain/oci-container-image-and-registry-supply-chain/SKILL.md) | leaf | container image signing, cosign sigstore, dockerfile secret layer, slsa provenance, oci registry security |
| [`saas-oauth-app-and-m365-workspace-security`](red-team/cloud-container-supply-chain/saas-oauth-app-and-m365-workspace-security/SKILL.md) | core | m365 security assessment, google workspace oauth audit, okta policy review, oauth app consent audit |
| [`secrets-hunting-and-source-leak`](red-team/cloud-container-supply-chain/secrets-hunting-and-source-leak/SKILL.md) | core | secret hunting, leaked credentials, github secret, trufflehog, source leak |
| [`serverless-and-function-abuse`](red-team/cloud-container-supply-chain/serverless-and-function-abuse/SKILL.md) | leaf | serverless attack, lambda exploit, function abuse, faas security |
| [`supply-chain-attack-recon`](red-team/cloud-container-supply-chain/supply-chain-attack-recon/SKILL.md) | core | supply chain recon, dependency mapping, software supply chain, third party risk recon |
| [`terraform-state-and-gitops-argocd-security`](red-team/cloud-container-supply-chain/terraform-state-and-gitops-argocd-security/SKILL.md) | leaf | terraform tfstate secrets, argocd security, flux gitops, appproject rbac, iac state backend |

## red-team / Cryptography Attacks

| Sub-skill | Tier | Triggers |
|---|---|---|
| [`aead-aes-gcm-and-chacha20-misuse`](red-team/cryptography-attacks/aead-aes-gcm-and-chacha20-misuse/SKILL.md) | core | aes-gcm nonce reuse, forbidden attack gcm, truncated gcm tag, missing aad binding, chacha20 poly1305 |
| [`block-cipher-modes-and-padding-oracles`](red-team/cryptography-attacks/block-cipher-modes-and-padding-oracles/SKILL.md) | core | padding oracle, cbc bit flip, ecb oracle, block cipher mode attack |
| [`block-cipher-modes-and-padding-oracles-cbc-bit-flipping`](red-team/cryptography-attacks/block-cipher-modes-and-padding-oracles-cbc-bit-flipping/SKILL.md) | leaf | cbc bit flip, iv manipulation, bit flipping attack |
| [`block-cipher-modes-and-padding-oracles-ecb-pattern-exploitation`](red-team/cryptography-attacks/block-cipher-modes-and-padding-oracles-ecb-pattern-exploitation/SKILL.md) | leaf | ecb oracle, byte at a time, ecb detection, block alignment |
| [`block-cipher-padding-oracle-exploitation`](red-team/cryptography-attacks/block-cipher-padding-oracle-exploitation/SKILL.md) | leaf | padding oracle attack, pkcs7 oracle, decryption oracle |
| [`classical-and-covert-encoding`](red-team/cryptography-attacks/classical-and-covert-encoding/SKILL.md) | leaf | classical cipher, caesar, vigenere, substitution cipher, base64 decode, encoding chain |
| [`constant-time-and-crypto-side-channel-code-audit`](red-team/cryptography-attacks/constant-time-and-crypto-side-channel-code-audit/SKILL.md) | leaf | timing attack code review, hmac.compare_digest, constant time comparison, secret branch leak |
| [`crypto-implementation-review`](red-team/cryptography-attacks/crypto-implementation-review/SKILL.md) | core | crypto code review, implementation mistake, key management, crypto misuse |
| [`ecc-and-diffie-hellman-attacks`](red-team/cryptography-attacks/ecc-and-diffie-hellman-attacks/SKILL.md) | core | ecc attack, elliptic curve, diffie hellman attack, invalid curve, small subgroup |
| [`envelope-encryption-and-kms-tenant-isolation`](red-team/cryptography-attacks/envelope-encryption-and-kms-tenant-isolation/SKILL.md) | leaf | envelope encryption security, kms encryptioncontext, dek kek tenant isolation, vault transit aad |
| [`hash-attacks-and-length-extension`](red-team/cryptography-attacks/hash-attacks-and-length-extension/SKILL.md) | core | hash length extension, md5 collision, hash bypass, weak hash |
| [`hash-attacks-and-length-extension-collision-and-bypass`](red-team/cryptography-attacks/hash-attacks-and-length-extension-collision-and-bypass/SKILL.md) | leaf | hash collision, magic hash, hash comparison bypass |
| [`hash-attacks-and-length-extension-length-extension`](red-team/cryptography-attacks/hash-attacks-and-length-extension-length-extension/SKILL.md) | leaf | length extension attack, hash append, merkle damgard |
| [`lattice-and-advanced-crypto-attacks`](red-team/cryptography-attacks/lattice-and-advanced-crypto-attacks/SKILL.md) | leaf | lattice attack, lll, coppersmith, hidden number, knapsack crypto |
| [`password-hashing-and-kdf-attacks`](red-team/cryptography-attacks/password-hashing-and-kdf-attacks/SKILL.md) | core | password hash attack, bcrypt cost, pbkdf2 weakness, kdf attack, unsalted hash |
| [`post-quantum-cryptography-migration-and-hybrids`](red-team/cryptography-attacks/post-quantum-cryptography-migration-and-hybrids/SKILL.md) | core | post quantum cryptography, ml-kem kyber, ml-dsa dilithium, hybrid kem tls, pqc migration |
| [`prng-and-nonce-attacks`](red-team/cryptography-attacks/prng-and-nonce-attacks/SKILL.md) | core | predictable random, prng weakness, seed prediction, nonce reuse, weak randomness |
| [`prng-and-nonce-attacks-predictable-token-generation`](red-team/cryptography-attacks/prng-and-nonce-attacks-predictable-token-generation/SKILL.md) | leaf | predictable token, prng state recovery, time seeded token |
| [`prng-and-nonce-attacks-signature-nonce-reuse`](red-team/cryptography-attacks/prng-and-nonce-attacks-signature-nonce-reuse/SKILL.md) | leaf | ecdsa nonce reuse, dsa nonce, private key recovery |
| [`rsa-attacks`](red-team/cryptography-attacks/rsa-attacks/SKILL.md) | flagship | rsa attack, rsa ctf, small exponent, common modulus, wiener attack, rsa oracle |
| [`rsa-attacks-factorization`](red-team/cryptography-attacks/rsa-attacks-factorization/SKILL.md) | leaf | rsa factorization, fermat attack, shared prime, pollard rho rsa |
| [`rsa-attacks-padding-oracle`](red-team/cryptography-attacks/rsa-attacks-padding-oracle/SKILL.md) | leaf | bleichenbacher, rsa padding oracle, pkcs1 oracle |
| [`rsa-attacks-signature-forgery`](red-team/cryptography-attacks/rsa-attacks-signature-forgery/SKILL.md) | leaf | rsa signature forgery, rsa signature attack, textbook rsa |
| [`rsa-attacks-small-and-low-exponent`](red-team/cryptography-attacks/rsa-attacks-small-and-low-exponent/SKILL.md) | leaf | rsa small exponent, e=3 rsa, hastad broadcast, coppersmith rsa |
| [`signature-and-mac-attacks`](red-team/cryptography-attacks/signature-and-mac-attacks/SKILL.md) | core | signature bypass, mac bypass, hmac attack, verification bypass |
| [`steganography-and-covert-channels`](red-team/cryptography-attacks/steganography-and-covert-channels/SKILL.md) | leaf | steganography, lsb steganography, hidden data, covert channel, steghide |
| [`symmetric-cipher-attacks`](red-team/cryptography-attacks/symmetric-cipher-attacks/SKILL.md) | core | aes attack, symmetric crypto attack, nonce reuse, iv reuse, ecb pattern |
| [`symmetric-cipher-attacks-keystream-and-nonce-reuse`](red-team/cryptography-attacks/symmetric-cipher-attacks-keystream-and-nonce-reuse/SKILL.md) | leaf | keystream reuse, ctr nonce reuse, stream cipher attack |
| [`symmetric-cipher-attacks-weak-key-derivation`](red-team/cryptography-attacks/symmetric-cipher-attacks-weak-key-derivation/SKILL.md) | leaf | weak kdf, predictable key, key derivation weakness |
| [`tls-and-pki-attacks`](red-team/cryptography-attacks/tls-and-pki-attacks/SKILL.md) | core | tls attack, ssl misconfiguration, pki attack, certificate validation, cipher suite |
| [`tls-and-pki-attacks-certificate-validation-gaps`](red-team/cryptography-attacks/tls-and-pki-attacks-certificate-validation-gaps/SKILL.md) | leaf | certificate validation bypass, pinning gap, chain validation |
| [`tls-and-pki-attacks-configuration-weaknesses`](red-team/cryptography-attacks/tls-and-pki-attacks-configuration-weaknesses/SKILL.md) | leaf | tls misconfiguration, weak cipher, no forward secrecy, ssl scan |
| [`zk-and-mpc-protocol-review`](red-team/cryptography-attacks/zk-and-mpc-protocol-review/SKILL.md) | leaf | zero knowledge review, zk circuit, mpc protocol, trusted setup, soundness |

## red-team / Mobile, Hardware, Wireless and ICS

| Sub-skill | Tier | Triggers |
|---|---|---|
| [`android-app-security`](red-team/mobile-hardware-wireless-ics/android-app-security/SKILL.md) | core | android pentest, apk analysis, android security, exported component, android storage |
| [`android-app-security-component-and-deeplink`](red-team/mobile-hardware-wireless-ics/android-app-security-component-and-deeplink/SKILL.md) | leaf | exported activity, deeplink abuse, intent redirection, content provider |
| [`android-app-security-static-analysis`](red-team/mobile-hardware-wireless-ics/android-app-security-static-analysis/SKILL.md) | leaf | apk static analysis, jadx apk, android manifest review |
| [`android-app-security-storage-and-network`](red-team/mobile-hardware-wireless-ics/android-app-security-storage-and-network/SKILL.md) | leaf | android storage, network security config, cleartext traffic, backup |
| [`automotive-and-can-bus`](red-team/mobile-hardware-wireless-ics/automotive-and-can-bus/SKILL.md) | leaf | can bus, automotive security, ecu attack, can injection |
| [`firmware-extraction-and-emulation`](red-team/mobile-hardware-wireless-ics/firmware-extraction-and-emulation/SKILL.md) | core | firmware extraction, firmware emulation, binwalk, squashfs, qemu firmware |
| [`gnss-and-satellite-link-security`](red-team/mobile-hardware-wireless-ics/gnss-and-satellite-link-security/SKILL.md) | leaf | gnss spoofing detection, gps authentication osnma, satcom modem security |
| [`hardware-debug-interfaces`](red-team/mobile-hardware-wireless-ics/hardware-debug-interfaces/SKILL.md) | core | uart, jtag, swd, hardware debug, serial console, spi flash |
| [`hardware-debug-interfaces-jtag-and-swd`](red-team/mobile-hardware-wireless-ics/hardware-debug-interfaces-jtag-and-swd/SKILL.md) | leaf | jtag debug, swd openocd, debug port |
| [`hardware-debug-interfaces-uart-and-serial`](red-team/mobile-hardware-wireless-ics/hardware-debug-interfaces-uart-and-serial/SKILL.md) | leaf | uart console, serial console, baud detection |
| [`ics-ot-protocol-attacks`](red-team/mobile-hardware-wireless-ics/ics-ot-protocol-attacks/SKILL.md) | core | ics security, modbus, dnp3, s7, ot protocol, scada testing |
| [`ics-ot-protocol-attacks-ot-network-architecture`](red-team/mobile-hardware-wireless-ics/ics-ot-protocol-attacks-ot-network-architecture/SKILL.md) | leaf | ot segmentation, it ot boundary, ot remote access |
| [`ics-ot-protocol-attacks-protocol-exposure-assessment`](red-team/mobile-hardware-wireless-ics/ics-ot-protocol-attacks-protocol-exposure-assessment/SKILL.md) | leaf | ics enumeration, ot protocol exposure, modbus scan |
| [`ieee-802-15-4-and-zigbee-mesh-security`](red-team/mobile-hardware-wireless-ics/ieee-802-15-4-and-zigbee-mesh-security/SKILL.md) | leaf | zigbee security, 802.15.4 mesh, trust center link key, zigbee install code |
| [`ios-app-security`](red-team/mobile-hardware-wireless-ics/ios-app-security/SKILL.md) | core | ios pentest, ipa analysis, ios security, keychain, url scheme ios |
| [`ios-app-security-binary-and-entitlements`](red-team/mobile-hardware-wireless-ics/ios-app-security-binary-and-entitlements/SKILL.md) | leaf | ios binary analysis, entitlements ios, decrypt ipa |
| [`ios-app-security-storage-and-url-handling`](red-team/mobile-hardware-wireless-ics/ios-app-security-storage-and-url-handling/SKILL.md) | leaf | ios keychain, url scheme hijack, universal link, plist storage |
| [`iot-device-exploitation`](red-team/mobile-hardware-wireless-ics/iot-device-exploitation/SKILL.md) | core | iot exploit, iot security, default creds iot, firmware update iot |
| [`iot-thread-and-openthread-security`](red-team/mobile-hardware-wireless-ics/iot-thread-and-openthread-security/SKILL.md) | core | openthread security, thread mesh protocol, meshcop commissioning, border router thread, pskd thread |
| [`matter-protocol-commissioning-and-fabric-security`](red-team/mobile-hardware-wireless-ics/matter-protocol-commissioning-and-fabric-security/SKILL.md) | core | matter protocol security, pase case matter, device attestation certificate, matter fabric acl |
| [`mobile-instrumentation-and-pinning-bypass`](red-team/mobile-hardware-wireless-ics/mobile-instrumentation-and-pinning-bypass/SKILL.md) | core | frida, objection, ssl pinning bypass, root detection bypass, jailbreak bypass |
| [`mqtt-and-coap-broker-security`](red-team/mobile-hardware-wireless-ics/mqtt-and-coap-broker-security/SKILL.md) | leaf | mqtt security, mosquitto wildcard acl, coap security, $sys topic exposure, iot broker audit |
| [`physical-security-and-rfid`](red-team/mobile-hardware-wireless-ics/physical-security-and-rfid/SKILL.md) | leaf | rfid cloning, physical access, badge clone, lock bypass |
| [`plc-and-scada-exploitation`](red-team/mobile-hardware-wireless-ics/plc-and-scada-exploitation/SKILL.md) | leaf | plc exploit, scada attack, engineering workstation, ladder logic |
| [`rf-and-sdr-attacks`](red-team/mobile-hardware-wireless-ics/rf-and-sdr-attacks/SKILL.md) | core | sdr, rf attack, signal replay, radio hacking, hackrf |
| [`secure-boot-and-trusted-execution`](red-team/mobile-hardware-wireless-ics/secure-boot-and-trusted-execution/SKILL.md) | leaf | secure boot bypass, trusted execution, tpm analysis, boot chain |
| [`side-channel-and-fault-injection`](red-team/mobile-hardware-wireless-ics/side-channel-and-fault-injection/SKILL.md) | leaf | side channel, power analysis, fault injection, glitching, timing attack hardware |
| [`wireless-wifi-and-bluetooth-attacks`](red-team/mobile-hardware-wireless-ics/wireless-wifi-and-bluetooth-attacks/SKILL.md) | core | wifi attack, wpa cracking, evil twin, bluetooth attack, ble sniffing, wps |
| [`wireless-wifi-and-bluetooth-attacks-bluetooth-and-ble`](red-team/mobile-hardware-wireless-ics/wireless-wifi-and-bluetooth-attacks-bluetooth-and-ble/SKILL.md) | leaf | ble attack, bluetooth sniffing, ble replay |
| [`wireless-wifi-and-bluetooth-attacks-rogue-ap-and-evil-twin`](red-team/mobile-hardware-wireless-ics/wireless-wifi-and-bluetooth-attacks-rogue-ap-and-evil-twin/SKILL.md) | leaf | evil twin, rogue ap, captive portal, deauth |
| [`wireless-wifi-and-bluetooth-attacks-wpa-handshake-and-pmkid`](red-team/mobile-hardware-wireless-ics/wireless-wifi-and-bluetooth-attacks-wpa-handshake-and-pmkid/SKILL.md) | leaf | wpa handshake, pmkid attack, wifi cracking |

## red-team / Network, Active Directory and Endpoint

| Sub-skill | Tier | Triggers |
|---|---|---|
| [`active-directory-acl-and-delegation-abuse`](red-team/network-ad-and-endpoint/active-directory-acl-and-delegation-abuse/SKILL.md) | core | acl abuse, ad acl, genericall, writedacl, rbcd, unconstrained delegation, ... |
| [`active-directory-acl-and-delegation-abuse-group-and-ou-abuse`](red-team/network-ad-and-endpoint/active-directory-acl-and-delegation-abuse-group-and-ou-abuse/SKILL.md) | leaf | group abuse, ou permissions, gpo link abuse, delegated control |
| [`active-directory-acl-genericall-writedacl`](red-team/network-ad-and-endpoint/active-directory-acl-genericall-writedacl/SKILL.md) | leaf | genericall, writedacl, full control acl, dacl abuse |
| [`active-directory-acl-targeted-kerberoast-shadow-credentials`](red-team/network-ad-and-endpoint/active-directory-acl-targeted-kerberoast-shadow-credentials/SKILL.md) | leaf | shadow credentials, key credential link, msds-keycredentiallink, whisker |
| [`active-directory-certificate-services`](red-team/network-ad-and-endpoint/active-directory-certificate-services/SKILL.md) | core | adcs, ad certificate services, esc1, esc8, certificate template, certipy |
| [`active-directory-certificate-services-esc1-through-esc4`](red-team/network-ad-and-endpoint/active-directory-certificate-services-esc1-through-esc4/SKILL.md) | leaf | esc1 esc2 esc3 esc4, adcs template abuse, requester supplied subject |
| [`active-directory-certificate-services-esc5-through-esc8`](red-team/network-ad-and-endpoint/active-directory-certificate-services-esc5-through-esc8/SKILL.md) | leaf | esc5 esc6 esc7 esc8, adcs relay, certificate persistence |
| [`active-directory-enumeration`](red-team/network-ad-and-endpoint/active-directory-enumeration/SKILL.md) | core | active directory enumeration, ad enum, bloodhound, ldap enumeration, domain enumeration |
| [`active-directory-enumeration-authenticated-enumeration`](red-team/network-ad-and-endpoint/active-directory-enumeration-authenticated-enumeration/SKILL.md) | leaf | bloodhound collection, ad path mapping, acl path, low priv enumeration |
| [`active-directory-enumeration-gpo-and-administrative-discovery`](red-team/network-ad-and-endpoint/active-directory-enumeration-gpo-and-administrative-discovery/SKILL.md) | leaf | gpo enumeration, delegated control discovery, admin group discovery |
| [`active-directory-enumeration-unauthenticated-enumeration`](red-team/network-ad-and-endpoint/active-directory-enumeration-unauthenticated-enumeration/SKILL.md) | leaf | unauthenticated ad enum, null session ldap, anonymous domain enum |
| [`active-directory-kerberos-attacks`](red-team/network-ad-and-endpoint/active-directory-kerberos-attacks/SKILL.md) | flagship | kerberos attack, kerberoast, asrep roast, golden ticket, silver ticket, delegation abuse |
| [`active-directory-kerberos-attacks-asrep-roasting`](red-team/network-ad-and-endpoint/active-directory-kerberos-attacks-asrep-roasting/SKILL.md) | leaf | asrep roast, as-rep roasting, no preauth |
| [`active-directory-kerberos-attacks-delegation`](red-team/network-ad-and-endpoint/active-directory-kerberos-attacks-delegation/SKILL.md) | leaf | kerberos delegation, unconstrained delegation, constrained delegation, s4u, rbcd kerberos |
| [`active-directory-kerberos-attacks-golden-and-silver-tickets`](red-team/network-ad-and-endpoint/active-directory-kerberos-attacks-golden-and-silver-tickets/SKILL.md) | leaf | golden ticket, silver ticket, krbtgt forge, ticket forgery |
| [`active-directory-kerberos-attacks-kerberoasting`](red-team/network-ad-and-endpoint/active-directory-kerberos-attacks-kerberoasting/SKILL.md) | leaf | kerberoast, spn crack, kerberoasting attack |
| [`active-directory-kerberos-attacks-ticket-abuse-and-forgery`](red-team/network-ad-and-endpoint/active-directory-kerberos-attacks-ticket-abuse-and-forgery/SKILL.md) | leaf | pass the ticket, overpass the hash, ticket dump, kirbi |
| [`active-directory-persistence`](red-team/network-ad-and-endpoint/active-directory-persistence/SKILL.md) | core | ad persistence, golden ticket persistence, sid history, adminsdholder, skeleton key, dcshadow |
| [`active-directory-trust-and-forest-abuse`](red-team/network-ad-and-endpoint/active-directory-trust-and-forest-abuse/SKILL.md) | leaf | ad trust, forest trust abuse, sid filtering, trust key, inter-domain escalation |
| [`antivirus-evasion-and-obfuscation`](red-team/network-ad-and-endpoint/antivirus-evasion-and-obfuscation/SKILL.md) | core | antivirus evasion, av obfuscation, packer, loader, payload encoding, signature evasion |
| [`byovd-and-driver-abuse`](red-team/network-ad-and-endpoint/byovd-and-driver-abuse/SKILL.md) | core | byovd, vulnerable driver, driver exploitation, disable edr driver, signed driver abuse |
| [`c2-implant-and-beaconing`](red-team/network-ad-and-endpoint/c2-implant-and-beaconing/SKILL.md) | core | c2 implant, beacon, implant operation, cobalt strike beacon, sliver, havoc |
| [`c2-infrastructure-and-redirectors`](red-team/network-ad-and-endpoint/c2-infrastructure-and-redirectors/SKILL.md) | core | c2 infrastructure, redirector, c2 domain, cobalt strike infrastructure, domain fronting, c2 opsec |
| [`credential-dumping`](red-team/network-ad-and-endpoint/credential-dumping/SKILL.md) | core | credential dumping, lsass dump, mimikatz, sam dump, ntds.dit, dpapi |
| [`credential-dumping-dpapi-and-secret-stores`](red-team/network-ad-and-endpoint/credential-dumping-dpapi-and-secret-stores/SKILL.md) | leaf | dpapi, credential manager, browser passwords, masterkey decrypt |
| [`credential-dumping-lsass-and-memory`](red-team/network-ad-and-endpoint/credential-dumping-lsass-and-memory/SKILL.md) | leaf | lsass dump, comsvcs minidump, procdump lsass, ppl lsass |
| [`credential-dumping-sam-and-ntds`](red-team/network-ad-and-endpoint/credential-dumping-sam-and-ntds/SKILL.md) | leaf | ntds.dit, sam hive dump, secretsdump, shadow copy ntds |
| [`defense-evasion-and-log-tampering`](red-team/network-ad-and-endpoint/defense-evasion-and-log-tampering/SKILL.md) | core | defense evasion, log tampering, clear event log, timestomp, indicator removal, audit policy |
| [`defense-evasion-and-log-tampering-indicator-removal`](red-team/network-ad-and-endpoint/defense-evasion-and-log-tampering-indicator-removal/SKILL.md) | leaf | timestomp, indicator removal, artefact cleanup, prefetch delete |
| [`defense-evasion-and-log-tampering-log-and-audit-evasion`](red-team/network-ad-and-endpoint/defense-evasion-and-log-tampering-log-and-audit-evasion/SKILL.md) | leaf | clear event log, audit policy evasion, usn journal, log deletion |
| [`edr-evasion-and-amsi-bypass`](red-team/network-ad-and-endpoint/edr-evasion-and-amsi-bypass/SKILL.md) | core | edr evasion, amsi bypass, av bypass, etw patch, endpoint evasion, defender evasion |
| [`edr-evasion-and-amsi-bypass-amsi-bypass`](red-team/network-ad-and-endpoint/edr-evasion-and-amsi-bypass-amsi-bypass/SKILL.md) | leaf | amsi bypass, amsiscanbuffer patch, amsi evasion |
| [`edr-evasion-and-amsi-bypass-etw-and-telemetry-evasion`](red-team/network-ad-and-endpoint/edr-evasion-and-amsi-bypass-etw-and-telemetry-evasion/SKILL.md) | leaf | etw patch, etw bypass, powershell logging bypass, telemetry evasion |
| [`edr-evasion-and-amsi-bypass-sandbox-and-analysis-detection`](red-team/network-ad-and-endpoint/edr-evasion-and-amsi-bypass-sandbox-and-analysis-detection/SKILL.md) | leaf | sandbox detection, vm detection, anti analysis, analysis environment check |
| [`edr-evasion-and-amsi-bypass-unhooking-and-direct-syscalls`](red-team/network-ad-and-endpoint/edr-evasion-and-amsi-bypass-unhooking-and-direct-syscalls/SKILL.md) | leaf | unhooking, direct syscall, indirect syscall, ntdll unhook |
| [`entra-id-and-hybrid-identity`](red-team/network-ad-and-endpoint/entra-id-and-hybrid-identity/SKILL.md) | core | entra id attack, azure ad attack, hybrid identity, token theft, consent phishing, service principal |
| [`firewall-and-segmentation-testing`](red-team/network-ad-and-endpoint/firewall-and-segmentation-testing/SKILL.md) | leaf | firewall test, segmentation test, acl bypass, egress filtering, network boundary |
| [`host-persistence`](red-team/network-ad-and-endpoint/host-persistence/SKILL.md) | core | persistence, host persistence, registry run key, wmi subscription, scheduled task persistence |
| [`host-persistence-linux-and-macos-persistence`](red-team/network-ad-and-endpoint/host-persistence-linux-and-macos-persistence/SKILL.md) | leaf | linux persistence, macos persistence, systemd persistence, cron persistence |
| [`host-persistence-registry-and-service-persistence`](red-team/network-ad-and-endpoint/host-persistence-registry-and-service-persistence/SKILL.md) | leaf | registry persistence, run key persistence, service persistence, com hijack |
| [`host-persistence-scheduled-and-wmi-persistence`](red-team/network-ad-and-endpoint/host-persistence-scheduled-and-wmi-persistence/SKILL.md) | leaf | wmi persistence, scheduled task persistence, event subscription persistence |
| [`initial-access-via-edge-devices`](red-team/network-ad-and-endpoint/initial-access-via-edge-devices/SKILL.md) | leaf | edge device initial access, vpn initial access, exposed appliance, perimeter access |
| [`initial-access-via-phishing`](red-team/network-ad-and-endpoint/initial-access-via-phishing/SKILL.md) | core | phishing, initial access phishing, payload delivery email, mfa fatigue, device code phishing |
| [`linux-lateral-movement`](red-team/network-ad-and-endpoint/linux-lateral-movement/SKILL.md) | leaf | linux lateral movement, ssh pivot, nfs lateral, ansible credential, agent forwarding |
| [`linux-privilege-escalation`](red-team/network-ad-and-endpoint/linux-privilege-escalation/SKILL.md) | flagship | linux privesc, linux privilege escalation, linpeas, sudo abuse, suid, gtfobins |
| [`linux-privilege-escalation-cron-and-systemd`](red-team/network-ad-and-endpoint/linux-privilege-escalation-cron-and-systemd/SKILL.md) | leaf | cron abuse, writable cron, systemd unit abuse, timer escalation |
| [`linux-privilege-escalation-kernel-and-container-escapes`](red-team/network-ad-and-endpoint/linux-privilege-escalation-kernel-and-container-escapes/SKILL.md) | leaf | linux kernel exploit, container escape, docker socket, privileged container escape |
| [`linux-privilege-escalation-nfs-and-share-abuse`](red-team/network-ad-and-endpoint/linux-privilege-escalation-nfs-and-share-abuse/SKILL.md) | leaf | nfs no_root_squash, nfs escalation, writable export, share abuse linux |
| [`linux-privilege-escalation-sudo-abuse`](red-team/network-ad-and-endpoint/linux-privilege-escalation-sudo-abuse/SKILL.md) | leaf | sudo abuse, sudo -l, sudoedit, ld_preload sudo, sudo misconfiguration |
| [`linux-privilege-escalation-suid-and-capabilities`](red-team/network-ad-and-endpoint/linux-privilege-escalation-suid-and-capabilities/SKILL.md) | leaf | suid, setuid escalation, linux capabilities, getcap, cap_setuid |
| [`lolbins-and-signed-binary-abuse`](red-team/network-ad-and-endpoint/lolbins-and-signed-binary-abuse/SKILL.md) | core | lolbins, lolbas, gtfobins, loldrivers, proxy execution, signed binary abuse |
| [`lolbins-and-signed-binary-abuse-download-and-staging`](red-team/network-ad-and-endpoint/lolbins-and-signed-binary-abuse-download-and-staging/SKILL.md) | leaf | certutil download, bitsadmin, certutil decode, lolbin staging |
| [`lolbins-and-signed-binary-abuse-driver-blocklist-gaps`](red-team/network-ad-and-endpoint/lolbins-and-signed-binary-abuse-driver-blocklist-gaps/SKILL.md) | leaf | loldrivers, vulnerable signed driver, driver blocklist |
| [`lolbins-and-signed-binary-abuse-execution-proxies`](red-team/network-ad-and-endpoint/lolbins-and-signed-binary-abuse-execution-proxies/SKILL.md) | leaf | mshta, rundll32, regsvr32, installutil, msbuild execution |
| [`macos-security-bypass`](red-team/network-ad-and-endpoint/macos-security-bypass/SKILL.md) | core | macos privesc, tcc bypass, gatekeeper bypass, macos persistence, keychain dump |
| [`macos-security-bypass-gatekeeper-and-notarization`](red-team/network-ad-and-endpoint/macos-security-bypass-gatekeeper-and-notarization/SKILL.md) | leaf | gatekeeper bypass, quarantine attribute, notarization bypass |
| [`macos-security-bypass-tcc-and-privacy-bypass`](red-team/network-ad-and-endpoint/macos-security-bypass-tcc-and-privacy-bypass/SKILL.md) | leaf | tcc bypass, macos privacy bypass, tcc.db, full disk access |
| [`network-protocol-attacks`](red-team/network-ad-and-endpoint/network-protocol-attacks/SKILL.md) | core | llmnr poisoning, responder, arp spoofing, ipv6 dns takeover, vlan hopping, network mitm |
| [`network-protocol-attacks-capture-and-intercept`](red-team/network-ad-and-endpoint/network-protocol-attacks-capture-and-intercept/SKILL.md) | leaf | traffic interception, packet capture attack, credential sniffing, tls strip |
| [`network-protocol-attacks-ipv6-and-dhcp-abuse`](red-team/network-ad-and-endpoint/network-protocol-attacks-ipv6-and-dhcp-abuse/SKILL.md) | leaf | ipv6 dns takeover, mitm6, rogue dhcp, ra spoofing |
| [`network-protocol-attacks-layer-two-attacks`](red-team/network-ad-and-endpoint/network-protocol-attacks-layer-two-attacks/SKILL.md) | leaf | arp spoofing, vlan hopping, stp attack, cam table flooding |
| [`network-protocol-attacks-name-resolution-poisoning`](red-team/network-ad-and-endpoint/network-protocol-attacks-name-resolution-poisoning/SKILL.md) | leaf | llmnr spoof, nbt-ns poisoning, mdns spoof, responder capture |
| [`network-recon-and-port-scanning`](red-team/network-ad-and-endpoint/network-recon-and-port-scanning/SKILL.md) | core | network recon, port scan, nmap, host discovery, service scan, network discovery |
| [`network-recon-and-port-scanning-external-perimeter-scanning`](red-team/network-ad-and-endpoint/network-recon-and-port-scanning-external-perimeter-scanning/SKILL.md) | leaf | external scan, asn mapping, internet facing recon, perimeter scan |
| [`network-recon-and-port-scanning-internal-network-mapping`](red-team/network-ad-and-endpoint/network-recon-and-port-scanning-internal-network-mapping/SKILL.md) | leaf | internal scan, internal discovery, network mapping internal |
| [`ntlm-relay-and-coercion`](red-team/network-ad-and-endpoint/ntlm-relay-and-coercion/SKILL.md) | core | ntlm relay, ntlm coercion, petitpotam, printerbug, responder relay, smb signing |
| [`ntlm-relay-and-coercion-coercion-primitives`](red-team/network-ad-and-endpoint/ntlm-relay-and-coercion-coercion-primitives/SKILL.md) | leaf | petitpotam, printerbug, dfscoerce, coerce authentication, shadowcoerce |
| [`ntlm-relay-and-coercion-relay-targets`](red-team/network-ad-and-endpoint/ntlm-relay-and-coercion-relay-targets/SKILL.md) | leaf | ntlm relay ldap, relay to smb, relay epa, channel binding relay |
| [`password-cracking-and-wordlists`](red-team/network-ad-and-endpoint/password-cracking-and-wordlists/SKILL.md) | core | password cracking, hashcat, john the ripper, wordlist, rule based cracking, ntlm crack |
| [`pivoting-and-tunneling`](red-team/network-ad-and-endpoint/pivoting-and-tunneling/SKILL.md) | core | pivoting, tunneling, socks proxy, port forward, chisel, ligolo, ... |
| [`pivoting-and-tunneling-dns-and-icmp-tunnels`](red-team/network-ad-and-endpoint/pivoting-and-tunneling-dns-and-icmp-tunnels/SKILL.md) | leaf | dns tunnel, icmp tunnel, dns exfiltration channel |
| [`pivoting-and-tunneling-socks-and-port-forwarding`](red-team/network-ad-and-endpoint/pivoting-and-tunneling-socks-and-port-forwarding/SKILL.md) | leaf | socks proxy pivot, port forwarding, chisel pivot, ligolo |
| [`process-injection-techniques`](red-team/network-ad-and-endpoint/process-injection-techniques/SKILL.md) | core | process injection, process hollowing, apc injection, thread hijacking, shellcode injection |
| [`process-injection-techniques-classic-and-apc-injection`](red-team/network-ad-and-endpoint/process-injection-techniques-classic-and-apc-injection/SKILL.md) | leaf | createremotethread, apc injection, thread hijacking, section injection |
| [`process-injection-techniques-hollowing-and-stomping`](red-team/network-ad-and-endpoint/process-injection-techniques-hollowing-and-stomping/SKILL.md) | leaf | process hollowing, module stomping, process doppelganging |
| [`process-injection-techniques-injection-via-callbacks`](red-team/network-ad-and-endpoint/process-injection-techniques-injection-via-callbacks/SKILL.md) | leaf | callback injection, threadpool injection, enumwindows callback |
| [`reverse-shells-and-payload-delivery`](red-team/network-ad-and-endpoint/reverse-shells-and-payload-delivery/SKILL.md) | leaf | reverse shell, payload delivery, shell upgrade, msfvenom, stabilize shell |
| [`service-enumeration`](red-team/network-ad-and-endpoint/service-enumeration/SKILL.md) | core | service enumeration, smb enum, snmp enum, nfs enum, ftp enum, enum4linux |
| [`service-enumeration-database-and-remote-access`](red-team/network-ad-and-endpoint/service-enumeration-database-and-remote-access/SKILL.md) | leaf | mssql enum, rdp enum, winrm enum, mysql enum, remote access enumeration |
| [`service-enumeration-ldap-and-directory`](red-team/network-ad-and-endpoint/service-enumeration-ldap-and-directory/SKILL.md) | leaf | ldap enum, anonymous ldap, base dn, directory enumeration |
| [`service-enumeration-smb-and-netbios`](red-team/network-ad-and-endpoint/service-enumeration-smb-and-netbios/SKILL.md) | leaf | smb enum, null session, smb signing, rid cycling, share enumeration |
| [`service-enumeration-snmp-and-infrastructure`](red-team/network-ad-and-endpoint/service-enumeration-snmp-and-infrastructure/SKILL.md) | leaf | snmp enum, community string, mib walk, ntp enumeration |
| [`windows-internals-and-api-abuse`](red-team/network-ad-and-endpoint/windows-internals-and-api-abuse/SKILL.md) | leaf | windows internals, token manipulation, handle duplication, native api, ntdll, ppl |
| [`windows-lateral-movement`](red-team/network-ad-and-endpoint/windows-lateral-movement/SKILL.md) | core | windows lateral movement, lateral movement windows, psexec, winrm wmi, pass the hash lateral |
| [`windows-lateral-movement-pass-the-hash-and-ticket`](red-team/network-ad-and-endpoint/windows-lateral-movement-pass-the-hash-and-ticket/SKILL.md) | leaf | pass the hash, pass the ticket, overpass the hash, pth lateral |
| [`windows-lateral-movement-rdp-and-session-abuse`](red-team/network-ad-and-endpoint/windows-lateral-movement-rdp-and-session-abuse/SKILL.md) | leaf | rdp lateral, session hijack, rdp shadow, restricted admin |
| [`windows-lateral-movement-smb-and-remote-execution`](red-team/network-ad-and-endpoint/windows-lateral-movement-smb-and-remote-execution/SKILL.md) | leaf | psexec lateral, smbexec, atexec, admin share execution |
| [`windows-lateral-movement-winrm-and-wmi`](red-team/network-ad-and-endpoint/windows-lateral-movement-winrm-and-wmi/SKILL.md) | leaf | winrm lateral, wmi lateral, evil-winrm, wmiexec |
| [`windows-privilege-escalation`](red-team/network-ad-and-endpoint/windows-privilege-escalation/SKILL.md) | flagship | windows privesc, windows privilege escalation, winpeas, seimpersonate, unquoted service path |
| [`windows-privilege-escalation-credential-and-config-exposure`](red-team/network-ad-and-endpoint/windows-privilege-escalation-credential-and-config-exposure/SKILL.md) | leaf | unattended xml, autologon registry, cpassword, saved rdp, config credentials |
| [`windows-privilege-escalation-kernel-and-driver-escalation`](red-team/network-ad-and-endpoint/windows-privilege-escalation-kernel-and-driver-escalation/SKILL.md) | leaf | windows kernel exploit, local privilege escalation windows, driver lpe |
| [`windows-privilege-escalation-service-and-path-flaws`](red-team/network-ad-and-endpoint/windows-privilege-escalation-service-and-path-flaws/SKILL.md) | leaf | unquoted service path, service acl, dll hijack, writable service binary |
| [`windows-privilege-escalation-token-and-privilege-abuse`](red-team/network-ad-and-endpoint/windows-privilege-escalation-token-and-privilege-abuse/SKILL.md) | leaf | seimpersonate, potato attack, sebackup, token privilege escalation |
| [`windows-privilege-escalation-uac-bypass`](red-team/network-ad-and-endpoint/windows-privilege-escalation-uac-bypass/SKILL.md) | leaf | uac bypass, bypass uac, auto elevate, uacme |
| [`windows-service-and-scheduled-task-abuse`](red-team/network-ad-and-endpoint/windows-service-and-scheduled-task-abuse/SKILL.md) | leaf | service abuse, scheduled task abuse, service permissions, sc create, schtasks abuse |

## red-team / OSINT and Red Operations

| Sub-skill | Tier | Triggers |
|---|---|---|
| [`adversary-emulation-planning`](red-team/osint-and-red-operations/adversary-emulation-planning/SKILL.md) | core | adversary emulation, threat actor emulation, attack mapping plan, red team scenario |
| [`brand-and-impersonation-monitoring`](red-team/osint-and-red-operations/brand-and-impersonation-monitoring/SKILL.md) | leaf | brand monitoring, typosquat domain, lookalike account, phishing infrastructure |
| [`bug-bounty-target-prioritization`](red-team/osint-and-red-operations/bug-bounty-target-prioritization/SKILL.md) | leaf | bug bounty targeting, target prioritization, bounty program selection |
| [`company-registry-and-beneficial-ownership-osint`](red-team/osint-and-red-operations/company-registry-and-beneficial-ownership-osint/SKILL.md) | leaf | company registry osint, opencorporates, sec edgar osint, beneficial ownership, subsidiary mapping |
| [`corporate-and-person-osint`](red-team/osint-and-red-operations/corporate-and-person-osint/SKILL.md) | core | person osint, employee enumeration, email pattern, social media recon, corporate osint |
| [`cryptocurrency-and-onchain-tracing-osint`](red-team/osint-and-red-operations/cryptocurrency-and-onchain-tracing-osint/SKILL.md) | leaf | crypto tracing osint, blockchain forensics, utxo clustering, onchain investigation |
| [`ctf-and-lab-methodology`](red-team/osint-and-red-operations/ctf-and-lab-methodology/SKILL.md) | leaf | ctf methodology, ctf strategy, lab practice, challenge solving |
| [`geolocation-and-imagery-verification-osint`](red-team/osint-and-red-operations/geolocation-and-imagery-verification-osint/SKILL.md) | core | geolocation osint, chronolocation, overpass turbo, suncalc, image verification osint |
| [`infrastructure-osint`](red-team/osint-and-red-operations/infrastructure-osint/SKILL.md) | core | infrastructure osint, dns history, asn lookup, certificate transparency, external footprint |
| [`infrastructure-osint-dns-and-certificate`](red-team/osint-and-red-operations/infrastructure-osint-dns-and-certificate/SKILL.md) | leaf | passive dns, certificate transparency, crt.sh, dns history |
| [`infrastructure-osint-host-and-service-discovery`](red-team/osint-and-red-operations/infrastructure-osint-host-and-service-discovery/SKILL.md) | leaf | shodan query, censys, internet scanner, banner search |
| [`lab-and-tooling-setup`](red-team/osint-and-red-operations/lab-and-tooling-setup/SKILL.md) | leaf | security lab setup, tooling setup, lab environment, kali setup |
| [`osint-identity-and-email-correlation`](red-team/osint-and-red-operations/osint-identity-and-email-correlation/SKILL.md) | leaf | username correlation, email lookup, breach data, identity correlation |
| [`osint-methodology`](red-team/osint-and-red-operations/osint-methodology/SKILL.md) | core | osint methodology, open source intelligence, osint process, collection plan |
| [`osint-methodology-collection-and-logging`](red-team/osint-and-red-operations/osint-methodology-collection-and-logging/SKILL.md) | leaf | osint collection plan, source logging, provenance |
| [`osint-methodology-verification-and-bias`](red-team/osint-and-red-operations/osint-methodology-verification-and-bias/SKILL.md) | leaf | osint verification, source credibility, intelligence bias |
| [`osint-operational-security`](red-team/osint-and-red-operations/osint-operational-security/SKILL.md) | leaf | osint opsec, sock puppet, collection attribution, investigator opsec |
| [`physical-and-facility-osint`](red-team/osint-and-red-operations/physical-and-facility-osint/SKILL.md) | leaf | physical osint, geolocation, facility recon, site intelligence |
| [`red-team-operations-and-scoping`](red-team/osint-and-red-operations/red-team-operations-and-scoping/SKILL.md) | core | red team operations, red team scoping, roe, red team opsec, adversary emulation |
| [`report-writing-and-findings`](red-team/osint-and-red-operations/report-writing-and-findings/SKILL.md) | core | security report, report writing, findings writeup, vulnerability report |
| [`security-arsenal-and-tool-index`](red-team/osint-and-red-operations/security-arsenal-and-tool-index/SKILL.md) | leaf | security tools, tool index, which tool, tooling reference |
| [`social-engineering-and-pretexting`](red-team/osint-and-red-operations/social-engineering-and-pretexting/SKILL.md) | core | social engineering, pretexting, vishing, social engineering assessment |
| [`social-engineering-and-pretexting-email-and-credential-phishing`](red-team/osint-and-red-operations/social-engineering-and-pretexting-email-and-credential-phishing/SKILL.md) | leaf | phishing execution, credential harvest, phishing infrastructure, evilginx |
| [`social-engineering-and-pretexting-voice-and-message-based`](red-team/osint-and-red-operations/social-engineering-and-pretexting-voice-and-message-based/SKILL.md) | leaf | vishing, smishing, helpdesk impersonation, voice phishing |
| [`username-and-account-pivot-osint`](red-team/osint-and-red-operations/username-and-account-pivot-osint/SKILL.md) | leaf | username pivot osint, maigret, handle correlation, commit email osint, pgp key lookup |
| [`web-archival-and-deleted-content-osint`](red-team/osint-and-red-operations/web-archival-and-deleted-content-osint/SKILL.md) | leaf | wayback cdx osint, web archive investigation, deleted page recovery, common crawl osint |

## red-team / Security Assessment Tooling and Automation

| Sub-skill | Tier | Triggers |
|---|---|---|
| [`angr-and-z3-constraint-solver-scripting`](red-team/security-assessment-tooling-and-automation/angr-and-z3-constraint-solver-scripting/SKILL.md) | leaf | angr script, z3 solver python, simulationmanager angr, bitvec z3 |
| [`async-http-and-dns-audit-scripting`](red-team/security-assessment-tooling-and-automation/async-http-and-dns-audit-scripting/SKILL.md) | core | httpx async scanner, python http audit script, asyncio semaphore http, dnspython script |
| [`binary-ninja-il-automation-scripting`](red-team/security-assessment-tooling-and-automation/binary-ninja-il-automation-scripting/SKILL.md) | leaf | binary ninja script, binja hlil, mlil ssa, binaryview python |
| [`burp-montoya-and-jython-extension-development`](red-team/security-assessment-tooling-and-automation/burp-montoya-and-jython-extension-development/SKILL.md) | flagship | burp extension, montoya api, burp plugin, passive scan check, burpextender |
| [`capstone-and-lief-binary-inspector-scripting`](red-team/security-assessment-tooling-and-automation/capstone-and-lief-binary-inspector-scripting/SKILL.md) | leaf | lief python, capstone disassembly script, pe elf security checker, firmware binary audit |
| [`cloud-and-k8s-readonly-posture-scripting`](red-team/security-assessment-tooling-and-automation/cloud-and-k8s-readonly-posture-scripting/SKILL.md) | core | boto3 security audit, k8s rbac audit script, custom cspm python, readonly cloud checker |
| [`codeql-query-development`](red-team/security-assessment-tooling-and-automation/codeql-query-development/SKILL.md) | flagship | codeql query, write codeql, tainttracking global, path-problem ql, variant analysis codeql |
| [`foundry-and-echidna-invariant-harness-scripting`](red-team/security-assessment-tooling-and-automation/foundry-and-echidna-invariant-harness-scripting/SKILL.md) | core | foundry invariant test, stdinvariant handler, echidna harness, ghost variables solidity |
| [`frida-diagnostic-tracing-scripting`](red-team/security-assessment-tooling-and-automation/frida-diagnostic-tracing-scripting/SKILL.md) | core | frida script authoring, interceptor.attach, java.perform frida, objc.classes frida |
| [`ghidra-headless-and-pcode-scripting`](red-team/security-assessment-tooling-and-automation/ghidra-headless-and-pcode-scripting/SKILL.md) | core | ghidra headless script, analyzeheadless, decompinterface pcode, varnode slice ghidra |
| [`go-fuzz-and-cargo-fuzz-harness-development`](red-team/security-assessment-tooling-and-automation/go-fuzz-and-cargo-fuzz-harness-development/SKILL.md) | core | go test fuzz, testing.f go, cargo fuzz, arbitrary crate rust, rust fuzz harness |
| [`go-ssa-and-rust-clippy-security-lints`](red-team/security-assessment-tooling-and-automation/go-ssa-and-rust-clippy-security-lints/SKILL.md) | leaf | go analysis linter, go ssa security, rust dylint, custom clippy lint |
| [`headless-browser-dom-security-audit-scripting`](red-team/security-assessment-tooling-and-automation/headless-browser-dom-security-audit-scripting/SKILL.md) | core | playwright security script, headless dom audit, csp violation collector, postmessage auditor |
| [`idapython-automation-scripting`](red-team/security-assessment-tooling-and-automation/idapython-automation-scripting/SKILL.md) | core | idapython script, ida_hexrays, ctree_visitor_t, idalib batch, idapython automation |
| [`js-ts-and-treesitter-security-analyzers`](red-team/security-assessment-tooling-and-automation/js-ts-and-treesitter-security-analyzers/SKILL.md) | core | tree-sitter query, eslint security rule, typescript ast scanner, s-expression ast |
| [`jwt-oauth-and-oidc-audit-cli-development`](red-team/security-assessment-tooling-and-automation/jwt-oauth-and-oidc-audit-cli-development/SKILL.md) | leaf | oidc audit script, jwks validator, jwt linter, oauth config checker |
| [`libfuzzer-and-afl-harness-engineering`](red-team/security-assessment-tooling-and-automation/libfuzzer-and-afl-harness-engineering/SKILL.md) | flagship | libfuzzer harness, llvmfuzzertestoneinput, fuzzeddataprovider, afl++ harness, asan fuzzing |
| [`mitmproxy-addon-scripting`](red-team/security-assessment-tooling-and-automation/mitmproxy-addon-scripting/SKILL.md) | core | mitmproxy addon, mitmdump script, httpflow python, mitmproxy hook, proxy automation |
| [`network-protocol-grammar-fuzzer-development`](red-team/security-assessment-tooling-and-automation/network-protocol-grammar-fuzzer-development/SKILL.md) | leaf | boofuzz script, protocol grammar fuzzer, stateful fuzzing python, s_initialize |
| [`nmap-nse-audit-script-authoring`](red-team/security-assessment-tooling-and-automation/nmap-nse-audit-script-authoring/SKILL.md) | core | nmap nse script, write nse lua, shortport, stdnse output_table, nmap script authoring |
| [`nuclei-template-engineering`](red-team/security-assessment-tooling-and-automation/nuclei-template-engineering/SKILL.md) | flagship | nuclei template, write nuclei yaml, nuclei matcher, nuclei extractor, nuclei v3 schema |
| [`openapi-and-graphql-schema-auditor-scripting`](red-team/security-assessment-tooling-and-automation/openapi-and-graphql-schema-auditor-scripting/SKILL.md) | core | openapi security linter, swagger auditor script, graphql schema checker, api spec diffing |
| [`osint-collector-and-entity-graph-scripting`](red-team/security-assessment-tooling-and-automation/osint-collector-and-entity-graph-scripting/SKILL.md) | core | osint python script, crt.sh collector, entity graph osint, rdap python, certstream |
| [`python-ast-and-libcst-security-linters`](red-team/security-assessment-tooling-and-automation/python-ast-and-libcst-security-linters/SKILL.md) | core | python ast linter, libcst codemod, custom python sast, ast nodevisitor security |
| [`python-atheris-and-hypothesis-security-fuzzing`](red-team/security-assessment-tooling-and-automation/python-atheris-and-hypothesis-security-fuzzing/SKILL.md) | core | atheris fuzzing, hypothesis property testing, python fuzzer, differential parser fuzzing |
| [`sarif-and-assessment-report-automation`](red-team/security-assessment-tooling-and-automation/sarif-and-assessment-report-automation/SKILL.md) | core | sarif generator, finding deduplication script, pentest report automation, sarif 2.1.0 python |
| [`semgrep-rule-engineering`](red-team/security-assessment-tooling-and-automation/semgrep-rule-engineering/SKILL.md) | flagship | semgrep rule, write semgrep yaml, semgrep taint mode, pattern-sinks, pattern-sanitizers |
| [`tls-and-header-compliance-scanner-scripting`](red-team/security-assessment-tooling-and-automation/tls-and-header-compliance-scanner-scripting/SKILL.md) | leaf | sslyze script, tls compliance scanner, security header checker python, certificate expiry audit |

## red-team / Web and Application

| Sub-skill | Tier | Triggers |
|---|---|---|
| [`api-key-and-secret-exposure`](red-team/web-and-application/api-key-and-secret-exposure/SKILL.md) | core | api key exposure, leaked secret, hardcoded key, secret in javascript, exposed credentials |
| [`authentication-bypass`](red-team/web-and-application/authentication-bypass/SKILL.md) | core | authentication bypass, auth bypass, login bypass, forced browsing, auth logic flaw |
| [`authentication-bypass-default-and-weak-credentials`](red-team/web-and-application/authentication-bypass-default-and-weak-credentials/SKILL.md) | leaf | default credentials, weak password, credential spraying, first run password |
| [`authentication-bypass-forced-browsing`](red-team/web-and-application/authentication-bypass-forced-browsing/SKILL.md) | leaf | forced browsing, path auth bypass, filter skip, unauthorized access |
| [`authentication-bypass-header-and-proxy-trust`](red-team/web-and-application/authentication-bypass-header-and-proxy-trust/SKILL.md) | leaf | x-original-url, x-rewrite-url, header auth bypass, internal header trust |
| [`authentication-bypass-response-manipulation`](red-team/web-and-application/authentication-bypass-response-manipulation/SKILL.md) | leaf | response manipulation auth, status code bypass, client trust bypass |
| [`authorization-and-idor`](red-team/web-and-application/authorization-and-idor/SKILL.md) | flagship | idor, insecure direct object, broken access control, bole, bola, privilege escalation web, ... |
| [`authorization-and-idor-function-level`](red-team/web-and-application/authorization-and-idor-function-level/SKILL.md) | leaf | function level authorization, bfla, admin endpoint bypass, verb tampering, route confusion |
| [`authorization-and-idor-object-level`](red-team/web-and-application/authorization-and-idor-object-level/SKILL.md) | leaf | idor object, bola, object level authorization, id enumeration |
| [`authorization-and-idor-property-level`](red-team/web-and-application/authorization-and-idor-property-level/SKILL.md) | leaf | property level authorization, mass assignment, writable role field, bopla |
| [`authorization-and-idor-tenant-isolation`](red-team/web-and-application/authorization-and-idor-tenant-isolation/SKILL.md) | leaf | tenant isolation, cross tenant, multi tenant bypass, organization id |
| [`bug-bounty-and-vdp-workflow`](red-team/web-and-application/bug-bounty-and-vdp-workflow/SKILL.md) | core | bug bounty, vdp, disclosure programme, bounty workflow, scope triage, report submission |
| [`business-logic-flaws`](red-team/web-and-application/business-logic-flaws/SKILL.md) | core | business logic, logic flaw, price manipulation, coupon abuse, workflow bypass, business logic vulnerability |
| [`business-logic-flaws-payment-and-pricing`](red-team/web-and-application/business-logic-flaws-payment-and-pricing/SKILL.md) | leaf | price manipulation, payment bypass, discount abuse, refund abuse |
| [`business-logic-flaws-quota-and-rate`](red-team/web-and-application/business-logic-flaws-quota-and-rate/SKILL.md) | leaf | rate limit bypass, quota bypass, limit abuse, counter reset |
| [`business-logic-flaws-workflow-and-state`](red-team/web-and-application/business-logic-flaws-workflow-and-state/SKILL.md) | leaf | workflow bypass, state machine abuse, step skip, process bypass |
| [`clickjacking-and-ui-redressing`](red-team/web-and-application/clickjacking-and-ui-redressing/SKILL.md) | leaf | clickjacking, ui redressing, framing, x-frame-options, frame ancestor, cursorjacking |
| [`client-side-security-bypasses`](red-team/web-and-application/client-side-security-bypasses/SKILL.md) | core | client side bypass, javascript validation bypass, hidden field tampering, frontend bypass, dom bypass |
| [`client-side-storage-and-token-theft`](red-team/web-and-application/client-side-storage-and-token-theft/SKILL.md) | leaf | localstorage token, sessionstorage leak, client storage, token in javascript |
| [`cms-and-framework-exploitation`](red-team/web-and-application/cms-and-framework-exploitation/SKILL.md) | core | cms exploit, wordpress, drupal, joomla, laravel, spring boot, ... |
| [`cms-and-framework-exploitation-node-and-nextjs`](red-team/web-and-application/cms-and-framework-exploitation-node-and-nextjs/SKILL.md) | leaf | nextjs exploit, node framework, server action, image optimization ssrf |
| [`cms-and-framework-exploitation-php-and-laravel`](red-team/web-and-application/cms-and-framework-exploitation-php-and-laravel/SKILL.md) | leaf | laravel exploit, ignition rce, app_key, php framework vuln |
| [`cms-and-framework-exploitation-spring-and-java-frameworks`](red-team/web-and-application/cms-and-framework-exploitation-spring-and-java-frameworks/SKILL.md) | leaf | spring exploit, actuator, spring4shell, spel injection |
| [`cms-and-framework-exploitation-wordpress`](red-team/web-and-application/cms-and-framework-exploitation-wordpress/SKILL.md) | leaf | wordpress exploit, wp plugin vuln, wp rest api, xmlrpc, route confusion, wordpress core version, ... |
| [`code-injection-and-eval`](red-team/web-and-application/code-injection-and-eval/SKILL.md) | leaf | code injection, eval injection, dynamic evaluation, assert injection, expression injection |
| [`code-injection-and-eval-dynamic-language-eval`](red-team/web-and-application/code-injection-and-eval-dynamic-language-eval/SKILL.md) | leaf | eval injection php, python eval, ruby eval, node eval injection |
| [`code-injection-and-eval-expression-language`](red-team/web-and-application/code-injection-and-eval-expression-language/SKILL.md) | leaf | expression language injection, spel injection, ognl injection, mvel |
| [`cors-misconfiguration`](red-team/web-and-application/cors-misconfiguration/SKILL.md) | leaf | cors, cors misconfiguration, access-control-allow-origin, acaо, cross origin |
| [`cors-misconfiguration-credentialed-wildcard`](red-team/web-and-application/cors-misconfiguration-credentialed-wildcard/SKILL.md) | leaf | cors credentials, wildcard cors, subdomain cors trust |
| [`cors-misconfiguration-reflected-origin`](red-team/web-and-application/cors-misconfiguration-reflected-origin/SKILL.md) | leaf | cors reflected origin, null origin cors, acao bypass |
| [`crlf-and-header-injection`](red-team/web-and-application/crlf-and-header-injection/SKILL.md) | leaf | crlf injection, header injection, response splitting, log injection, http response splitting |
| [`cross-site-scripting`](red-team/web-and-application/cross-site-scripting/SKILL.md) | flagship | xss, cross-site scripting, cross site scripting, script injection, html injection, dom xss |
| [`cross-site-scripting-blind-and-oob-xss`](red-team/web-and-application/cross-site-scripting-blind-and-oob-xss/SKILL.md) | leaf | blind xss, oob xss, xss in admin panel, headless xss |
| [`cross-site-scripting-csp-bypass`](red-team/web-and-application/cross-site-scripting-csp-bypass/SKILL.md) | leaf | csp bypass xss, xss with csp, nonce bypass, jsonp xss, script gadget xss |
| [`cross-site-scripting-dom`](red-team/web-and-application/cross-site-scripting-dom/SKILL.md) | leaf | dom xss, dom based xss, client side xss, source sink |
| [`cross-site-scripting-filter-and-context-bypass`](red-team/web-and-application/cross-site-scripting-filter-and-context-bypass/SKILL.md) | leaf | xss filter bypass, waf xss, xss payload bypass, context escape |
| [`cross-site-scripting-mutation`](red-team/web-and-application/cross-site-scripting-mutation/SKILL.md) | leaf | mutation xss, mxss, parser differential, dompurify bypass, sanitizer bypass |
| [`cross-site-scripting-reflected`](red-team/web-and-application/cross-site-scripting-reflected/SKILL.md) | leaf | reflected xss, non-persistent xss, reflected cross site |
| [`cross-site-scripting-stored`](red-team/web-and-application/cross-site-scripting-stored/SKILL.md) | leaf | stored xss, persistent xss, second order xss, stored cross site |
| [`csp-and-security-header-bypass`](red-team/web-and-application/csp-and-security-header-bypass/SKILL.md) | leaf | csp bypass, content security policy, security header bypass, nonce reuse, script gadget |
| [`csrf`](red-team/web-and-application/csrf/SKILL.md) | core | csrf, cross-site request forgery, anti-csrf, samesite, xsf, request forgery |
| [`csv-formula-injection`](red-team/web-and-application/csv-formula-injection/SKILL.md) | leaf | csv injection, formula injection, spreadsheet injection, excel injection, dyngnosis |
| [`cve-poc-research-and-triage`](red-team/web-and-application/cve-poc-research-and-triage/SKILL.md) | leaf | cve poc, proof of concept, cve research, exploit db, poc triage, exploit code |
| [`dns-rebinding-attacks`](red-team/web-and-application/dns-rebinding-attacks/SKILL.md) | leaf | dns rebinding, rebind attack, dns rebind ssrf, ttl rebinding |
| [`dom-based-vulnerabilities`](red-team/web-and-application/dom-based-vulnerabilities/SKILL.md) | leaf | dom xss, dom based, postmessage, sink source, client side injection, dom clobbering |
| [`email-header-injection`](red-team/web-and-application/email-header-injection/SKILL.md) | leaf | email header injection, smtp injection, mail injection, header injection email |
| [`enterprise-appliance-and-n-day-exploitation`](red-team/web-and-application/enterprise-appliance-and-n-day-exploitation/SKILL.md) | core | n-day exploitation, appliance exploit, edge device exploit, patch diff, poc adaptation, vpn exploit |
| [`enterprise-appliance-and-n-day-exploitation-edge-network-devices`](red-team/web-and-application/enterprise-appliance-and-n-day-exploitation-edge-network-devices/SKILL.md) | leaf | firewall exploit, load balancer exploit, edge device n-day, router exploit |
| [`enterprise-appliance-n-day-mail-collaboration`](red-team/web-and-application/enterprise-appliance-n-day-mail-collaboration/SKILL.md) | leaf | exchange exploit, mail gateway exploit, collaboration platform n-day |
| [`enterprise-appliance-n-day-vpn-remote-access`](red-team/web-and-application/enterprise-appliance-n-day-vpn-remote-access/SKILL.md) | leaf | vpn exploit, remote access appliance, ssl vpn n-day, pre-auth rce appliance |
| [`file-upload-and-webshell`](red-team/web-and-application/file-upload-and-webshell/SKILL.md) | core | file upload, upload bypass, webshell, web shell, unrestricted upload, multipart bypass |
| [`file-upload-and-webshell-config-and-htaccess-abuse`](red-team/web-and-application/file-upload-and-webshell-config-and-htaccess-abuse/SKILL.md) | leaf | htaccess upload, web.config upload, user.ini upload, upload config |
| [`file-upload-and-webshell-extension-and-mime-bypass`](red-team/web-and-application/file-upload-and-webshell-extension-and-mime-bypass/SKILL.md) | leaf | upload extension bypass, mime bypass, content type bypass, double extension |
| [`file-upload-and-webshell-filename-and-path-abuse`](red-team/web-and-application/file-upload-and-webshell-filename-and-path-abuse/SKILL.md) | leaf | filename traversal upload, upload path traversal, upload overwrite, upload race |
| [`file-upload-and-webshell-polyglot-and-archive`](red-team/web-and-application/file-upload-and-webshell-polyglot-and-archive/SKILL.md) | leaf | polyglot upload, image polyglot, zip slip, svg upload, archive upload |
| [`graphql-security`](red-team/web-and-application/graphql-security/SKILL.md) | core | graphql, graphql introspection, resolver authz, query batching, graphql injection, graphql dos |
| [`graphql-security-batching-and-dos`](red-team/web-and-application/graphql-security-batching-and-dos/SKILL.md) | leaf | graphql batching, graphql dos, alias brute force, query depth |
| [`graphql-security-introspection-and-schema`](red-team/web-and-application/graphql-security-introspection-and-schema/SKILL.md) | leaf | graphql introspection, graphql schema, __schema, graphql discovery |
| [`graphql-security-resolver-authorization`](red-team/web-and-application/graphql-security-resolver-authorization/SKILL.md) | leaf | graphql authorization, resolver authz, graphql idor, field authorization |
| [`http-host-header-attacks`](red-team/web-and-application/http-host-header-attacks/SKILL.md) | leaf | host header injection, host header, forwarded header, x-forwarded-host, host poisoning, virtual host bypass |
| [`http-method-and-verb-attacks`](red-team/web-and-application/http-method-and-verb-attacks/SKILL.md) | leaf | verb tampering, method override, http method bypass, trace method, options disclosure |
| [`http-parameter-pollution-and-mass-assignment`](red-team/web-and-application/http-parameter-pollution-and-mass-assignment/SKILL.md) | leaf | parameter pollution, hpp, mass assignment, object injection, autobinding, overposting |
| [`http-request-smuggling`](red-team/web-and-application/http-request-smuggling/SKILL.md) | core | request smuggling, smuggling, desync, cl.te, te.cl, http desync, ... |
| [`http-request-smuggling-cl-te-and-te-cl`](red-team/web-and-application/http-request-smuggling-cl-te-and-te-cl/SKILL.md) | leaf | cl.te, te.cl, request smuggling basics, desync detection |
| [`http-request-smuggling-client-side-desync`](red-team/web-and-application/http-request-smuggling-client-side-desync/SKILL.md) | leaf | client side desync, csd, browser desync |
| [`http-request-smuggling-http2-desync`](red-team/web-and-application/http-request-smuggling-http2-desync/SKILL.md) | leaf | h2 desync, h2.cl, request tunnelling, http2 smuggling |
| [`http-request-smuggling-te-te-and-obfuscation`](red-team/web-and-application/http-request-smuggling-te-te-and-obfuscation/SKILL.md) | leaf | te.te, obfuscated transfer encoding, smuggling obfuscation |
| [`http2-specific-attacks`](red-team/web-and-application/http2-specific-attacks/SKILL.md) | leaf | http2 attack, h2 attack, h2c, rapid reset, pseudo header injection |
| [`injection-detection-methodology`](red-team/web-and-application/injection-detection-methodology/SKILL.md) | core | injection detection, find injection, parameter fuzzing, input validation testing, injection testing methodology |
| [`injection-detection-methodology-confirmation-discipline`](red-team/web-and-application/injection-detection-methodology-confirmation-discipline/SKILL.md) | leaf | injection confirmation, false positive injection, prove injection |
| [`injection-detection-methodology-parameter-mining`](red-team/web-and-application/injection-detection-methodology-parameter-mining/SKILL.md) | leaf | parameter mining, hidden parameter, param discovery, undocumented parameter |
| [`insecure-deserialization`](red-team/web-and-application/insecure-deserialization/SKILL.md) | core | deserialization, deserialize, gadget chain, ysoserial, phpggc, pickle, ... |
| [`insecure-deserialization-dotnet-gadgets`](red-team/web-and-application/insecure-deserialization-dotnet-gadgets/SKILL.md) | leaf | net deserialization, viewstate, binaryformatter, ysoserial.net, machinekey |
| [`insecure-deserialization-java-gadgets`](red-team/web-and-application/insecure-deserialization-java-gadgets/SKILL.md) | leaf | java deserialization, ysoserial, objectinputstream, jrmp, java gadget |
| [`insecure-deserialization-php-gadgets`](red-team/web-and-application/insecure-deserialization-php-gadgets/SKILL.md) | leaf | php deserialization, php object injection, pop chain, phpggc, phar metadata |
| [`insecure-deserialization-python-and-ruby-gadgets`](red-team/web-and-application/insecure-deserialization-python-and-ruby-gadgets/SKILL.md) | leaf | pickle deserialization, python deserialization, ruby marshal, yaml load |
| [`jndi-injection`](red-team/web-and-application/jndi-injection/SKILL.md) | leaf | jndi injection, log4shell, log4j, ldap injection java, rmi class loading, jndi lookup |
| [`jndi-injection-logging-lookups`](red-team/web-and-application/jndi-injection-logging-lookups/SKILL.md) | leaf | log4shell, log4j jndi, logging lookup injection, message lookup |
| [`jndi-injection-remote-class-loading`](red-team/web-and-application/jndi-injection-remote-class-loading/SKILL.md) | leaf | jndi rmi, ldap codebase, trustURLCodebase bypass, jndi factory |
| [`jwt-attacks`](red-team/web-and-application/jwt-attacks/SKILL.md) | core | jwt, json web token, jwt none, alg confusion, kid injection, jwt cracking, ... |
| [`jwt-attacks-algorithm-confusion`](red-team/web-and-application/jwt-attacks-algorithm-confusion/SKILL.md) | leaf | jwt alg none, jwt algorithm confusion, rs256 hs256, jwt bypass |
| [`jwt-attacks-claim-tampering`](red-team/web-and-application/jwt-attacks-claim-tampering/SKILL.md) | leaf | jwt claim tampering, jwt expiry bypass, jwt replay, audience confusion |
| [`jwt-attacks-header-injection`](red-team/web-and-application/jwt-attacks-header-injection/SKILL.md) | leaf | jwt kid injection, jku injection, x5u, jwt header injection |
| [`jwt-attacks-secret-cracking`](red-team/web-and-application/jwt-attacks-secret-cracking/SKILL.md) | leaf | jwt cracking, jwt secret, hashcat jwt, weak jwt key |
| [`ldap-and-xpath-injection`](red-team/web-and-application/ldap-and-xpath-injection/SKILL.md) | leaf | ldap injection, xpath injection, directory injection, filter injection, ldap bypass |
| [`ldap-and-xpath-injection-ldap`](red-team/web-and-application/ldap-and-xpath-injection-ldap/SKILL.md) | leaf | ldap injection, ldap filter bypass, directory enumeration injection |
| [`ldap-and-xpath-injection-xpath`](red-team/web-and-application/ldap-and-xpath-injection-xpath/SKILL.md) | leaf | xpath injection, xpath bypass, xml query injection |
| [`mfa-and-otp-bypass`](red-team/web-and-application/mfa-and-otp-bypass/SKILL.md) | leaf | mfa bypass, otp bypass, 2fa bypass, two factor bypass, mfa, otp brute force |
| [`mobile-and-hybrid-web-api-abuse`](red-team/web-and-application/mobile-and-hybrid-web-api-abuse/SKILL.md) | leaf | mobile api testing, hybrid app api, backend api mobile, app api abuse |
| [`nosql-injection`](red-team/web-and-application/nosql-injection/SKILL.md) | core | nosql injection, mongodb injection, operator injection, $ne bypass, nosql |
| [`oast-and-blind-vulnerability-testing`](red-team/web-and-application/oast-and-blind-vulnerability-testing/SKILL.md) | core | oast, out-of-band, blind vulnerability, dns callback, burp collaborator, interactsh, ... |
| [`oast-and-blind-vulnerability-testing-dns-and-http-callbacks`](red-team/web-and-application/oast-and-blind-vulnerability-testing-dns-and-http-callbacks/SKILL.md) | leaf | dns callback, http callback, interactsh, collaborator, oob confirmation |
| [`oast-and-blind-vulnerability-testing-timing-oracles`](red-team/web-and-application/oast-and-blind-vulnerability-testing-timing-oracles/SKILL.md) | leaf | timing oracle, time based blind, latency confirmation |
| [`oauth-oidc-misconfiguration`](red-team/web-and-application/oauth-oidc-misconfiguration/SKILL.md) | core | oauth, oidc, openid connect, redirect_uri, authorization code, implicit flow, ... |
| [`oauth-oidc-misconfiguration-flow-and-state-flaws`](red-team/web-and-application/oauth-oidc-misconfiguration-flow-and-state-flaws/SKILL.md) | leaf | oauth state, pkce downgrade, implicit flow, oauth mixup |
| [`oauth-oidc-misconfiguration-redirect-uri-abuse`](red-team/web-and-application/oauth-oidc-misconfiguration-redirect-uri-abuse/SKILL.md) | leaf | oauth redirect_uri, redirect uri bypass, authorization code leak, oauth redirect |
| [`oauth-oidc-misconfiguration-token-and-scope-abuse`](red-team/web-and-application/oauth-oidc-misconfiguration-token-and-scope-abuse/SKILL.md) | leaf | oauth scope escalation, token substitution, refresh token, audience validation |
| [`open-redirect`](red-team/web-and-application/open-redirect/SKILL.md) | leaf | open redirect, url redirect, redirect bypass, returnurl, next parameter, unvalidated redirect |
| [`open-redirect-allowlist-bypass`](red-team/web-and-application/open-redirect-allowlist-bypass/SKILL.md) | leaf | open redirect bypass, redirect allowlist bypass, url parsing bypass |
| [`open-redirect-chain-to-token-theft`](red-team/web-and-application/open-redirect-chain-to-token-theft/SKILL.md) | leaf | open redirect oauth, redirect token theft, redirect ssrf chain |
| [`openapi-and-swagger-exposure`](red-team/web-and-application/openapi-and-swagger-exposure/SKILL.md) | leaf | swagger exposure, openapi discovery, api documentation leak, swagger ui |
| [`os-command-injection`](red-team/web-and-application/os-command-injection/SKILL.md) | core | command injection, os command, cmdi, shell injection, rce via command, argument injection |
| [`os-command-injection-argument-injection`](red-team/web-and-application/os-command-injection-argument-injection/SKILL.md) | leaf | argument injection, cli option injection, parameter injection, git argument injection |
| [`os-command-injection-blind-and-time-based`](red-team/web-and-application/os-command-injection-blind-and-time-based/SKILL.md) | leaf | blind command injection, time based rce, cmdi blind, ping delay |
| [`os-command-injection-escalation-to-shell`](red-team/web-and-application/os-command-injection-escalation-to-shell/SKILL.md) | leaf | command injection reverse shell, cmdi to shell, interactive shell upgrade |
| [`os-command-injection-shell-metacharacter-bypass`](red-team/web-and-application/os-command-injection-shell-metacharacter-bypass/SKILL.md) | leaf | command injection bypass, metacharacter bypass, ifs bypass, no space rce |
| [`password-reset-and-account-recovery`](red-team/web-and-application/password-reset-and-account-recovery/SKILL.md) | leaf | password reset, account recovery, reset token, forgot password, recovery flow |
| [`path-traversal-and-lfi`](red-team/web-and-application/path-traversal-and-lfi/SKILL.md) | core | path traversal, lfi, local file inclusion, directory traversal, file read, dotdot slash, ... |
| [`path-traversal-and-lfi-encoding-bypass`](red-team/web-and-application/path-traversal-and-lfi-encoding-bypass/SKILL.md) | leaf | traversal bypass, encoded traversal, dotdot bypass, null byte, unicode traversal |
| [`path-traversal-and-lfi-lfi-to-rce`](red-team/web-and-application/path-traversal-and-lfi-lfi-to-rce/SKILL.md) | leaf | lfi to rce, log poisoning, lfi rce, inclusion to code execution |
| [`path-traversal-and-lfi-log-and-cache-poisoning`](red-team/web-and-application/path-traversal-and-lfi-log-and-cache-poisoning/SKILL.md) | leaf | log poisoning, log injection lfi, access log payload, mail log include |
| [`path-traversal-and-lfi-php-wrappers`](red-team/web-and-application/path-traversal-and-lfi-php-wrappers/SKILL.md) | leaf | php wrapper, php filter, php data wrapper, phar deserialization, php expect |
| [`pdf-and-headless-renderer-injection`](red-team/web-and-application/pdf-and-headless-renderer-injection/SKILL.md) | core | html to pdf ssrf, wkhtmltopdf lfi, weasyprint attachment, headless pdf injection |
| [`prototype-pollution`](red-team/web-and-application/prototype-pollution/SKILL.md) | core | prototype pollution, proto pollution, object pollution, __proto__, constructor prototype |
| [`prototype-pollution-client-side-gadgets`](red-team/web-and-application/prototype-pollution-client-side-gadgets/SKILL.md) | leaf | client side prototype pollution, dom pollution gadget, pp gadget xss |
| [`prototype-pollution-rce-chains`](red-team/web-and-application/prototype-pollution-rce-chains/SKILL.md) | leaf | prototype pollution rce, pp to rce, node rce pollution |
| [`prototype-pollution-server-side`](red-team/web-and-application/prototype-pollution-server-side/SKILL.md) | leaf | server side prototype pollution, node prototype pollution, merge pollution |
| [`race-conditions-and-concurrency`](red-team/web-and-application/race-conditions-and-concurrency/SKILL.md) | core | race condition, toctou, concurrency, parallel requests, single packet attack, double spend |
| [`race-conditions-and-concurrency-limit-bypass`](red-team/web-and-application/race-conditions-and-concurrency-limit-bypass/SKILL.md) | leaf | race limit bypass, double spend, token reuse race |
| [`race-conditions-and-concurrency-single-packet-attack`](red-team/web-and-application/race-conditions-and-concurrency-single-packet-attack/SKILL.md) | leaf | single packet attack, last byte sync, race exploit technique |
| [`rest-and-grpc-api-security`](red-team/web-and-application/rest-and-grpc-api-security/SKILL.md) | core | api security, rest api, grpc, api testing, bola, excessive data exposure, ... |
| [`saml-and-webauthn-passkey-implementation-flaws`](red-team/web-and-application/saml-and-webauthn-passkey-implementation-flaws/SKILL.md) | leaf | webauthn vulnerability, passkey implementation flaw, fido2 origin check, rpidhash verification |
| [`saml-assertion-attacks`](red-team/web-and-application/saml-assertion-attacks/SKILL.md) | core | saml, saml attack, signature wrapping, xsw, assertion replay, sso bypass, ... |
| [`saml-assertion-attacks-assertion-forgery`](red-team/web-and-application/saml-assertion-attacks-assertion-forgery/SKILL.md) | leaf | saml forgery, assertion replay, unsigned saml, saml bypass |
| [`saml-assertion-attacks-signature-wrapping`](red-team/web-and-application/saml-assertion-attacks-signature-wrapping/SKILL.md) | leaf | saml xsw, signature wrapping, xsw attack, xml signature wrapping |
| [`server-side-includes-injection`](red-team/web-and-application/server-side-includes-injection/SKILL.md) | leaf | ssi injection, server side includes, shtml injection, ssi directives |
| [`session-and-token-lifecycle`](red-team/web-and-application/session-and-token-lifecycle/SKILL.md) | leaf | session management, session fixation, session hijack, cookie attributes, session expiry, token lifecycle |
| [`session-and-token-lifecycle-cookie-attribute-flaws`](red-team/web-and-application/session-and-token-lifecycle-cookie-attribute-flaws/SKILL.md) | leaf | cookie flags, cookie scope, samesite bypass, cookie shadowing |
| [`session-and-token-lifecycle-fixation-and-prediction`](red-team/web-and-application/session-and-token-lifecycle-fixation-and-prediction/SKILL.md) | leaf | session fixation, predictable session, session id prediction |
| [`session-and-token-lifecycle-revocation-gaps`](red-team/web-and-application/session-and-token-lifecycle-revocation-gaps/SKILL.md) | leaf | session revocation, logout bypass, session not invalidated, token reuse |
| [`sql-injection`](red-team/web-and-application/sql-injection/SKILL.md) | flagship | sql injection, sqli, sql inject, union select, blind sql, injection in sql, ... |
| [`sql-injection-mssql-variants`](red-team/web-and-application/sql-injection-mssql-variants/SKILL.md) | leaf | mssql injection, sql server injection, waitfor delay, xp_cmdshell, openrowset |
| [`sql-injection-mysql-variants`](red-team/web-and-application/sql-injection-mysql-variants/SKILL.md) | leaf | mysql injection, mariadb injection, sleep benchmark, into outfile, extractvalue |
| [`sql-injection-oracle-variants`](red-team/web-and-application/sql-injection-oracle-variants/SKILL.md) | leaf | oracle injection, dbms_pipe, utl_http, oracle sqli, dual table |
| [`sql-injection-orm-and-query-builder`](red-team/web-and-application/sql-injection-orm-and-query-builder/SKILL.md) | leaf | orm injection, hql injection, active record injection, django raw, sequelize literal, prisma raw, ... |
| [`sql-injection-postgres-variants`](red-team/web-and-application/sql-injection-postgres-variants/SKILL.md) | leaf | postgres injection, postgresql sqli, pg_sleep, copy to program, dollar quoting |
| [`sql-injection-second-order`](red-team/web-and-application/sql-injection-second-order/SKILL.md) | leaf | second order sql, stored sql injection, stored injection, persistent sqli |
| [`sql-injection-sqlite-variants`](red-team/web-and-application/sql-injection-sqlite-variants/SKILL.md) | leaf | sqlite injection, sqlite sqli, sqlite_master, attach database, sqlite error |
| [`sql-injection-waf-tamper-chains`](red-team/web-and-application/sql-injection-waf-tamper-chains/SKILL.md) | leaf | sqlmap tamper, tamper script, sqli waf bypass, tamper chain |
| [`ssrf`](red-team/web-and-application/ssrf/SKILL.md) | flagship | ssrf, server-side request forgery, server side request, internal request, url fetch, webhook abuse |
| [`ssrf-allowlist-bypass`](red-team/web-and-application/ssrf-allowlist-bypass/SKILL.md) | leaf | ssrf bypass, ssrf allowlist bypass, dns rebinding, url parser bypass |
| [`ssrf-blind-ssrf`](red-team/web-and-application/ssrf-blind-ssrf/SKILL.md) | leaf | blind ssrf, ssrf oob, ssrf exfiltration, ssrf timing |
| [`ssrf-cloud-metadata`](red-team/web-and-application/ssrf-cloud-metadata/SKILL.md) | leaf | ssrf metadata, 169.254.169.254, imds, instance metadata ssrf, cloud metadata |
| [`ssrf-internal-service-pivot`](red-team/web-and-application/ssrf-internal-service-pivot/SKILL.md) | leaf | ssrf internal, internal service ssrf, pivot via ssrf, kubernetes api ssrf |
| [`ssrf-protocol-smuggling`](red-team/web-and-application/ssrf-protocol-smuggling/SKILL.md) | leaf | gopher ssrf, dict ssrf, file ssrf, protocol smuggling ssrf |
| [`ssti`](red-team/web-and-application/ssti/SKILL.md) | core | ssti, template injection, server-side template, jinja2, twig, freemarker, ... |
| [`ssti-java-template-engines`](red-team/web-and-application/ssti-java-template-engines/SKILL.md) | leaf | freemarker ssti, velocity ssti, pebble ssti, thymeleaf ssti, java template |
| [`ssti-jinja2-and-twig`](red-team/web-and-application/ssti-jinja2-and-twig/SKILL.md) | leaf | jinja2 ssti, twig ssti, python template injection, php template injection |
| [`ssti-node-and-client-engines`](red-team/web-and-application/ssti-node-and-client-engines/SKILL.md) | leaf | ejs ssti, handlebars ssti, pug ssti, client side template injection, angular injection |
| [`ssti-sandbox-escape`](red-team/web-and-application/ssti-sandbox-escape/SKILL.md) | leaf | ssti sandbox escape, template sandbox, ssti rce, template escape |
| [`subdomain-takeover`](red-team/web-and-application/subdomain-takeover/SKILL.md) | leaf | subdomain takeover, dangling cname, dangling dns, unclaimed bucket, ns takeover |
| [`subdomain-takeover-cname-fingerprints`](red-team/web-and-application/subdomain-takeover-cname-fingerprints/SKILL.md) | leaf | cname takeover, cname fingerprint, dangling cname exploit |
| [`subdomain-takeover-ns-and-service-takeover`](red-team/web-and-application/subdomain-takeover-ns-and-service-takeover/SKILL.md) | leaf | ns takeover, nameserver takeover, dangling ns, delegation takeover |
| [`type-juggling-and-loose-comparison`](red-team/web-and-application/type-juggling-and-loose-comparison/SKILL.md) | leaf | type juggling, loose comparison, magic hash, php juggling, weak comparison, 0e hash |
| [`type-juggling-and-loose-comparison-php-juggling`](red-team/web-and-application/type-juggling-and-loose-comparison-php-juggling/SKILL.md) | leaf | php type juggling, php loose comparison, magic hash php, php == bypass |
| [`type-juggling-javascript-other-languages`](red-team/web-and-application/type-juggling-javascript-other-languages/SKILL.md) | leaf | javascript type coercion, python comparison bypass, ruby type juggling |
| [`unicode-normalization-and-charset-confusion`](red-team/web-and-application/unicode-normalization-and-charset-confusion/SKILL.md) | leaf | unicode normalization bypass, nfkc collision, case mapping bypass, charset confusion, jackson hex cast |
| [`waf-bypass-and-payload-obfuscation`](red-team/web-and-application/waf-bypass-and-payload-obfuscation/SKILL.md) | core | waf bypass, bypass waf, filter bypass, payload obfuscation, firewall evasion, blocked payload |
| [`waf-bypass-and-payload-obfuscation-comment-and-whitespace`](red-team/web-and-application/waf-bypass-and-payload-obfuscation-comment-and-whitespace/SKILL.md) | leaf | comment bypass, whitespace bypass, keyword splitting, sql comment bypass |
| [`waf-bypass-and-payload-obfuscation-encoding-layers`](red-team/web-and-application/waf-bypass-and-payload-obfuscation-encoding-layers/SKILL.md) | leaf | encoding bypass, double encoding, unicode bypass, hex obfuscation |
| [`waf-bypass-and-payload-obfuscation-parser-differentials`](red-team/web-and-application/waf-bypass-and-payload-obfuscation-parser-differentials/SKILL.md) | leaf | parser differential waf, content type bypass, charset bypass, waf differential |
| [`waf-bypass-and-payload-obfuscation-rule-specific-evasion`](red-team/web-and-application/waf-bypass-and-payload-obfuscation-rule-specific-evasion/SKILL.md) | leaf | waf fingerprint, waf vendor detection, evade waf rule, waf identification |
| [`web-app-fuzzing-and-automation`](red-team/web-and-application/web-app-fuzzing-and-automation/SKILL.md) | leaf | web fuzzing, automate web testing, nuclei templates, request templating, burp automation |
| [`web-cache-poisoning-and-deception`](red-team/web-and-application/web-cache-poisoning-and-deception/SKILL.md) | core | cache poisoning, web cache, cache deception, cache key, unkeyed input, cdn poisoning |
| [`web-cache-poisoning-and-deception-cdn-specific-behaviour`](red-team/web-and-application/web-cache-poisoning-and-deception-cdn-specific-behaviour/SKILL.md) | leaf | cdn cache poisoning, cloudflare cache, akamai cache, fastly cache |
| [`web-cache-poisoning-and-deception-deception-and-path`](red-team/web-and-application/web-cache-poisoning-and-deception-deception-and-path/SKILL.md) | leaf | cache deception, path confusion cache, web cache deception |
| [`web-cache-poisoning-and-deception-unkeyed-input`](red-team/web-and-application/web-cache-poisoning-and-deception-unkeyed-input/SKILL.md) | leaf | cache poisoning unkeyed, cache deception unkeyed, cache poisoning header |
| [`web-fingerprinting-and-tech-detection`](red-team/web-and-application/web-fingerprinting-and-tech-detection/SKILL.md) | leaf | fingerprint, tech detection, whatweb, wappalyzer, version detection, server header |
| [`web-pentest-engagement-workflow`](red-team/web-and-application/web-pentest-engagement-workflow/SKILL.md) | core | web pentest, web assessment, engagement workflow, testing plan, pentest methodology |
| [`web-recon-and-content-discovery`](red-team/web-and-application/web-recon-and-content-discovery/SKILL.md) | core | web recon, content discovery, directory brute force, ffuf, gobuster, endpoint discovery, ... |
| [`web-recon-and-content-discovery-archive-and-osint-recon`](red-team/web-and-application/web-recon-and-content-discovery-archive-and-osint-recon/SKILL.md) | leaf | wayback recon, archive recon, gau, common crawl, historical endpoint |
| [`web-recon-and-content-discovery-directory-and-file`](red-team/web-and-application/web-recon-and-content-discovery-directory-and-file/SKILL.md) | leaf | directory brute force, file discovery, ffuf, gobuster, dirsearch |
| [`web-recon-and-content-discovery-javascript-analysis`](red-team/web-and-application/web-recon-and-content-discovery-javascript-analysis/SKILL.md) | leaf | javascript recon, js endpoint extraction, source map, hardcoded secret js |
| [`webshell-management-and-interaction`](red-team/web-and-application/webshell-management-and-interaction/SKILL.md) | leaf | webshell usage, webshell interaction, manage webshell, shell stability web |
| [`websocket-security`](red-team/web-and-application/websocket-security/SKILL.md) | leaf | websocket, ws security, websocket hijacking, ws origin check, socket injection |
| [`xml-attacks-xxe-and-xslt`](red-team/web-and-application/xml-attacks-xxe-and-xslt/SKILL.md) | leaf | xslt injection, xpath injection, xml attack, stylesheet injection, xslt extension |
| [`xml-attacks-xxe-and-xslt-xpath-and-schema`](red-team/web-and-application/xml-attacks-xxe-and-xslt-xpath-and-schema/SKILL.md) | leaf | xpath injection, xml schema attack, xinclude, billion laughs |
| [`xml-attacks-xxe-and-xslt-xslt-injection`](red-team/web-and-application/xml-attacks-xxe-and-xslt-xslt-injection/SKILL.md) | leaf | xslt injection, xsl extension, xslt rce, stylesheet injection |
| [`xxe`](red-team/web-and-application/xxe/SKILL.md) | core | xxe, xml external entity, external entity, xml injection, doctype, billion laughs |
| [`xxe-file-disclosure`](red-team/web-and-application/xxe-file-disclosure/SKILL.md) | leaf | xxe file read, xxe local file, xxe disclosure |
| [`xxe-oob-exfiltration`](red-team/web-and-application/xxe-oob-exfiltration/SKILL.md) | leaf | blind xxe, xxe oob, external dtd, xxe exfiltration |
| [`xxe-ooxml-and-svg`](red-team/web-and-application/xxe-ooxml-and-svg/SKILL.md) | leaf | docx xxe, xlsx xxe, svg xxe, ooxml xxe, document xxe |
| [`xxe-parser-differential-bypass`](red-team/web-and-application/xxe-parser-differential-bypass/SKILL.md) | leaf | xinclude, xxe bypass, entity blocking bypass, parser differential xxe |
| [`zip-slip-and-archive-extraction-attacks`](red-team/web-and-application/zip-slip-and-archive-extraction-attacks/SKILL.md) | leaf | zip slip, tar symlink escape, archive traversal, decompression bomb, extractall vulnerability |
