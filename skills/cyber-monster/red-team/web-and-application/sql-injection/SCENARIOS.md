# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`sql-injection`](SKILL.md) | Family: **Web and Application**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: ASPNET-CORE: sql

- **Provenance:** Source: `securecode-web` | CWE: `CWE-89` | CVE: `CVE-2023-34362`
- **Context / Surface:** I'm building the transfer list for our support console. The product is a managed file-transfer service, ASP.NET Core 10 + EF Core with SQLite for now, and the app is used by our...
- **Root Cause / Analysis:** An attacker who can reach the support console can use SQL injection to read unrelated customer data from the same database.
- **Actionable Takeaway:** Replace the vulnerable aspnet-core pattern with parameterized/validated state transitions.

## Case 2: Report Template: SQL Injection

- **Provenance:** Source: `bug-bounty-pentest-en`
- **Root Cause / Analysis:** An attacker can extract all database data, including user personal information, hashed passwords and sensitive business data.
- **Actionable Takeaway:** 1. Use prepared statements (parameterized queries) for all database interactions 2. Implement strict input validation (whitelist) 3. Apply least privilege principle for database accounts 4.

## Case 3: SQL injection in https://labs.data.gov/dashboard/datagov/csv_to_json via User-agent

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** I've identified an SQL injection vulnerability in the website **labs.data.gov** that affects the endpoint '/dashboard/datagov/csv_to_json' and can be exploited via the **User-Agent** HTTP header.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 4: SQL injection on contactws.contact-sys.com in TScenObject action ScenObjects leads to remote code executi

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Summary The API interface on https://contactws.contact-sys.com:3456/ accepts a '' body to interact with the server's AppServ object.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 5: [windows10.hi-tech.mail.ru] Blind SQL Injection

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Доброе утро! Сегодня удалось найти у вас слепую скулю, правда она снова вне скопа походу(( URL: https://windows10.hi-tech.mail.ru/api/tweets?city_id=(select(0)from(select(sleep(25)))v) Request: GET /api/tweets?city_id=(select(0)from(select(sleep(25)))v) HTTP/1.1 Host:...
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 6: SQL Injection on cookie parameter

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Summary: Hello team. It seams one of the parameters in the cookies is vulnerable to SQL injection. Below requests has the lang parameter in cookies. If you inject one quote mark like '. You get SQL error with the syntax. By injecting a second you have the error removed.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 7: SQL Injection in agent-manager

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** 1.https://mc-beta-cloud.acronis.com/api/agent_manager/v2/unit_configurations?name=update-schedule&no_data=false&tenant_id=1590228&unit=atp-agent%27and%2F%2A%2A%2Fextractvalue%281%2Cconcat%28char%28126%29%2C%28select+database%28%29%29%29%29and%27...
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 8: SQL Injection in www.hyperpure.com

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Vulnerable Request : PUT /consumer/onboarding/saleslead/6b6a8a5a-4a74-46db-b2fe-32a46f927ecc HTTP/1.1 Host: api.hyperpure.com User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64;
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.
