# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`rest-and-grpc-api-security`](SKILL.md) | Family: **Web and Application**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: Unauthenticated Private Messages DIsclosure via wordpress Rest API

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Vulnearble Plugin: Senei LMS Hi there, Hope you are doing well, So, i noticed that their is an option to contact teacher on Sensei LMS which is meant to private. By default, other user can't see the question I asked to the teacher.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 2: Kafka Connect RCE via connector SASL JAAS JndiLoginModule configuration

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Summary: When configuring the connector via the Aiven API or the Kafka Connect REST API, the attacker can set the 'database.history.producer.sasl.jaas.config' connector property for the 'io.debezium.connector.mysql.MySqlConnector' connector.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 3: Improper access control for users with expired password, giving the user full access through API and Git

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Summary Users with an "expired password" can still access the full API with tokens. This includes the REST API, GraphQL API and Git HTTP access. The same issue was mitigated in 13.12.2 as "Insufficient Expired Password Validation".
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 4: Wordpress Users Disclosure (/wp-json/wp/v2/users/)

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Information Using REST API, we can see all the WordPress users/author with some of their information. Step TO Reproduce You can get user info by entering below url in your browser: https://www.lahitapiolarahoitus.fi/wp-json/wp/v2/users/ Result javascript [ { "id": 1, "name":...
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 5: REST API Endpoint leads to Unauthorized user disclosed private [ issue ] details

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Summary Jira allows an administrator to restrict access to projects to specific users only. Or adjusting all project properties to be available only to the system administrator, which means that all users in the jira account cannot access issues, project, dashboard and any...
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 6: User Information Disclosure via the REST API - /?_method=GET

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Basic report information **Summary:** browser access to www.lahitapiolarahoitus.fi/wp-json is restricted for general public but it is still be accessible through which User information is leaked.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 7: Private System Note Disclosure using GraphQL

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Summary When you use the REST API or UI to view an issue's discussion/notes, private system note is hidden to member's only. Such as moving an issue to a private project, making issue as duplicate of a confidential issue, someone mentioned this issue in a confidential issue.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 8: anti_ransomware_service.exe REST API does not require authentication

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** anti_ransomware_service.exe exposes a REST API that can be used by everyone, even unprivileged users. This API is used to communicate from the Acronis True Image 2020 GUI to the anti_ransomware_service.exe.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.
