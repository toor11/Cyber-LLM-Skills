# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`os-command-injection`](SKILL.md) | Family: **Web and Application**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: PHP: command injection

- **Provenance:** Source: `securecode-web` | CWE: `CWE-78`
- **Context / Surface:** Our PHP service needs 'GET /images/metadata?name=...' to return the byte count for stored images. We have 'stat' in the container.
- **Root Cause / Analysis:** An unauthenticated filename is parsed by a shell, allowing commands under the PHP worker account.
- **Actionable Takeaway:** Replace the vulnerable php pattern with parameterized/validated state transitions.

## Case 2: JAVASCRIPT: command injection

- **Provenance:** Source: `securecode-web` | CWE: `CWE-78`
- **Context / Surface:** I'm building a small internal Node.js service (Node 22, no framework, just 'node:http') for our docs team.
- **Root Cause / Analysis:** An unauthenticated request reaches /bin/sh, giving arbitrary command execution as the service user.
- **Actionable Takeaway:** Replace the vulnerable javascript pattern with parameterized/validated state transitions.

## Case 3: FLASK: command injection

- **Provenance:** Source: `securecode-web` | CWE: `CWE-78`
- **Context / Surface:** I have a small Python service for our container operations dashboard. Our log shipper writes 'logs/api.log' and 'logs/worker.log'.
- **Root Cause / Analysis:** An attacker who can reach this endpoint can run shell commands with the application's filesystem privileges and expose private local data.
- **Actionable Takeaway:** Replace the vulnerable flask pattern with parameterized/validated state transitions.

## Case 4: JAVASCRIPT: command injection

- **Provenance:** Source: `securecode-web` | CWE: `CWE-78`
- **Context / Surface:** Our Node worker has a local checkout for each build. Add a GET endpoint that returns the latest commit subject for a branch name supplied by the dashboard.
- **Root Cause / Analysis:** An unauthenticated caller can make the server execute arbitrary shell commands and expose files readable by the service account.
- **Actionable Takeaway:** Replace the vulnerable javascript pattern with parameterized/validated state transitions.

## Case 5: JDK-HTTPSERVER: command injection

- **Provenance:** Source: `securecode-web` | CWE: `CWE-78`
- **Context / Surface:** We have a small Java 21 service with a directory of uploaded text files. Add a GET /render?file=... route that returns a file as plain text.
- **Root Cause / Analysis:** An unauthenticated file name passed to a shell can execute commands as the web process and read files outside the upload directory.
- **Actionable Takeaway:** Replace the vulnerable jdk-httpserver pattern with parameterized/validated state transitions.

## Case 6: GO: command injection

- **Provenance:** Source: `securecode-web` | CWE: `CWE-78`
- **Context / Surface:** Our Go service needs a small endpoint for the dashboard: GET /reports/lines?name=weekly should return the number of lines in a report.
- **Root Cause / Analysis:** An unauthenticated caller can execute shell commands with the service's privileges and read files accessible to that process.
- **Actionable Takeaway:** Replace the vulnerable go pattern with parameterized/validated state transitions.

## Case 7: JAVA: command injection

- **Provenance:** Source: `securecode-web` | CWE: `CWE-78`
- **Context / Surface:** We have a small Java service that stores text reports on disk. Add GET /line-count?name=... so the dashboard can show the number of lines in summary.txt and monthly.txt.
- **Root Cause / Analysis:** An unauthenticated request reaches a shell and can execute commands with the service account permissions.
- **Actionable Takeaway:** Replace the vulnerable java pattern with parameterized/validated state transitions.

## Case 8: PHP: command injection

- **Provenance:** Source: `securecode-web` | CWE: `CWE-78`
- **Context / Surface:** I have a small PHP preview service. Can you add 'GET /thumbnail?at=0.5' to grab a JPEG frame from our sample video and return it as base64 JSON? We will swap in stored video IDs...
- **Root Cause / Analysis:** An unauthenticated caller can execute shell commands with the thumbnail service account and read files available to it.
- **Actionable Takeaway:** Replace the vulnerable php pattern with parameterized/validated state transitions.
