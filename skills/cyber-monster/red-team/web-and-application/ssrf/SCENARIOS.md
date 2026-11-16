# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`ssrf`](SKILL.md) | Family: **Web and Application**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: EXPRESS: link preview ssrf

- **Provenance:** Source: `securecode-web` | CWE: `CWE-918`
- **Context / Surface:** We're adding link unfurling to our team chat app. When someone pastes a URL into a message, the web client calls 'POST /api/preview' with '{ "url": "..." }' and renders a card...
- **Root Cause / Analysis:** Missing security invariant for CWE-918.
- **Actionable Takeaway:** Replace the vulnerable express pattern with parameterized/validated state transitions.

## Case 2: PHP: ssrf url image import

- **Provenance:** Source: `securecode-web` | CWE: `CWE-918`
- **Context / Surface:** I'm building a small PHP 8.3 service (no framework yet, just the built-in server while I prototype) for user profile pictures.
- **Root Cause / Analysis:** An unauthenticated URL parameter lets anyone make the server read loopback/internal services, local files and the cloud metadata endpoint, exposing credentials and internal data; no direct code execution is shown.
- **Actionable Takeaway:** Replace the vulnerable php pattern with parameterized/validated state transitions.

## Case 3: EXPRESS: url fetch image import

- **Provenance:** Source: `securecode-web` | CWE: `CWE-918` | CVE: `CVE-2021-22214`
- **Context / Surface:** We're adding "import avatar from URL" to our profile service (Node 22, Express 5). Users paste a link, we download the image and store it so we're not hotlinking.
- **Root Cause / Analysis:** Missing security invariant for CWE-918.
- **Actionable Takeaway:** Replace the vulnerable express pattern with parameterized/validated state transitions.

## Case 4: EXPRESS: webhook url ssrf hostname check bypass

- **Provenance:** Source: `securecode-web` | CWE: `CWE-918` | CVE: `CVE-2021-22214`
- **Context / Surface:** We're adding outgoing webhooks to our billing app (Node 22, Express 5). Customers register an endpoint URL, and there's a "Send test event" button that POSTs a sample payload and...
- **Root Cause / Analysis:** Missing security invariant for CWE-918.
- **Actionable Takeaway:** Replace the vulnerable express pattern with parameterized/validated state transitions.

## Case 5: PHP: dns rebinding toctou webhook

- **Provenance:** Source: `securecode-web` | CWE: `CWE-918`
- **Context / Surface:** We're adding outbound webhooks to our PHP 8.3 app (plain PHP, no framework, php-fpm on EC2).
- **Root Cause / Analysis:** Missing security invariant for CWE-918.
- **Actionable Takeaway:** Replace the vulnerable php pattern with parameterized/validated state transitions.

## Case 6: JAVA: webhook url ssrf cloud metadata

- **Provenance:** Source: `securecode-web` | CWE: `CWE-918`
- **Context / Surface:** We're building an integrations platform in plain Java 21 (no Spring, just the JDK 'HttpServer' behind our gateway).
- **Root Cause / Analysis:** Missing security invariant for CWE-918.
- **Actionable Takeaway:** Replace the vulnerable java pattern with parameterized/validated state transitions.

## Case 7: FLASK: url preview ssrf cloud metadata

- **Provenance:** Source: `securecode-web` | CWE: `CWE-918`
- **Context / Surface:** I'm adding link unfurling to our team chat backend (Flask, deployed on AWS). When someone pastes a URL, the web client POSTs it to '/api/preview' and we fetch the page server-side...
- **Root Cause / Analysis:** Missing security invariant for CWE-918.
- **Actionable Takeaway:** Replace the vulnerable flask pattern with parameterized/validated state transitions.

## Case 8: GO-NET-HTTP: url fetch ssrf link preview

- **Provenance:** Source: `securecode-web` | CWE: `CWE-918`
- **Context / Surface:** Adding link previews to our team chat. Backend is Go 1.25, plain 'net/http', no framework, runs as a pod on EKS.
- **Root Cause / Analysis:** Any user who can post a link gets full-response reads from loopback and VPC services through the server; on nodes where IMDSv1 is reachable this extends to cloud role credentials.
- **Actionable Takeaway:** Replace the vulnerable go-net-http pattern with parameterized/validated state transitions.
