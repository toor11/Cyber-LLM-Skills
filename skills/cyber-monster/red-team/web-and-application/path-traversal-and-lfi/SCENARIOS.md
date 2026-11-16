# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`path-traversal-and-lfi`](SKILL.md) | Family: **Web and Application**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: EXPRESS: path traversal

- **Provenance:** Source: `securecode-web` | CWE: `CWE-22`
- **Context / Surface:** We have a few public text reports bundled with our Express app. Can you add '/download?file=q3.txt' so customers get a file attachment? The reports live in a 'reports' folder.
- **Root Cause / Analysis:** An unauthenticated traversal can disclose files readable by the web process outside the public report directory.
- **Actionable Takeaway:** Replace the vulnerable express pattern with parameterized/validated state transitions.

## Case 2: EXPRESS: path traversal

- **Provenance:** Source: `securecode-web` | CWE: `CWE-22`
- **Context / Surface:** We use Express for a small document portal. Add a GET /download?file=... endpoint so visitors can save the public guide from the docs folder. The first file is guide.txt.
- **Root Cause / Analysis:** An unauthenticated request can disclose any file readable by the web process when its path is passed to the download endpoint.
- **Actionable Takeaway:** Replace the vulnerable express pattern with parameterized/validated state transitions.

## Case 3: PHP: path traversal

- **Provenance:** Source: `securecode-web` | CWE: `CWE-22`
- **Context / Surface:** We have a plain PHP route inside a workspace that already gates all requests at a trusted front end.
- **Root Cause / Analysis:** A path traversal in a shared download route can disclose files readable by the PHP process outside the intended upload tree.
- **Actionable Takeaway:** Replace the vulnerable php pattern with parameterized/validated state transitions.

## Case 4: FLASK: path traversal

- **Provenance:** Source: `securecode-web` | CWE: `CWE-22`
- **Context / Surface:** Can you add a Flask download route for our text reports? The report job writes quarterly.txt under data/reports.
- **Root Cause / Analysis:** A caller can read any local file reachable by the app process through an unauthenticated download route.
- **Actionable Takeaway:** Replace the vulnerable flask pattern with parameterized/validated state transitions.

## Case 5: DJANGO: path traversal

- **Provenance:** Source: `securecode-web` | CWE: `CWE-22`
- **Context / Surface:** Our Django service has a public reports page. Can you add a GET /download/?name=quarterly.txt endpoint that serves the text reports in data/public/reports as attachments? A...
- **Root Cause / Analysis:** An unauthenticated query parameter lets any caller read any file the service process can read, including environment variables and configuration that often hold credentials.
- **Actionable Takeaway:** Replace the vulnerable django pattern with parameterized/validated state transitions.

## Case 6: FLASK: path traversal

- **Provenance:** Source: `securecode-web` | CWE: `CWE-22`
- **Context / Surface:** We have a Flask service that stores text templates in a 'templates/' folder. Add a preview endpoint where the UI passes a template name, including names such as...
- **Root Cause / Analysis:** An unauthenticated path parameter can disclose readable files outside the intended template directory.
- **Actionable Takeaway:** Replace the vulnerable flask pattern with parameterized/validated state transitions.

## Case 7: EXPRESS: path traversal

- **Provenance:** Source: `securecode-web` | CWE: `CWE-22` | CVE: `CVE-2021-43798`
- **Context / Surface:** We publish a handful of customer reports (quarterly.txt, usage.txt, activity.txt, archive.txt, feed.txt) from an Express 5 app on Node 22.
- **Root Cause / Analysis:** An unauthenticated request can read any non-dot-path file the web process can read, such as system files and application source, but cannot modify files or execute code directly.
- **Actionable Takeaway:** Replace the vulnerable express pattern with parameterized/validated state transitions.

## Case 8: TYPESCRIPT: path traversal

- **Provenance:** Source: `securecode-web` | CWE: `CWE-22`
- **Context / Surface:** We have a tiny Node service that reads text runbooks from 'content/public'. Add 'GET /docs?name=guide.txt' so the support UI can display a requested file.
- **Root Cause / Analysis:** A network client can read a server-side file outside the intended public directory.
- **Actionable Takeaway:** Replace the vulnerable typescript pattern with parameterized/validated state transitions.
