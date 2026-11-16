# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`velociraptor-vql-artifact-development`](SKILL.md) | Family: **Security Automation and Tool Development**

Representative VQL artifact failures, each with the artifact that proves the diagnosis.

## Case 1: The hunt saturated a file server

- **Surface & Preconditions:** an artifact globs `C:\Windows\System32\winevt\Logs\*.evtx` and calls `parse_evtx` per file with no `resources` block, launched fleet-wide.
- **Root cause & impact:** every endpoint decodes every log at full speed simultaneously; on a server with large third-party channels the collector consumes the CPU the investigation needs, and the hunt itself becomes the incident.
- **Verification & fix:** declare `ops_per_second`, `cpu_limit`, and `timeout`; narrow the glob to the channel in scope; push the channel/ID filter inside the VQL so decoding work drops.

## Case 2: A clean report that was actually truncated

- **Surface & Preconditions:** the artifact sets `max_rows: 50000` and a busy endpoint exceeds it.
- **Root cause & impact:** the collector returns the first 50,000 rows and the analyst reads "no malicious script blocks" from a partial set. Nothing in the output says the cap was hit.
- **Verification & fix:** compare the row count against `max_rows` and label the result partial; raise the cap only with a matching `timeout` increase, and prefer narrowing the filter.

## Case 3: Verify passed, collection returned nothing

- **Surface & Preconditions:** a parameter default is written as `C:\Windows\System32\winevt\Logs\*.evtx` and passed straight to `glob`.
- **Root cause & impact:** the backslashes are escape sequences in a VQL string, and `%SystemRoot%` never expands without `expand()`; the glob matches nothing and the run is indistinguishable from a clean host.
- **Verification & fix:** use forward slashes or escaped backslashes, wrap environment variables in `expand(path=...)`, and add a `LET paths = ...` count check so an empty path list is reported.

## Case 4: Plugin exists on the server, not on the client

- **Surface & Preconditions:** a notebook tests a query against the server, then the same query is packaged as a client artifact.
- **Root cause & impact:** a mixed-version fleet means some clients lack the plugin, so those endpoints silently return nothing while others return data; the hunt appears to show "most hosts clean".
- **Verification & fix:** pin the client version for the hunt, verify plugin availability with `velociraptor query "SELECT * FROM info()"` on a representative client, and report per-client plugin errors instead of swallowing them.
