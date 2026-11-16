# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`ole-pdf-and-office-triage-scripting`](SKILL.md) | Family: **Security Automation and Tool Development**

Representative document-triage failures, each with the artifact that proves the diagnosis.

## Case 1: A remote template lure was assessed as clean

- **Surface & Preconditions:** an analyst checks a `.docx` for macros, finds none, and closes the ticket.
- **Root cause & impact:** the document's settings relationship points at an external template (`TargetMode="External"`), so opening it fetches and renders attacker-controlled content that can itself contain macros. "No macros in this file" is technically true and operationally wrong.
- **Verification & fix:** always inspect the relationship parts for external targets, defang and report them, and treat a remote template as equivalent risk to a macro.

## Case 2: The triage host fetched the payload

- **Surface & Preconditions:** an enrichment step resolves the external template URL to capture its content hash.
- **Root cause & impact:** the request tells the operator the document reached an analyst, may serve a different (benign) payload, and brings hostile content onto the analysis host. Triage changed the attacker's view of the environment.
- **Verification & fix:** never fetch; record the defanged URL and let network-side telemetry confirm whether any host in the estate contacted it.

## Case 3: A decompression bomb exhausted the analyst's workstation

- **Surface & Preconditions:** the parser reads all ZIP members into memory before inspecting the macro stream.
- **Root cause & impact:** a small document declares a huge uncompressed total, and the triage process consumes all available RAM before producing any finding — an availability attack delivered through the investigation tool.
- **Verification & fix:** sum `file_size` from `infolist()` and refuse above a cap, reporting the size as a suspicious property rather than an error to retry.

## Case 4: `/JS` counted as execution

- **Surface & Preconditions:** a PDF report marks a document malicious because it contains `/JavaScript`.
- **Root cause & impact:** the script object may be unreachable from any triggered action, so the file is suspicious but not confirmed to run anything. Overstating it produces a false positive that damages trust in the triage report.
- **Verification & fix:** follow `/OpenAction`/`/AA` to the referenced objects and state whether the script is reachable; report unreachable script as present-but-not-triggered.
