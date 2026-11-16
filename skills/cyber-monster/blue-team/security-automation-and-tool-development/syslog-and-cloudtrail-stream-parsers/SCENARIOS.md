# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`syslog-and-cloudtrail-stream-parsers`](SKILL.md) | Family: **Security Automation and Tool Development**

Representative cloud/syslog parsing failures, each with the artifact that proves the diagnosis.

## Case 1: One event per file, forever

- **Surface & Preconditions:** a parser reads `json.load(f)["Records"][0]` and treats the object as a single event.
- **Root cause & impact:** CloudTrail batches many events per object. Everything after the first record is discarded, and because the first record parses cleanly there is no error — the pipeline simply sees a fraction of the account's activity.
- **Verification & fix:** iterate the full `Records[]` array and reconcile the count against `jq '.Records | length'` per file before shipping.

## Case 2: Trail disabled, nobody noticed

- **Surface & Preconditions:** an operator stops a trail to reduce cost; the parser continues to run on an empty prefix.
- **Root cause & impact:** zero objects means zero records, which is indistinguishable from "no activity" unless the pipeline distinguishes a read error from an empty delivery. The account loses visibility silently.
- **Verification & fix:** treat a zero-record read of a present object as an error, and separately alert on `StopLogging`/`UpdateTrail`/`DeleteTrail` so the change itself is the signal.

## Case 3: CEF columns shifted by one

- **Surface & Preconditions:** a CEF message contains an escaped pipe inside the `name` field and the parser splits on `|`.
- **Root cause & impact:** every field after the escape shifts by one, so severity is read as the extension block and the extension is truncated. Detections on severity then fire on the wrong events.
- **Verification & fix:** tokenize on unescaped pipes only and assert the header field count matches the schema for every line.

## Case 4: Memory spike from a crafted parameter blob

- **Surface & Preconditions:** the parser deep-copies `requestParameters` into the output document for every record.
- **Root cause & impact:** a single API call can carry a very large parameter structure, and copying it per record multiplies memory by batch size; a crafted request turns the parser into a memory amplifier.
- **Verification & fix:** project a fixed whitelist of fields and cap the retained raw blob; measure peak memory against a worst-case fixture.
