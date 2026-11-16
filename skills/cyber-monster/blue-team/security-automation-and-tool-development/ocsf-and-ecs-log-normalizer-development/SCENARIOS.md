# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`ocsf-and-ecs-log-normalizer-development`](SKILL.md) | Family: **Security Automation and Tool Development**

Representative normalization failures, each with the artifact that proves the diagnosis.

## Case 1: One feed's events land in the wrong hour

- **Surface & Preconditions:** a vendor feed emits `2026-11-14 18:40:00` with no offset; the parser treats it as UTC.
- **Root cause & impact:** every event from that feed is shifted by the collector's local offset, so a five-minute window detection misses the sequence it was written for and the "spike" appears at the wrong time of day.
- **Verification & fix:** require an explicit offset in `parse_instant` and dead-letter naive values; obtain the source's documented timezone and apply it explicitly rather than inferring from the collector host.

## Case 2: Malformed line drops the whole batch

- **Surface & Preconditions:** a batch normalizer calls `json.loads` per line outside a try block, or `parse_json!` without `reroute_dropped` in Vector.
- **Root cause & impact:** one truncated line from a log rotation aborts the entire batch, so hundreds of well-formed events behind it are never indexed and nothing indicates the loss.
- **Verification & fix:** per-record error handling with a dead-letter writer that stores line number, error, and raw bytes; in VRL, `reroute_dropped = true` plus a file sink on `<transform>.dropped`.

## Case 3: class_uid and category_uid disagree

- **Surface & Preconditions:** a normalizer sets `class_uid: 3004` but leaves `category_uid` at a default of `1`.
- **Root cause & impact:** presence-based schema checks pass, yet every category-scoped query and dashboard ignores the events. The feed looks healthy and contributes nothing.
- **Verification & fix:** derive `category_uid` from the chosen class, and assert the pair in the fixture set rather than only asserting field presence.

## Case 4: OCSF identifiers pushed into an ECS index

- **Surface & Preconditions:** a team reuses an OCSF normalizer for an Elasticsearch destination configured with ECS mappings.
- **Root cause & impact:** `class_uid`/`category_uid` have no ECS equivalent, so the fields either land in unmapped dynamic fields or are dropped by strict mappings; `event.category` stays empty and ECS-based detections never match.
- **Verification & fix:** map the class to the `event.category`/`event.type`/`event.kind` triple and keep the OCSF identity only in an explicitly unmapped location.
