# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`tabletop-exercise-design`](SKILL.md) | Family: **Incident Response**

Verified facilitation and record-keeping tooling. These tools schedule, record and structure an exercise; none of them touches production, and none should be used to store real customer data in a scenario.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `crontab` / `at` | `at now + 45 minutes` then type the inject delivery command | Deterministic inject timing that does not depend on the facilitator watching a clock | Linux / macOS |
| `timeout` | `timeout 12m ./segment.sh` | Hard stop on an exercise segment so overruns do not consume the hot wash | Linux / macOS |
| `ffmpeg` | `ffmpeg -f pulse -i default -t 7200 session.wav` | Audio capture for the conduct record where note-taking is too slow | Linux |
| `git` | `git -C ./ttx init`, then commit the design record and action register | Versioned exercise artefacts so revisions are visible and attributable | Cross-platform |
| `pandoc` | `pandoc aar.md -o aar.pdf --toc` | Render the after-action report from a reviewable source | Cross-platform |
| `jq` | `jq -r 'map(select(.verify == null))' register.json` | Find actions with no verification method before the review meeting | Cross-platform |

## Minimal Script Shape

The shape below runs an exercise's timing and produces the two records that make the exercise auditable: the delivered-inject log and the action register. It touches no production system and holds no real data.

```bash
#!/usr/bin/env bash
# ttx-run.sh — deterministic inject delivery and record capture. No production access.
set -euo pipefail

DESIGN="${DESIGN:?path to ttx-traceability.yaml}"
CASE="${CASE:?exercise record directory}"
mkdir -p "$CASE"
LOG="$CASE/delivered-injects.tsv"
REG="$CASE/action-register.tsv"

[ -f "$LOG" ] || printf 'inject\tat\tpresent\tdecision\tbasis\n' > "$LOG"
[ -f "$REG" ] || printf 'id\tfinding\taction\towner\tdue\tverify\n' > "$REG"

# Gate 0: the design record must exist and reference a plan revision.
if ! grep -q 'plan_reference' "$DESIGN"; then
  echo "BLOCKED: design record names no plan revision; the exercise cannot be scored."; exit 2
fi

# Gate 1: refuse to run if any objective lacks an inject.
orphans="$(python3 - "$DESIGN" <<'PY'
import sys, yaml
d = yaml.safe_load(open(sys.argv[1]))
forced = {i.get("forces_objective") for i in d.get("injects", [])}
print(" ".join(o["id"] for o in d.get("objectives", []) if o["id"] not in forced))
PY
)"
if [ -n "$orphans" ]; then
  echo "BLOCKED: objectives with no inject: $orphans"; exit 3
fi

# Gate 2: deliver injects on a clock and capture the decision live.
deliver() { # deliver <id> <minutes> <prompt>
  sleep "$(( $2 * 60 ))"
  printf '\n[INJECT %s] %s\n' "$1" "$3"
  read -r -p "Present roles: " roles
  read -r -p "Decision taken : " decision
  read -r -p "Basis cited    : " basis
  printf '%s\tT+%s\t%s\t%s\t%s\n' "$1" "$2" "$roles" "$decision" "$basis" >> "$LOG"
}

# In production delivery, schedule each inject rather than blocking sequentially:
#   at now + 45 minutes <<< './deliver.sh INJ-3'
echo "Design validated. Deliver injects per $DESIGN and record decisions live."

# Gate 3: no action may be registered without an owner, a date and a verification test.
add_action() { # add_action <id> <finding> <action> <owner> <due> <verify>
  if [ -z "${4:-}" ] || [ -z "${5:-}" ] || [ -z "${6:-}" ]; then
    echo "REJECTED: action $1 lacks owner, due date or verification method." >&2
    return 1
  fi
  printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" "$5" "$6" >> "$REG"
}
```

## Notes That Prevent Wrong Runs

- Deliver injects on a timer, not on the facilitator's judgement. Exercises that run on facilitator pacing drift, and the last two objectives are usually the ones cut.
- Record the decision log live. Reconstructed logs record the decision the group wishes it had made, and every action item inherits that distortion.
- Never place real customer records, live credentials or production screenshots in an exercise artefact. The scenario needs plausibility, not authenticity.
- Reserve the hot wash immediately after conduct, before people disperse. A hot wash scheduled for the next day loses the specific recollections that make findings actionable.
- CISA's CTEP package publishes a situation manual, facilitator/evaluator handbook, exercise brief, feedback form and AAR/Improvement Plan template, and recommends drafting the AAR-IP within three to four weeks of conduct. Adapting those is faster and more defensible than building equivalents.
