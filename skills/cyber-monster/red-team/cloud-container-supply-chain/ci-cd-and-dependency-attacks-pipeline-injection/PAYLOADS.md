# Verification Probes and Expected Differentials

> Sub-skill: [`ci-cd-and-dependency-attacks-pipeline-injection`](SKILL.md) | Family: **Cloud, Container and Supply Chain**

Non-destructive probes only: record the benign baseline first, then the probe, and treat a
repeatable difference between the two as the finding. Every probe below is a read, a parse,
or an offline decode; none of them writes to the target.

## Class 1 — Interpolation inventory

```text
# Expressions inside run blocks, which is the sink that matters.
rg -n --no-heading -B2 -A4 "run:\s*[|>]?" .github/workflows/ | rg -n '\$\{\{\s*github\.event'
# GitLab: variable expansion inside script blocks.
rg -n --no-heading "script:" -A6 .gitlab-ci.yml | rg -n "CI_MERGE_REQUEST|CI_COMMIT"
```

Expected differential: an expression inside `run:` is the finding; the same expression inside `env:` with a quoted `"$VAR"` reference in the script is the control.

## Class 2 — Sink classification

```text
python - <<'CICDANDDEPENDE9B96_CLASS2'
import pathlib, re
SINK = re.compile(r"\$\{\{\s*github\.event\.(pull_request|issue|comment|commits)[^}]*\}\}")
for p in pathlib.Path(".github/workflows").glob("*.yml"):
    text = p.read_text(errors="ignore")
    in_run = False
    for i, line in enumerate(text.splitlines(), 1):
        if re.match(r"\s*run:", line):
            in_run = True
        elif re.match(r"\s*[a-z_-]+:", line):
            in_run = False
        if in_run and SINK.search(line):
            print(f"{p.name}:{i}: {line.strip()[:90]}")
CICDANDDEPENDE9B96_CLASS2
```

Expected differential: every printed line is a direct injection point; an empty output across the workflow directory is the negative result you report with the file count.

## Class 3 — Lab reproduction

```text
# In a fork you own: set a PR title containing a command substitution and check the
# workflow log for the effect. Never on a repository you do not own.
gh pr create --title 'test $(id)' --body 'lab'
gh run list --workflow label --limit 1
gh run view --log | rg -i "uid=|Processing"
```

Expected differential: the marker appearing in the log proves execution; its absence with the title still echoed proves the value was treated as data.

## Differential Discipline

- Run the baseline twice before the probe so run-to-run variance is known.
- A probe that changes nothing is evidence of a control, and belongs in the non-finding list.
- Never widen a probe into state change to make a difference appear.
