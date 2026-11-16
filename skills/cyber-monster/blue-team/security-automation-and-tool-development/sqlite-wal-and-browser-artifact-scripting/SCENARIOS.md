# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`sqlite-wal-and-browser-artifact-scripting`](SKILL.md) | Family: **Security Automation and Tool Development**

Representative SQLite evidence failures, each with the artifact that proves the diagnosis.

## Case 1: The last hour of browsing is missing

- **Surface & Preconditions:** an analyst copies only `History` from a live profile and queries it.
- **Root cause & impact:** the browser runs in WAL mode; every commit since the last checkpoint lives in `History-wal`. Copying the main database alone yields a view that ends at the last checkpoint, which reads as "the user stopped browsing" rather than "the evidence was incomplete".
- **Verification & fix:** enumerate and copy all sidecars before querying, and record which sidecars were present in the report. When `-wal` is absent, state that the browser was likely shut down cleanly rather than implying no later activity.

## Case 2: `immutable=1` produced a stale but authoritative-looking answer

- **Surface & Preconditions:** a script opens the live profile with `?immutable=1` to "avoid modifying evidence".
- **Root cause & impact:** `immutable=1` instructs SQLite to ignore the `-wal` entirely, so the result is a snapshot from an arbitrary earlier point served without warning; on a dirty rollback journal it can also surface uncommitted rows.
- **Verification & fix:** never use `immutable=1` where sidecars exist. Hash, copy, and open the copy with `mode=ro` (or `mode=rw` when replaying a journal).

## Case 3: Handle left open, temp cleanup fails on Windows

- **Surface & Preconditions:** the extractor uses `with sqlite3.connect(...) as conn:` and deletes the temp directory afterwards.
- **Root cause & impact:** the `sqlite3` context manager commits or rolls back and does **not** close, so the file stays locked; `shutil.rmtree` then raises `PermissionError [WinError 32]`, and in a live-profile workflow the lock can hold the browser's own files.
- **Verification & fix:** wrap with `contextlib.closing(...)` or a `try/finally: conn.close()`; verify by asserting the temp directory is removable in the test.

## Case 4: Fifty rows, one website

- **Surface & Preconditions:** the report is generated from `SELECT * FROM visits ORDER BY visit_time DESC LIMIT 50`.
- **Root cause & impact:** `visits` is one row per navigation, so a user who refreshed one page repeatedly fills the entire report and the narrative "visited 50 sites" is false.
- **Verification & fix:** aggregate with `GROUP BY u.url` and take `MAX(v.visit_time)`; report both distinct-site count and navigation count so the two are not conflated.
