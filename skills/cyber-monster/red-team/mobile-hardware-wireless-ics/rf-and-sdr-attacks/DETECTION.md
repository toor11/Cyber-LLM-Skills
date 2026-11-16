# Detection Signals and Blue-Team Handoff

> Sub-skill: [`rf-and-sdr-attacks`](SKILL.md) | Family: **Mobile, Hardware, Wireless and ICS**

Each line names the field, event, or query that carries the signal. Detection engineering
and response ownership stay with the paired blue-team skill.

- RF monitoring: a transmission at the device's frequency from a location outside its expected operating area.
- Receiver log: a frame rejected for a counter out of window, which is the rolling-code control firing.
- Receiver log: the same counter value seen twice, which is the replay signal.
- Physical security audit: a receiver whose acceptance window was widened, which the configuration shows.
- Spectrum monitoring: continuous carrier activity on a frequency that should carry only periodic bursts.

## Handoff

| Target | Purpose |
|---|---|
| Paired blue-team counterpart linked in [`SKILL.md`](SKILL.md) | Triage queries, alert thresholds, and containment ownership |
