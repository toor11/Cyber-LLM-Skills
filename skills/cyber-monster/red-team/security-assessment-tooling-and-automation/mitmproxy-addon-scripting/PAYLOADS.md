# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`mitmproxy-addon-scripting`](SKILL.md) | Family: **Security Assessment Tooling and Automation**

Probes for `mitmproxy-addon-scripting`. Each group names the baseline it is compared against and the differential that counts. Run every probe twice; a one-off difference is not proof.

## Read-only flow capture

Baseline: traffic captured with no addon mutation. Probe: the same action with the recording addon. Differential: identical request count and statuses, plus one record per flow.

```bash
mitmdump -s addon.py --set flow_detail=0
mitmdump -s addon.py --set save_stream_file=flows.mitm
mitmdump -nr flows.mitm --set flow_detail=1
```

## Header observation

Baseline: the server's header set. Probe: the same endpoint after a client change. Differential: a header present in one capture and absent in the other, with the request otherwise identical.

```python
print(sorted(k.lower() for k in flow.response.headers.keys()))
print(flow.response.status_code, flow.request.pretty_url)
print(len(flow.response.content or b''))
```

## Usage Rules

- Baseline first, probe second, same scope and same credentials for both runs.
- Stop at the first confirmed differential; do not expand the probe once it fires.
- Pair every confirmed finding with the structural remediation in [`SKILL.md`](SKILL.md).
