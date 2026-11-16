# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`network-protocol-grammar-fuzzer-development`](SKILL.md) | Family: **Security Assessment Tooling and Automation**

Probes for `network-protocol-grammar-fuzzer-development`. Each group names the baseline it is compared against and the differential that counts. Run every probe twice; a one-off difference is not proof.

## Valid frame baseline then one mutation

Baseline: the captured valid frame must produce the normal response. Probe: the same frame with the payload mutated and the length recomputed. Differential: a difference in response or liveness that survives a replay.

```python
frame = struct.pack('>H', len(payload)) + payload
sock.sendall(frame)
print(sock.recv(4096)[:64])
```

## Crash replay against a fresh instance

Baseline: the daemon handles the unmutated frame. Probe: the logged crash frame. Differential: the same failure reproduces, which makes the crash a finding rather than a one-off.

```bash
python -c "import socket,struct; p=bytes.fromhex('474554202f00'); s=socket.create_connection(('127.0.0.1',9000)); s.sendall(struct.pack('>H',len(p))+p); print(s.recv(64))"
```

## Usage Rules

- Baseline first, probe second, same scope and same credentials for both runs.
- Stop at the first confirmed differential; do not expand the probe once it fires.
- Pair every confirmed finding with the structural remediation in [`SKILL.md`](SKILL.md).
