# Tools, Flags, and Minimal Script Shape

> Sub-skill: [`zk-and-mpc-protocol-review`](SKILL.md) | Family: **Cryptography Attacks**

Flags below are the ones this technique actually needs. Verify with `--help` when the
installed version differs; never guess a flag into a report.

| Tool | Command | What it settles | Platform |
|---|---|---|---|
| `snarkjs` | `snarkjs zkey verify circuit.r1cs pot.ptau final.zkey` | Whether the setup artefacts are internally consistent | Node |
| `snarkjs` | `snarkjs groth16 verify vk.json public.json proof.json` | Reference verification for comparison with the application's | Node |
| `rg` | `rg -n -e 'keccak256' -e 'sha256' -e 'challenge'` | Challenge-derivation sites and their inputs | any |
| `circom` | `circom circuit.circom --r1cs --wasm` | Rebuilds the circuit so constraints can be counted against the claim | circom |
| `ecdsa`/`sage` | `sage -c "print(Mod(1, 101).multiplicative_order())"` | Group-order arithmetic behind a soundness-error argument | SageMath |

## Minimal script shape

```python
# Report which transcript elements are inside the challenge, from source.
import ast
import pathlib

def challenge_inputs(path: str) -> dict[str, list[str]]:
    tree = ast.parse(pathlib.Path(path).read_text(errors="ignore"))
    out = {}
    for fn in [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)]:
        if "challenge" not in fn.name and "hash" not in fn.name:
            continue
        names = {a.arg for a in fn.args.args}
        used = {n.id for n in ast.walk(fn) if isinstance(n, ast.Name)}
        out[fn.name] = sorted(names & used)
    return out

if __name__ == "__main__":
    print(challenge_inputs("zkp.py"))
```

A challenge that consumes only a commitment argument names the binding gap; a challenge consuming the verifier key and the inputs is the control.
