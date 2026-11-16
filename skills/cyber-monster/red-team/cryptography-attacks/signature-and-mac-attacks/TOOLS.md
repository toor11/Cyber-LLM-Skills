# Tools, Flags, and Minimal Script Shape

> Sub-skill: [`signature-and-mac-attacks`](SKILL.md) | Family: **Cryptography Attacks**

Flags below are the ones this technique actually needs. Verify with `--help` when the
installed version differs; never guess a flag into a report.

| Tool | Command | What it settles | Platform |
|---|---|---|---|
| `python` | `python -c "import hmac,hashlib;print(hmac.new(b'k',b'm','sha256').hexdigest())"` | Reproduces the MAC offline for comparison with the service's | CPython |
| `openssl` | `openssl dgst -sha256 -mac HMAC -macopt hexkey:00ff body.bin` | Independent MAC computation | OpenSSL 3.x |
| `jwt` | `jwt decode "$TOKEN" --json` | Shows the header and claims without verifying, which is where the algorithm confusion lives | jwt-cli |
| `rg` | `rg -n "algorithms\s*=\s*\["` | JWT verification call sites and their algorithm lists | any |
| `mitmproxy` | `mitmproxy -p 8081 --set http2=true` | Inspects callback traffic to see which fields the consumer actually reads | any |

## Minimal script shape

```python
# Compute the covered set and the used set for one endpoint, from source.
import ast
import pathlib

def functions(path: str) -> list[ast.AST]:
    tree = ast.parse(pathlib.Path(path).read_text(errors="ignore"))
    return [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]

def field_reads(fn: ast.AST) -> set[str]:
    out = set()
    for node in ast.walk(fn):
        if isinstance(node, ast.Subscript) and isinstance(node.slice, ast.Constant):
            if isinstance(node.slice.value, str):
                out.add(node.slice.value)
    return out

if __name__ == "__main__":
    for fn in functions("handler.py"):
        print(fn.name, sorted(field_reads(fn)))
```

Compare the printed field set to the fields the signer passes into the MAC; the difference is the finding list.
