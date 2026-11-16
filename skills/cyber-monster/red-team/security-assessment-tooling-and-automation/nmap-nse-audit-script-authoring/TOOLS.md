# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`nmap-nse-audit-script-authoring`](SKILL.md) | Family: **Security Assessment Tooling and Automation**

Flags below are the ones that matter for this technique, not an exhaustive dump. Re-check with `--help` against the installed version before quoting a flag.

## Pinned Engineering Stack

- **Primary SDK / Schema:** Nmap 7.9x NSE, Lua 5.3, `shortport`/`http`/`stdnse` libraries.
- **Validation Gate:** `nmap --script ./audit.nse --script-help audit` loads the script and prints its help without running it.
- NSE scripts are loaded from `--datadir` and the script path; a syntax error appears only when Nmap loads the file.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `nmap` | `nmap --script ./audit.nse -p 443 target.example` | Run the script against one port | Cross-platform |
| `nmap --script-help` | `nmap --script-help ./audit.nse` | Confirm the script loads and its categories parse | Cross-platform |
| `lua` | `lua -e "assert(loadfile('audit.nse'))"` | Syntax-check the script without Nmap's loader | Linux, macOS |

## Minimal Script Shape

Smallest shape that matches the current API and stays read-only by default.

```lua
local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"

categories = {"safe", "discovery"}

portrule = shortport.http

action = function(host, port)
  local resp = http.get(host, port, "/")
  if not resp then
    return nil
  end
  local out = stdnse.output_table()
  out.status = resp.status
  out.server = resp.header["server"]
  return out
end
```
