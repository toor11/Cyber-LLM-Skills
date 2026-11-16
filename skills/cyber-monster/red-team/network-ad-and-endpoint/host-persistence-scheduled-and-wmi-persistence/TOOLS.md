# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`host-persistence-scheduled-and-wmi-persistence`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Entry points verified against current releases. Impacket, Certipy and netexec rename subcommands between minor versions; check `--help` before scripting.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `Get-ScheduledTask` | `Get-ScheduledTask &#124; Where-Object TaskPath -notlike '\Microsoft\*'` | Non-Microsoft task inventory | Windows |
| `schtasks` | `schtasks /query /fo LIST /v` | Verbose task detail including run-as | Windows |
| `Get-CimInstance` | `Get-CimInstance -Namespace root\subscription -ClassName __EventFilter` | WMI subscription filters | Windows |
| `Get-WmiObject` | `Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding` | Subscription bindings | Windows |
| `autorunsc` | `autorunsc.exe -a t -h -s` | Task autostart inventory with signatures | Windows |

## Minimal Lab Validation Script

Enumerate the task and subscription populations and flag incomplete subscriptions, which is the difference between staged and live.

```python
import subprocess

def ps(cmd):
    return subprocess.run(["powershell", "-NoProfile", "-Command", cmd],
                          capture_output=True, text=True).stdout

tasks = ps("Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\\Microsoft\\*' } | "
           "Select-Object TaskName,Author | ConvertTo-Csv -NoTypeInformation")
filters = ps("(Get-CimInstance -Namespace root\\subscription -ClassName __EventFilter).Name")
consumers = ps("(Get-CimInstance -Namespace root\\subscription -ClassName CommandLineEventConsumer).Name")
bindings = ps("(Get-CimInstance -Namespace root\\subscription -ClassName __FilterToConsumerBinding).Filter")

print("non_ms_tasks", len(tasks.splitlines()) - 1)
print("wmi_filters", filters.split(), "consumers", consumers.split(), "bindings", bindings.split())
```

## Flag Notes

- `/v` on schtasks adds the run-as account and the stored-credential flag, which the summary view omits.
- `-a t` in autorunsc restricts to tasks, which is faster than the full autostart scan.
- Namespace `root\\subscription` is where all three subscription classes live; querying any other namespace finds nothing.
