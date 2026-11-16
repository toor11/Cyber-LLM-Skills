# Multi-Dataset Provenance Log

> Sub-skill: [`os-command-injection`](SKILL.md) | Family: **Web and Application**

Case labels below are stored in this file. The procedure is in [`SKILL.md`](SKILL.md).

## In-file case labels

| Tag | What this file already states |
|---|---|
| CWE-78 | php - command injection |
| CWE-78 | javascript - command injection |
| CWE-78 | flask - command injection |
| CWE-78 | javascript - command injection |
| CWE-78 | jdk-httpserver - command injection |
| CWE-78 | go - command injection |
| CWE-78 | java - command injection |
| CWE-78 | php - command injection |
| - | Webshell via File Upload on ecjobs.starbucks.com.cn |
| - | RCE by command line argument injection to 'gm convert' in '/edit/process?a=crop' |
| - | RCE using bash command injection on /system/images (toimitilat.lahitapiola.fi) |
| - | No SearchEngine sanatizing can lead to command injection |
| Telemetry/Playbook | Command Injection Attack |
| Nuclei YAML Check | http |
| Nuclei YAML Check | Seagate BlackArmor NAS - Command Injection |
| Nuclei YAML Check | Xdebug <= 2.5.5 - Command Injection |
| Nuclei YAML Check | NETGEAR WNAP320 Access Point Firmware - Remote Command Injection |
| Nuclei YAML Check | Trixbox - 2.8.0.4 OS Command Injection |
| Nuclei YAML Check | Oracle Fusion Middleware Weblogic Server - Remote OS Command Execution |
| Nuclei YAML Check | Jenkins - Remote Command Injection |
| Nuclei YAML Check | Dasan GPON Devices - Remote Code Execution |
| Nuclei YAML Check | LG NAS Devices - Remote Code Execution |
| Nuclei YAML Check | Apache Tika < 1.1.8 - Header Command Injection |
| Nuclei YAML Check | LogonTracer <=1.2.0 - Remote Command Injection |
| mitigation | Using the system() function in C to execute commands, as it accepts a single string and... |
| Injection | Reject any input containing non-alphanumeric characters, including special symbols such as ';'... |
| code_snippet | ping -c 4 $(echo $userInput / sed 's/[^a-zA-Z0-9.]//g') |
| Validation | The validation does not enforce the presence of a file extension, which is necessary to... |
| API Function Calls | Python: subprocess.popen |
| OSCommandInjection | Rely solely on denylists to filter out known malicious inputs. |
