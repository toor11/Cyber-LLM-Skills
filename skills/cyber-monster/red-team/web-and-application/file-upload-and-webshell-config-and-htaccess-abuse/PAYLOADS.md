# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`file-upload-and-webshell-config-and-htaccess-abuse`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `file-upload-and-webshell-config-and-htaccess-abuse`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### Configuration-filename acceptance

**Expected differential:** the directory-override filename is accepted versus rejected by name, deciding whether the variant is even possible

```text
upload a file named .htaccess containing a benign AddType mapping
upload a file named web.config declaring a benign handler entry
```

### Before-and-after evaluation of one content file

**Expected differential:** an unchanged benign data file is served verbatim before the configuration and evaluated after it is present

```text
GET /uploads/probe.img before any .htaccess is present, expect static bytes
GET /uploads/probe.img after .htaccess maps .img to the interpreter
```

### Override-scope confirmation

**Expected differential:** a directive that should only affect this directory is or is not honoured, revealing the AllowOverride state

```text
plant a .user.ini with auto_prepend_file pointing at a benign include
fetch any .php in the directory to see whether the prepend token appears
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
