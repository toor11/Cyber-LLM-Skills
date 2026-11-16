# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`libfuzzer-and-afl-harness-engineering`](SKILL.md) | Family: **Security Assessment Tooling and Automation**

Flags below are the ones that matter for this technique, not an exhaustive dump. Re-check with `--help` against the installed version before quoting a flag.

## Pinned Engineering Stack

- **Primary SDK / Schema:** libFuzzer via clang `-fsanitize=fuzzer`; AFL++ 5.x with `afl-clang-fast` and LTO mode (`AFL_LLVM_LTO=1`).
- **Validation Gate:** a `-runs=0` corpus pass, then a bounded campaign with `-max_len` set.
- AFL++ 5.x moved to an exec-based limit before mode switching and added Ball-Larus path coverage via `AFL_LLVM_PATH`; older command lines that relied on time-based limits behave differently.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `clang` | `clang -g -O1 -fsanitize=fuzzer,address,undefined fuzz.c -o fuzz` | Build the instrumented harness | Cross-platform |
| `afl-clang-fast` | `AFL_LLVM_LTO=1 afl-clang-fast -g -O1 target.c -o target` | LTO instrumentation for cross-file coverage | Linux, macOS |
| `afl-tmin` | `afl-tmin -i crash -o crash_min -- ./target @@` | Minimise a crasher before reporting | Linux, macOS |

## Minimal Script Shape

Smallest shape that matches the current API and stays read-only by default.

```c
#include <stdint.h>
#include <stddef.h>

int parse(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 4 || size > 1 << 20) {
        return 0;
    }
    (void)parse(data, size);
    return 0;
}
```
