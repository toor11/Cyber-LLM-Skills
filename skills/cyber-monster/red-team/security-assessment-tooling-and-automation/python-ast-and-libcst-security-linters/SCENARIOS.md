# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`python-ast-and-libcst-security-linters`](SKILL.md) | Family: **Security Assessment Tooling and Automation**

Two worked shapes for this technique. Identifiers are placeholders for the engagement's own assets; no incident below is a fabricated advisory.

## Case 1: Rule Flags a Documentation String

- **Surface & Preconditions:** A new rule reports `eval(` inside a docstring example and blocks the build.
- **Root Cause & Impact:** The rule matched text rather than the AST, so a string literal counted as a call.
- **Verification & Fix:** Move to `ast.NodeVisitor`, keep the fixture pair, and confirm the documentation file produces zero hits.

## Case 2: Autofix Reformatting the Whole File

- **Surface & Preconditions:** The fix commit for one dangerous call rewrites indentation and quoting across the module.
- **Root Cause & Impact:** The tool re-serialised the module instead of transforming the CST node.
- **Verification & Fix:** Use `libcst.CSTTransformer`, which rewrites only the matched node, and confirm the diff contains one hunk.
