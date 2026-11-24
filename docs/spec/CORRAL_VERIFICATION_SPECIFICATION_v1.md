# Corral-Lite Verification Specification (CVS-Lite) v1.0
## Deterministic Static Verification & Quality Gate Specification

Status: Open Standard  
Published: November 2026  
License: Apache-2.0  
Authority: Corral Contributors  

### 1. Abstract

The Corral-Lite Verification Specification defines a lightweight, deterministic, zero-dependency static analysis and verification standard for multi-language repositories. It provides rigorous, automated verification of code quality, security posture, and developer safeguards across Python, Rust, Go, TypeScript/JavaScript, agent configuration files, and package manifests.

The specification guarantees:
1. **Zero External Runtime Dependencies**: Verification operates strictly using standard runtime libraries.
2. **Deterministic Exit Codes**: Reproducible gating behavior across local terminals and CI/CD automation.
3. **Structured Diagnostic Output**: Multi-format reporting via human-readable text, structured JSON, and OASIS SARIF v2.1.0.
4. **Standardized Rule Taxonomy**: Consistent severity classifications (`blocking` vs `advisory`).

---

### 2. Operational Model & Execution Architecture

Corral-Lite inspects files via abstract syntax tree (AST) traversal and deterministic pattern verification.

#### Deterministic Exit Codes
- **`0` (PASS)**: Zero blocking findings detected. Advisory findings may be present.
- **`1` (FAIL)**: One or more blocking findings detected.
- **`2` (ERROR)**: Invalid CLI arguments or file/verification error.

#### Supported File Discovery
Recursive repository discovery inspects files matching registered suffixes and basenames:
- **Python**: `.py`
- **Rust**: `.rs`
- **Go**: `.go`
- **TypeScript / JavaScript**: `.ts`, `.tsx`, `.js`, `.jsx`
- **Agent Configurations**: `.cursorrules`, `.claude/settings.local.json`, `settings.local.json`
- **Package Manifests**: `package.json`
- **Dockerfile**: `Dockerfile`, `*.dockerfile`, `dockerfile.*`
- **Shell Scripts**: `.sh`, `.bash`

Ignored by default: `.git`, `__pycache__`, `node_modules`, and hidden dot-directories (except `.claude`).

---

### 3. Rule Taxonomy & Severity Spectrum

Corral-Lite implements 19 deterministic rules across two severity tiers:

#### Blocking Severity (`blocking` -> Exit 1)
Defects and security hazards requiring immediate remediation before merge or release:
- **`PY001`**: Bare or broad exception (`BaseException`, `Exception`) swallowed with `pass`.
- **`PY002`**: Mutable collection default argument (`list`, `dict`, `set`) in function definition.
- **`PY003`**: Dynamic code execution via `eval()` or `exec()`.
- **`PY006`**: Subprocess invocation with `shell=True`.
- **`PY007`**: `assert` statement in non-test production Python module.
- **`PY008`**: Hardcoded secret string assigned to credential/secret variables.
- **`PY009`**: Insecure deserialization via `pickle.load`/`pickle.loads` or `torch.load` missing `weights_only=True`.
- **`PY010`**: Insecure YAML deserialization without `SafeLoader` or `CSafeLoader`.
- **`RS001`**: Unguarded `.unwrap()`, `.expect()`, or `panic!()` in non-test Rust code.
- **`RS002`**: Identical conditional logic across `if` and `else` branches in Rust code.
- **`RS003`**: Holding mutex lock guard across `.await` point in async Rust function.
- **`GO001`**: Discarded error value via blank identifier (`_ = err`, `_, _ = ...`, `, _ :=`) in non-test Go code.
- **`TS001`**: Vacant `catch` block (empty or comment-only) in TypeScript/JavaScript.
- **`AGT001`**: Hardcoded API secret tokens (`sk-`, `ghp_`, `AKIA`) or wildcard permissions in agent config.

#### Advisory Severity (`advisory` -> Exit 0)
Quality and supply-chain hygiene warnings:
- **`PY004`**: Wildcard import (`from module import *`) obscuring namespace provenance.
- **`PY005`**: Unguarded `json.loads()` call outside `try-except` block.
- **`DEPS001`**: `package.json` defines `preinstall` or `postinstall` lifecycle scripts posing supply-chain risks.
- **`DK001`**: `Dockerfile` pipes remote script directly to shell (`curl ... | bash` / `wget ... | sh`).
- **`SH001`**: Shell script lacks `set -e` or `set -euo pipefail` for robust error handling.

---

### 4. Diagnostic Reporting Formats

Corral-Lite provides three standard output formats:

1. **Human-Readable Text (`--format text`)**:
   Standard CLI text output detailing finding locations, rule IDs, severities, error messages, and actionable fix hints.

2. **Structured JSON (`--format json`)**:
   Machine-readable payload containing overall verdict (`PASSED` or `FAILED`), finding counts, and individual finding records.

3. **OASIS SARIF v2.1.0 (`--format sarif`)**:
   Fully compliant Static Analysis Results Interchange Format (SARIF) JSON document for integration with code review platforms, IDE extensions, and security dashboards.
