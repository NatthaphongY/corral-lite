# corral-lite

[![CI](https://github.com/NatthaphongY/corral-lite/actions/workflows/ci.yml/badge.svg)](https://github.com/NatthaphongY/corral-lite/actions)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![Typing](https://img.shields.io/badge/typing-PEP_561-blueviolet.svg)](https://peps.python.org/pep-0561/)

> **Fast, deterministic AST and pattern static verification engine for Python, Rust, Go, TypeScript, AI agent configs, package manifests, Dockerfile, and Shell with zero external dependencies.**

Corral-Lite provides instant, reproducible static gatekeeper checks designed to eliminate silent error swallowing, unsafe dynamic code execution, mutable default state bugs, and structural defects before code reaches pull requests or production.

> 🤖 **AI Agents**: See [llms.txt](llms.txt) for low-token API/CLI discovery and [AGENTS.md](AGENTS.md) for coding-agent repository invariants.

---

## Architecture Pipeline

Corral-Lite processes source files through a deterministic pipeline that maps directly to fail-closed gate decisions and standardized compliance artifacts:

```mermaid
flowchart LR
    A["Source Files<br/>(*.py, *.rs, *.go, *.ts,<br/>*.sh, Dockerfile, etc.)"] --> B["AST & Pattern Rules<br/>(ast, re, json)"]
    B --> C{"Gate Decision<br/>(Exit 0 / 1)"}
    C --> D["Text Report<br/>(Terminal / Logs)"]
    C --> E["Structured JSON<br/>(CI Automation)"]
    C --> F["SARIF v2.1.0<br/>(GitHub Code Scanning)"]
```

---

## Key Capabilities

- **Zero Heavy Runtime Dependencies**: Pure Python standard library implementation (`ast`, `re`, `json`, `argparse`). Instant installation with zero supply-chain risk.
- **Strictly Deterministic**: Reproducible pass/fail verdicts with identical exit codes across Windows, Linux, and macOS.
- **Fail-Closed Gatekeeper**: Blocking violations immediately yield exit code `1`, preventing flawed pull requests from merging. Advisory findings provide actionable feedback without breaking pipelines.
- **SARIF v2.1.0 Native**: Direct support for OASIS SARIF v2.1.0 exports, seamlessly integrating with GitHub Advanced Security and Code Scanning alerts.
- **Pre-Commit Ready**: First-class `.pre-commit-hooks.yaml` integration for local git workflow enforcement.
- **Typed & Standards-Compliant**: Fully typed PEP 561 package (`src/` layout, `py.typed`) ready for strict static typing setups.
- **Normative Specification Alignment**: Implements core verification checks aligned with the [CORRAL Verification Specification (CVS) v1.0](docs/spec/CORRAL_VERIFICATION_SPECIFICATION_v1.md).

---

## 30-Second Quickstart

### Installation

Install directly from GitHub via `pip`:

```bash
pip install git+https://github.com/NatthaphongY/corral-lite.git
```

Or clone the repository and install in editable mode:

```bash
git clone https://github.com/NatthaphongY/corral-lite.git
cd corral-lite
pip install -e .
```

### Basic Scan

Run static verification against any target file or directory tree:

```bash
corral-lite check src/
# or invoke as a Python module:
python -m corral_lite.cli check src/
```

If any **blocking** finding is detected, `corral-lite` exits with code `1`. If only advisory findings or zero findings are detected, it exits with code `0`.

---

## Verification Rules

Corral-Lite inspects codebases against 19 deterministic static verification rules:

| Rule ID | Language | Severity | Title | Description |
|---|---|---|---|---|
| **PY001** | Python | Blocking | Bare / Broad Except Pass | Flags `except:` or `except Exception:` blocks containing only `pass`. |
| **PY002** | Python | Blocking | Mutable Default Argument | Flags function definitions with mutable collections (`[]`, `{}`, `set()`) as defaults. |
| **PY003** | Python | Blocking | Eval / Exec Invocations | Flags direct invocations of dynamic execution builtins `eval()` or `exec()`. |
| **PY004** | Python | Advisory | Wildcard Import | Flags wildcard imports of the form `from module import *`. |
| **PY005** | Python | Advisory | Unguarded `json.loads` | Flags `json.loads()` calls executed outside an enclosing `try-except` block. |
| **PY006** | Python | Blocking | Subprocess `shell=True` | Flags `subprocess` executions using `shell=True`. |
| **PY007** | Python | Blocking | Assert in Non-Test Code | Flags `assert` statements used in non-test production modules. |
| **PY008** | Python | Blocking | Hardcoded Secret Literal | Flags credential variables assigned static secret string literals. |
| **PY009** | Python | Blocking | Insecure Deserialization | Flags `pickle.load`/`pickle.loads` or `torch.load` missing `weights_only=True`. |
| **PY010** | Python | Blocking | Insecure YAML Load | Flags `yaml.load()` without explicit `SafeLoader` or `CSafeLoader`. |
| **RS001** | Rust | Blocking | Unguarded Unwrap / Panic | Flags `.unwrap()`, `.expect()`, or `panic!()` in non-test Rust code. |
| **RS002** | Rust | Blocking | Identical Conditional Branches | Flags duplicate logic executed across both `if` and `else` branches. |
| **RS003** | Rust | Blocking | Lock Guard Across Await | Flags mutex locks held across `.await` points in async functions. |
| **GO001** | Go | Blocking | Discarded Error Identifier | Flags discarded error values via blank identifier (`_ = err`, `_, _ = ...`). |
| **TS001** | TypeScript | Blocking | Vacant Catch Block | Flags empty or comment-only `catch` blocks in TypeScript/JavaScript. |
| **AGT001** | Config | Blocking | Agent Secret / Wildcard | Flags hardcoded secret tokens (`sk-`, `ghp_`, `AKIA`) or wildcard permissions in agent configs. |
| **DEPS001** | Config | Advisory | Lifecycle Install Scripts | Flags `preinstall` or `postinstall` lifecycle scripts in `package.json`. |
| **DK001** | Dockerfile | Advisory | Pipe Remote Script to Shell | Flags `Dockerfile` piping remote scripts to shell (`curl ... \| bash` / `wget ... \| sh`). |
| **SH001** | Shell | Advisory | Shell Missing `set -e` | Flags `.sh` / `.bash` scripts lacking `set -e` or `set -euo pipefail`. |

---

## Output Formats

### 1. Human-Readable Terminal (Default)

```text
======================================================================
CORRAL-LITE VERIFICATION REPORT
======================================================================
Verdict: FAILED
Total Findings: 1 (Blocking: 1, Advisory: 0)

[BLOCKING] PY001: src/worker.py:42:4
  Message: Broad or bare except block silenced with pass statement.
  Fix Hint: Handle the exception, log with diagnostic context, or propagate upward.
======================================================================
```

### 2. Machine-Readable JSON

Export structured findings for automated tooling:

```bash
corral-lite check src/ --format json
```

```json
{
  "verdict": "FAILED",
  "findings_count": 1,
  "blocking_count": 1,
  "findings": [
    {
      "rule_id": "PY001",
      "severity": "blocking",
      "file_path": "src/worker.py",
      "line": 42,
      "column": 4,
      "message": "Broad or bare except block silenced with pass statement.",
      "fix_hint": "Handle the exception, log with diagnostic context, or propagate upward."
    }
  ]
}
```

### 3. OASIS SARIF v2.1.0 for GitHub Code Scanning

Export findings directly to SARIF and integrate with GitHub Actions (see full workflow at [examples/github-action-sarif.yml](examples/github-action-sarif.yml)):

```bash
corral-lite check src/ --format sarif > results.sarif
```

In your `.github/workflows/ci.yml`:
```yaml
- name: Run Corral-Lite Gate
  run: corral-lite check src/ --format sarif > results.sarif
  continue-on-error: true

- name: Upload SARIF report
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

---

## Pre-Commit Hook

Enforce Corral-Lite verification automatically on commit using [pre-commit](https://pre-commit.com/):

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/NatthaphongY/corral-lite
    rev: v0.4.0
    hooks:
      - id: corral-lite
```

---

## Python API

Integrate Corral-Lite directly into your Python scripts or test harnesses:

```python
from corral_lite import verify_path, Severity

findings = verify_path("src/")
for finding in findings:
    if finding.severity == Severity.BLOCKING:
        print(f"Blocking violation: {finding.rule_id} at {finding.file_path}:{finding.line}")
```

---

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for local development setup, test instructions, and contribution guidelines.

---

## Security

Please review our [SECURITY.md](SECURITY.md) for vulnerability disclosure procedures.

---

## License

This project is licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.
