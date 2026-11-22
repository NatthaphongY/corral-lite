# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] - 2026-11-22

### Added
- Dependency lifecycle rule `DEPS001` (ADVISORY, config/deps): detects `package.json` files defining `preinstall` or `postinstall` lifecycle scripts to safeguard against supply-chain lifecycle risks.
- Discovery and verification support for `package.json` in `verify_file` and `verify_path`.
- Exported `verify_package_json` helper in `corral_lite`.
- Unit tests verifying positive and negative detection of `DEPS001`.

## [0.2.0] - 2026-11-22

### Added
- 6 developer safeguard rules expanding language coverage to Go, TypeScript/JavaScript, and AI agent configuration files (total 16 rules):
  - `PY009`: Deserialization hazards via `pickle.load`/`pickle.loads` or `torch.load` missing `weights_only=True`.
  - `PY010`: Insecure `yaml.load` calls without `SafeLoader` or `CSafeLoader`.
  - `RS003`: Holding lock guards across `.await` points before explicit `drop()` inside `async fn`.
  - `GO001`: Discarded errors via blank identifiers (`_ = err`, `_, _ = ...`, `, _ :=`) in non-test `.go` files.
  - `TS001`: Vacant `catch` blocks (empty or comment-only) in `.ts`, `.tsx`, `.js`, and `.jsx` files.
  - `AGT001`: Hardcoded secret tokens (`sk-`, `ghp_`, `AKIA`) or wildcard execution permissions (`"Bash(*)"`, `"*"`) in `.cursorrules` or `.claude/settings.local.json`.
- Recursive discovery and file verification support for `.go`, `.ts`, `.tsx`, `.js`, `.jsx`, `.cursorrules`, and `settings.local.json`.
- Comprehensive positive and negative test coverage for all new rules in `tests/test_corral_lite.py`.

## [0.1.0] - 2026-11-22

### Added
- Deterministic AST and pattern static verification engine for Python and Rust.
- Zero-dependency rule execution leveraging Python standard library (`ast`, `re`, `json`, `argparse`).
- 8 Python AST verification rules:
  - `PY001`: Bare / broad except blocks silenced with `pass`.
  - `PY002`: Mutable default arguments in function definitions (`[]`, `{}`, `set()`).
  - `PY003`: Dynamic code execution via `eval()` or `exec()`.
  - `PY004`: Wildcard imports (`from module import *`).
  - `PY005`: Unguarded `json.loads` calls outside `try-except`.
  - `PY006`: Insecure `subprocess` executions with `shell=True`.
  - `PY007`: `assert` statements located in non-test production modules.
  - `PY008`: Hardcoded static secret strings in credential variables.
- 2 Rust heuristic verification rules:
  - `RS001`: Unguarded `.unwrap()`, `.expect()`, or `panic!()` in non-test source files.
  - `RS002`: Identical conditional branches across `if` and `else` blocks.
- Multiple report output formats: human-readable CLI text, structured JSON, and OASIS SARIF v2.1.0.
- Command-line interface with `corral-lite check` and `python -m corral_lite.cli check`.
- Programmatic Python API via `from corral_lite import verify_path, Severity, Finding`.
- Full specification alignment with CORRAL Verification Specification (CVS) v1.0.
- PEP 561 type markings (`py.typed`) and standard `src/` layout.
- Comprehensive automated test suite with pytest.
