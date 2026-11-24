# AGENTS.md

Instructions and repository contract for autonomous coding agents (Claude Code, Cursor, Cline, Copilot) inspecting or modifying `corral-lite`.

## Repository Architecture

- `src/corral_lite/`: Pure Python package adhering to PEP 561 (`py.typed`).
  - `ast_rules.py`: Deterministic AST and regex pattern verification engine implementing all 19 rules.
  - `cli.py`: Command-line interface with `--format text|json|sarif` support and built-in SARIF v2.1.0 serializer.
- `tests/`: Comprehensive pytest suite (`test_corral_lite.py`).
- `docs/spec/`: Normative specification documentation (`CORRAL_VERIFICATION_SPECIFICATION_v1.md`).

## Non-Negotiable Invariants

1. **Zero External Runtime Dependencies**: Standard library only (`ast`, `re`, `json`, `argparse`, `dataclasses`, `enum`, `pathlib`, `typing`, `sys`). Never add 3rd-party dependencies to `dependencies` in `pyproject.toml`.
2. **Deterministic Exit Codes**:
   - Exit code `0`: Zero blocking findings.
   - Exit code `1`: One or more blocking findings or invalid CLI arguments.
3. **No Bare/Broad Except Pass**: Never catch errors with a bare `except:` or `except Exception:` followed solely by `pass`.
4. **No Unguarded `json.loads`**: Always wrap JSON parsing in a `try...except json.JSONDecodeError` block.
5. **Fail-Closed Verification**: All PRs and modifications must pass pytest 100% and report 0 findings during static verification.

## Verification Gates

Always run the following commands before finalizing any changes:

```bash
# 1. Run unit test suite
py -3.13 -m pytest -v

# 2. Run self-scan with corral-lite CLI
py -3.13 -m corral_lite.cli check src/corral_lite
```
