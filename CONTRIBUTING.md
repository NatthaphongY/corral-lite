# Contributing to Corral-Lite

Thank you for your interest in contributing to **Corral-Lite**! We welcome bug reports, documentation enhancements, test cases, and feature pull requests.

---

## Code of Conduct

All contributors and maintainers are expected to adhere to our [Code of Conduct](CODE_OF_CONDUCT.md). Please read it before participating.

---

## Development Setup

Corral-Lite requires Python 3.10+ and relies strictly on Python standard library modules at runtime (zero external dependencies).

### 1. Fork & Clone

```bash
git clone https://github.com/<your-username>/corral-lite.git
cd corral-lite
git remote add upstream https://github.com/NatthaphongY/corral-lite.git
```

### 2. Set Up Virtual Environment

```bash
# Windows
py -3.13 -m venv .venv
.venv\Scripts\activate

# Linux / macOS
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install in Editable Mode

Install the package in editable mode with development dependencies:

```bash
pip install -e .[dev]
```

---

## Testing & Verification

Before submitting code changes, ensure all tests pass and the self-verification check reports 0 findings.

### Run Unit Tests

```bash
pytest -v
```

### Run Self-Verification

Corral-Lite dogfoods its own static analysis engine against its source code:

```bash
python -m corral_lite.cli check src/corral_lite
```

Expected output:
```
PASS: 0 findings detected across scanned targets.
```

---

## Guidelines for New Rules

When proposing or adding new verification checks:

1. **Deterministic Execution**: Rules must produce 100% predictable, reproducible results across platforms without external network calls or non-deterministic state.
2. **Zero Runtime Dependencies**: The core verification engine must remain free of external dependencies beyond the Python standard library.
3. **Actionable Fix Hints**: Every finding must include a clear, diagnostic `fix_hint` guiding developers toward resolution.
4. **Comprehensive Test Coverage**: Accompany every rule change with positive and negative test cases under `tests/`.

---

## Pull Request Checklist

When opening a Pull Request:

- [ ] Branch from `main` with a descriptive name (e.g., `feat/new-rule-py009` or `fix/cli-sarif-escape`).
- [ ] Add unit tests covering all new behavior or bug fixes.
- [ ] Ensure `pytest -v` passes cleanly.
- [ ] Run `python -m corral_lite.cli check src/corral_lite` to confirm zero violations.
- [ ] Update `CHANGELOG.md` under `[Unreleased]` if applicable.
- [ ] Ensure commit messages follow standard conventional commits (e.g., `feat:`, `fix:`, `docs:`, `chore:`).
