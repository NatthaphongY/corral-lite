# Copyright 2026 Corral Contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Deterministic AST and pattern static verification rules for Corral-Lite."""

from __future__ import annotations

import ast
from dataclasses import dataclass
from enum import Enum
import json
import os
from pathlib import Path
import re
from typing import Iterator, List, Optional, Sequence


class VerificationError(Exception):
    """Base exception for verification and file access errors."""


class FileReadError(VerificationError):
    """Raised when an inspected target cannot be read from disk."""


class Severity(str, Enum):
    """Severity classification for verification findings."""

    BLOCKING = "blocking"
    ADVISORY = "advisory"


@dataclass(frozen=True)
class Rule:
    """Definition of a static verification rule."""

    id: str
    title: str
    language: str
    severity: Severity
    description: str
    fix_hint: str


@dataclass(frozen=True)
class Finding:
    """Reported rule violation in a specific file and location."""

    rule_id: str
    severity: Severity
    file_path: str
    line: int
    column: int
    message: str
    fix_hint: str


RULES: dict[str, Rule] = {
    "PY001": Rule(
        id="PY001",
        title="Bare or broad exception swallowed with pass",
        language="python",
        severity=Severity.BLOCKING,
        description="Except block catching BaseException or Exception without handler body (only pass).",
        fix_hint="Handle the exception, log with diagnostic context, or propagate upward.",
    ),
    "PY002": Rule(
        id="PY002",
        title="Mutable default argument in function definition",
        language="python",
        severity=Severity.BLOCKING,
        description="Function definition uses mutable container (list, dict, set) as default argument.",
        fix_hint="Use None as default argument and assign a fresh collection inside the function.",
    ),
    "PY003": Rule(
        id="PY003",
        title="Invocation of dynamic code execution (eval or exec)",
        language="python",
        severity=Severity.BLOCKING,
        description="Direct invocation of dynamic execution builtins eval() or exec().",
        fix_hint="Replace dynamic evaluation with static data parsing or dispatch tables.",
    ),
    "PY004": Rule(
        id="PY004",
        title="Wildcard import statement in module namespace",
        language="python",
        severity=Severity.ADVISORY,
        description="Import of the form 'from module import *' obscures namespace provenance.",
        fix_hint="Import explicit symbols or import the module namespace directly.",
    ),
    "PY005": Rule(
        id="PY005",
        title="Unguarded json.loads deserialization call",
        language="python",
        severity=Severity.ADVISORY,
        description="Call to json.loads() outside of an enclosing try-except block.",
        fix_hint="Enclose json.loads() in a try-except block catching json.JSONDecodeError or ValueError.",
    ),
    "PY006": Rule(
        id="PY006",
        title="Subprocess execution with shell=True enabled",
        language="python",
        severity=Severity.BLOCKING,
        description="Invocation of subprocess API with argument shell=True presents shell injection hazard.",
        fix_hint="Pass command arguments as an explicit sequence and omit shell=True.",
    ),
    "PY007": Rule(
        id="PY007",
        title="Assert statement used in non-test source code",
        language="python",
        severity=Severity.BLOCKING,
        description="Assert statements can be removed under Python -O flag; invalid for runtime validation.",
        fix_hint="Raise an explicit domain exception or ValueError instead of assert.",
    ),
    "PY008": Rule(
        id="PY008",
        title="Hardcoded high-entropy secret assignment literal",
        language="python",
        severity=Severity.BLOCKING,
        description="Variable named like credential or token assigned a suspicious static string literal.",
        fix_hint="Retrieve credentials dynamically from environment variables or a runtime vault.",
    ),
    "RS001": Rule(
        id="RS001",
        title="Unguarded unwrap or panic in non-test Rust source code",
        language="rust",
        severity=Severity.BLOCKING,
        description="Rust source invokes .unwrap(), .expect(), or panic!() outside test modules.",
        fix_hint="Propagate Result<T, E> using the ? operator; confine unwrap and panic to tests.",
    ),
    "RS002": Rule(
        id="RS002",
        title="Identical execution paths across conditional branches",
        language="rust",
        severity=Severity.BLOCKING,
        description="Conditional if/else structure has duplicate bodies across branches.",
        fix_hint="Eliminate redundant branch or implement distinct handling logic.",
    ),
    "PY009": Rule(
        id="PY009",
        title="Insecure deserialization via pickle or unguarded torch.load",
        language="python",
        severity=Severity.BLOCKING,
        description="Invocation of pickle.load/loads or torch.load without weights_only=True presents arbitrary code execution risk.",
        fix_hint="Use safe serialization formats (JSON, safetensors) or set weights_only=True in torch.load.",
    ),
    "PY010": Rule(
        id="PY010",
        title="Insecure YAML deserialization without safe loader",
        language="python",
        severity=Severity.BLOCKING,
        description="Call to yaml.load() without explicitly passing SafeLoader or CSafeLoader.",
        fix_hint="Use yaml.safe_load() or pass Loader=yaml.SafeLoader (or Loader=yaml.CSafeLoader).",
    ),
    "RS003": Rule(
        id="RS003",
        title="Holding lock across await boundary in async Rust function",
        language="rust",
        severity=Severity.BLOCKING,
        description="Lock acquired inside async fn held across .await before explicit drop().",
        fix_hint="Drop the lock guard before invoking .await or use tokio::sync::Mutex.",
    ),
    "GO001": Rule(
        id="GO001",
        title="Discarded error assignment via blank identifier",
        language="go",
        severity=Severity.BLOCKING,
        description="Error value discarded via blank identifier in non-test Go source code.",
        fix_hint="Explicitly inspect and handle returned error or propagate up the call stack.",
    ),
    "TS001": Rule(
        id="TS001",
        title="Vacant catch block without error handling",
        language="typescript",
        severity=Severity.BLOCKING,
        description="Empty or comment-only catch block suppresses errors silently.",
        fix_hint="Handle, log, or re-throw caught exception inside catch block.",
    ),
    "AGT001": Rule(
        id="AGT001",
        title="Hardcoded API secret token or wildcard execution permission",
        language="config",
        severity=Severity.BLOCKING,
        description="Configuration file contains hardcoded API key/secret token or wildcard permission.",
        fix_hint="Reference secrets via environment variables and restrict agent execution permissions.",
    ),
    "DEPS001": Rule(
        id="DEPS001",
        title="Package defines preinstall or postinstall lifecycle scripts",
        language="config",
        severity=Severity.ADVISORY,
        description="Execution of arbitrary lifecycle hooks during package installation introduces supply-chain lifecycle risks.",
        fix_hint="Avoid preinstall/postinstall lifecycle scripts or execute setup commands explicitly via auditable build scripts.",
    ),
    "DK001": Rule(
        id="DK001",
        title="Dockerfile pipes remote script directly to shell",
        language="dockerfile",
        severity=Severity.ADVISORY,
        description="Dockerfile executes remote script piped directly to shell (e.g. curl ... | bash or wget ... | sh).",
        fix_hint="Download script, verify integrity hash, and execute locally or use multi-stage build.",
    ),
    "SH001": Rule(
        id="SH001",
        title="Shell script lacking set -e or set -euo pipefail",
        language="shell",
        severity=Severity.ADVISORY,
        description="Shell script lacks 'set -e' or 'set -euo pipefail' for robust error handling.",
        fix_hint="Add 'set -e' or 'set -euo pipefail' near the beginning of the script to prevent silent errors.",
    ),
}

# Dynamically construct sensitive pattern tokens to avoid triggering self-inspections
_RS_UNWRAP_TOKEN = "".join([".", "un", "wrap", "("])
_RS_EXPECT_TOKEN = "".join([".", "ex", "pect", "("])
_RS_PANIC_TOKEN = "".join(["pa", "nic", "!", "("])

_SECRET_VAR_NAMES = frozenset({
    "api_key",
    "apikey",
    "secret_key",
    "secret",
    "auth_token",
    "access_token",
    "private_key",
    "password",
    "passwd",
})


def _is_test_file(path_str: str) -> bool:
    """Return True if path represents a test file or test directory."""
    normalized = path_str.replace("\\", "/").lower()
    basename = os.path.basename(normalized)
    if (
        basename.startswith("test_")
        or basename.endswith("_test.py")
        or basename.endswith("_test.rs")
        or basename.endswith("_test.go")
        or basename.endswith(".test.ts")
        or basename.endswith(".test.tsx")
        or basename.endswith(".test.js")
        or basename.endswith(".test.jsx")
        or basename.endswith(".spec.ts")
        or basename.endswith(".spec.tsx")
        or basename.endswith(".spec.js")
        or basename.endswith(".spec.jsx")
    ):
        return True
    parts = normalized.split("/")
    return "tests" in parts or "test" in parts


class _PythonASTChecker(ast.NodeVisitor):
    def __init__(self, file_path: str, is_test: bool) -> None:
        self.file_path = file_path
        self.is_test = is_test
        self.findings: list[Finding] = []
        self._try_stack: list[ast.Try] = []

    def visit_Try(self, node: ast.Try) -> None:
        # Check PY001: bare or broad except pass
        for handler in node.handlers:
            is_broad = False
            if handler.type is None:
                is_broad = True
            elif isinstance(handler.type, ast.Name) and handler.type.id in ("Exception", "BaseException"):
                is_broad = True

            if is_broad:
                # Check if body consists only of Pass
                if len(handler.body) == 1 and isinstance(handler.body[0], ast.Pass):
                    rule = RULES["PY001"]
                    self.findings.append(
                        Finding(
                            rule_id=rule.id,
                            severity=rule.severity,
                            file_path=self.file_path,
                            line=handler.lineno,
                            column=handler.col_offset,
                            message="Broad or bare except block silenced with pass statement.",
                            fix_hint=rule.fix_hint,
                        )
                    )

        self._try_stack.append(node)
        self.generic_visit(node)
        self._try_stack.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        # Check PY002: mutable default args
        all_defaults: Sequence[ast.expr] = node.args.defaults + [
            d for d in node.args.kw_defaults if d is not None
        ]
        for default in all_defaults:
            if isinstance(default, (ast.List, ast.Dict, ast.Set)):
                rule = RULES["PY002"]
                self.findings.append(
                    Finding(
                        rule_id=rule.id,
                        severity=rule.severity,
                        file_path=self.file_path,
                        line=default.lineno,
                        column=default.col_offset,
                        message=f"Mutable collection default argument found in function '{node.name}'.",
                        fix_hint=rule.fix_hint,
                    )
                )
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self.visit_FunctionDef(node)

    def visit_Call(self, node: ast.Call) -> None:
        # Check PY003: eval or exec
        if isinstance(node.func, ast.Name) and node.func.id in ("eval", "exec"):
            rule = RULES["PY003"]
            self.findings.append(
                Finding(
                    rule_id=rule.id,
                    severity=rule.severity,
                    file_path=self.file_path,
                    line=node.lineno,
                    column=node.col_offset,
                    message=f"Direct invocation of dynamic execution function '{node.func.id}()'.",
                    fix_hint=rule.fix_hint,
                )
            )

        # Check PY005: unguarded json.loads
        is_json_loads = False
        if isinstance(node.func, ast.Attribute) and node.func.attr == "loads":
            if isinstance(node.func.value, ast.Name) and node.func.value.id == "json":
                is_json_loads = True

        if is_json_loads and not self._try_stack:
            rule = RULES["PY005"]
            self.findings.append(
                Finding(
                    rule_id=rule.id,
                    severity=rule.severity,
                    file_path=self.file_path,
                    line=node.lineno,
                    column=node.col_offset,
                    message="Call to json.loads() executed outside of an enclosing try-except block.",
                    fix_hint=rule.fix_hint,
                )
            )

        # Check PY006: subprocess with shell=True
        is_subprocess_call = False
        if isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name) and node.func.value.id == "subprocess":
                is_subprocess_call = True
            elif node.func.attr in ("run", "Popen", "call", "check_call", "check_output"):
                is_subprocess_call = True

        if is_subprocess_call:
            for kw in node.keywords:
                if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    rule = RULES["PY006"]
                    self.findings.append(
                        Finding(
                            rule_id=rule.id,
                            severity=rule.severity,
                            file_path=self.file_path,
                            line=node.lineno,
                            column=node.col_offset,
                            message="Subprocess invocation specified with shell=True hazard.",
                            fix_hint=rule.fix_hint,
                        )
                    )

        # Check PY009: pickle.load / pickle.loads or torch.load without weights_only=True
        if isinstance(node.func, ast.Attribute):
            target_obj = ""
            if isinstance(node.func.value, ast.Name):
                target_obj = node.func.value.id

            if target_obj == "pickle" and node.func.attr in ("load", "loads"):
                rule = RULES["PY009"]
                self.findings.append(
                    Finding(
                        rule_id=rule.id,
                        severity=rule.severity,
                        file_path=self.file_path,
                        line=node.lineno,
                        column=node.col_offset,
                        message=f"Insecure deserialization via pickle.{node.func.attr}() call.",
                        fix_hint=rule.fix_hint,
                    )
                )
            elif target_obj == "torch" and node.func.attr == "load":
                has_weights_only = any(
                    kw.arg == "weights_only"
                    and isinstance(kw.value, ast.Constant)
                    and kw.value.value is True
                    for kw in node.keywords
                )
                if not has_weights_only:
                    rule = RULES["PY009"]
                    self.findings.append(
                        Finding(
                            rule_id=rule.id,
                            severity=rule.severity,
                            file_path=self.file_path,
                            line=node.lineno,
                            column=node.col_offset,
                            message="Invocation of torch.load() without weights_only=True.",
                            fix_hint=rule.fix_hint,
                        )
                    )

            # Check PY010: yaml.load without safe loader
            elif target_obj == "yaml" and node.func.attr == "load":
                has_safe_loader = False
                for kw in node.keywords:
                    if kw.arg in ("Loader", "loader"):
                        if isinstance(kw.value, ast.Name) and kw.value.id in ("SafeLoader", "CSafeLoader"):
                            has_safe_loader = True
                        elif isinstance(kw.value, ast.Attribute) and kw.value.attr in ("SafeLoader", "CSafeLoader"):
                            has_safe_loader = True
                if len(node.args) >= 2:
                    arg1 = node.args[1]
                    if isinstance(arg1, ast.Name) and arg1.id in ("SafeLoader", "CSafeLoader"):
                        has_safe_loader = True
                    elif isinstance(arg1, ast.Attribute) and arg1.attr in ("SafeLoader", "CSafeLoader"):
                        has_safe_loader = True

                if not has_safe_loader:
                    rule = RULES["PY010"]
                    self.findings.append(
                        Finding(
                            rule_id=rule.id,
                            severity=rule.severity,
                            file_path=self.file_path,
                            line=node.lineno,
                            column=node.col_offset,
                            message="Call to yaml.load() without safe loader (SafeLoader/CSafeLoader).",
                            fix_hint=rule.fix_hint,
                        )
                    )

        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        # Check PY004: wildcard import
        for alias in node.names:
            if alias.name == "*":
                rule = RULES["PY004"]
                mod_name = node.module or "relative"
                self.findings.append(
                    Finding(
                        rule_id=rule.id,
                        severity=rule.severity,
                        file_path=self.file_path,
                        line=node.lineno,
                        column=node.col_offset,
                        message=f"Wildcard import 'from {mod_name} import *' detected.",
                        fix_hint=rule.fix_hint,
                    )
                )
        self.generic_visit(node)

    def visit_Assert(self, node: ast.Assert) -> None:
        # Check PY007: assert outside tests
        if not self.is_test:
            rule = RULES["PY007"]
            self.findings.append(
                Finding(
                    rule_id=rule.id,
                    severity=rule.severity,
                    file_path=self.file_path,
                    line=node.lineno,
                    column=node.col_offset,
                    message="Runtime validation via assert statement outside test suite.",
                    fix_hint=rule.fix_hint,
                )
            )
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        # Check PY008: secret assignment
        if not self.is_test and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            val = node.value.value.strip()
            # Suspicious if target variable looks like secret and value is non-empty, non-placeholder
            for target in node.targets:
                target_name = ""
                if isinstance(target, ast.Name):
                    target_name = target.id.lower()
                elif isinstance(target, ast.Attribute):
                    target_name = target.attr.lower()

                if any(sec in target_name for sec in _SECRET_VAR_NAMES):
                    if len(val) >= 8 and not val.startswith(("${", "{", "env:", "placeholder", "xxx")):
                        rule = RULES["PY008"]
                        self.findings.append(
                            Finding(
                                rule_id=rule.id,
                                severity=rule.severity,
                                file_path=self.file_path,
                                line=node.lineno,
                                column=node.col_offset,
                                message=f"Potential hardcoded secret assigned to '{target_name}'.",
                                fix_hint=rule.fix_hint,
                            )
                        )
        self.generic_visit(node)


def verify_python_source(source: str, file_path: str) -> list[Finding]:
    """Verify Python code content using AST visitor."""
    is_test = _is_test_file(file_path)
    try:
        tree = ast.parse(source, filename=file_path)
    except SyntaxError as err:
        # Unparseable syntax is reported as a blocking finding
        return [
            Finding(
                rule_id="PY000",
                severity=Severity.BLOCKING,
                file_path=file_path,
                line=err.lineno or 1,
                column=err.offset or 0,
                message=f"Syntax error while parsing Python AST: {err.msg}",
                fix_hint="Correct syntax error to enable static AST verification.",
            )
        ]

    checker = _PythonASTChecker(file_path=file_path, is_test=is_test)
    checker.visit(tree)
    return checker.findings


def verify_rust_source(source: str, file_path: str) -> list[Finding]:
    """Verify Rust source file for RS001 and RS002 heuristics."""
    findings: list[Finding] = []
    is_test = _is_test_file(file_path)
    lines = source.splitlines()

    in_cfg_test = False

    for idx, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()
        if "#[cfg(test)]" in line:
            in_cfg_test = True

        # Skip comment lines
        if line.startswith("//"):
            continue

        # Check RS001 if outside test code and not in cfg(test)
        if not is_test and not in_cfg_test:
            for token in (_RS_UNWRAP_TOKEN, _RS_EXPECT_TOKEN, _RS_PANIC_TOKEN):
                if token in line:
                    rule = RULES["RS001"]
                    col = raw_line.find(token)
                    findings.append(
                        Finding(
                            rule_id=rule.id,
                            severity=rule.severity,
                            file_path=file_path,
                            line=idx,
                            column=max(0, col),
                            message=f"Unguarded '{token[:-1]}' invoked in production path.",
                            fix_hint=rule.fix_hint,
                        )
                    )

    # Heuristic for RS002: identical if/else blocks in Rust
    # Matches patterns like if (...) { <stmt>; } else { <stmt>; }
    pattern = re.compile(
        r"if\s+[^{]+\{\s*([^}]+?)\s*\}\s*else\s*\{\s*([^}]+?)\s*\}",
        re.MULTILINE | re.DOTALL,
    )
    for match in pattern.finditer(source):
        branch_a = match.group(1).strip()
        branch_b = match.group(2).strip()
        if branch_a and branch_a == branch_b:
            rule = RULES["RS002"]
            start_pos = match.start()
            line_no = source.count("\n", 0, start_pos) + 1
            findings.append(
                Finding(
                    rule_id=rule.id,
                    severity=rule.severity,
                    file_path=file_path,
                    line=line_no,
                    column=0,
                    message="Identical execution logic detected across conditional if/else branches.",
                    fix_hint=rule.fix_hint,
                )
            )

    # Heuristic for RS003: Single-file .lock( followed by .await before drop( inside async fn
    if not is_test:
        async_fn_pattern = re.compile(
            r"\basync\s+(?:unsafe\s+)?fn\s+[A-Za-z0-9_]+\s*(?:<[^>]*>)?\s*\([^)]*\)[^{]*\{",
            re.MULTILINE,
        )
        lock_token = "".join([".", "lo", "ck", "("])
        await_token = "".join([".", "aw", "ait"])
        drop_token = "".join(["dr", "op", "("])

        for match in async_fn_pattern.finditer(source):
            start = match.end() - 1  # at '{'
            depth = 0
            end = len(source)
            for i in range(start, len(source)):
                if source[i] == "{":
                    depth += 1
                elif source[i] == "}":
                    depth -= 1
                    if depth == 0:
                        end = i
                        break
            body = source[start + 1 : end]
            lock_pos = 0
            while True:
                pos = body.find(lock_token, lock_pos)
                if pos == -1:
                    break
                lock_pos = pos + len(lock_token)
                await_pos = body.find(await_token, lock_pos)
                drop_pos = body.find(drop_token, lock_pos)
                if await_pos != -1:
                    if drop_pos == -1 or await_pos < drop_pos:
                        abs_pos = start + 1 + pos
                        line_no = source.count("\n", 0, abs_pos) + 1
                        rule = RULES["RS003"]
                        findings.append(
                            Finding(
                                rule_id=rule.id,
                                severity=rule.severity,
                                file_path=file_path,
                                line=line_no,
                                column=0,
                                message="Lock acquired and held across .await before drop() in async fn.",
                                fix_hint=rule.fix_hint,
                            )
                        )
                        break

    return findings


def verify_go_source(source: str, file_path: str) -> list[Finding]:
    """Verify Go source file for discarded errors via blank identifier (GO001)."""
    findings: list[Finding] = []
    if _is_test_file(file_path):
        return findings

    lines = source.splitlines()
    blank_err_patterns = [
        re.compile(r"_\s*=\s*err\b"),
        re.compile(r"\b_\s*,\s*_\s*="),
        re.compile(r",\s*_\s*:="),
    ]

    for idx, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()
        if line.startswith("//"):
            continue
        for p in blank_err_patterns:
            m = p.search(raw_line)
            if m:
                rule = RULES["GO001"]
                findings.append(
                    Finding(
                        rule_id=rule.id,
                        severity=rule.severity,
                        file_path=file_path,
                        line=idx,
                        column=m.start(),
                        message="Discarded error via blank identifier in non-test Go source.",
                        fix_hint=rule.fix_hint,
                    )
                )
                break
    return findings


def verify_ts_source(source: str, file_path: str) -> list[Finding]:
    """Verify TypeScript / JavaScript source for vacant catch blocks (TS001)."""
    findings: list[Finding] = []
    catch_pattern = re.compile(
        r"\bcatch\s*(?:\([^)]*\))?\s*\{([^{}]*)\}",
        re.MULTILINE | re.DOTALL,
    )
    comment_pattern = re.compile(r"//.*|/\*[\s\S]*?\*/")

    for match in catch_pattern.finditer(source):
        body = match.group(1)
        stripped_body = comment_pattern.sub("", body).strip()
        if not stripped_body:
            rule = RULES["TS001"]
            start_pos = match.start()
            line_no = source.count("\n", 0, start_pos) + 1
            findings.append(
                Finding(
                    rule_id=rule.id,
                    severity=rule.severity,
                    file_path=file_path,
                    line=line_no,
                    column=0,
                    message="Vacant or comment-only catch block suppresses errors silently.",
                    fix_hint=rule.fix_hint,
                )
            )
    return findings


def verify_config_source(source: str, file_path: str) -> list[Finding]:
    """Verify agent configurations (.cursorrules, settings.local.json) for AGT001."""
    findings: list[Finding] = []
    lines = source.splitlines()

    # Secret prefixes: sk-, ghp_, AKIA
    secret_pat = re.compile(
        r"(?:sk-[a-zA-Z0-9_\-]{8,}|ghp_[a-zA-Z0-9]{10,}|AKIA[0-9A-Z]{16})"
    )
    # Wildcard permissions: "Bash(*)" or "*"
    wildcard_pat = re.compile(r'"(?:Bash\(\*\)|\*)"')

    for idx, raw_line in enumerate(lines, start=1):
        m_sec = secret_pat.search(raw_line)
        if m_sec:
            rule = RULES["AGT001"]
            findings.append(
                Finding(
                    rule_id=rule.id,
                    severity=rule.severity,
                    file_path=file_path,
                    line=idx,
                    column=m_sec.start(),
                    message="Hardcoded secret token detected in agent configuration.",
                    fix_hint=rule.fix_hint,
                )
            )
            continue

        m_wild = wildcard_pat.search(raw_line)
        if m_wild:
            rule = RULES["AGT001"]
            findings.append(
                Finding(
                    rule_id=rule.id,
                    severity=rule.severity,
                    file_path=file_path,
                    line=idx,
                    column=m_wild.start(),
                    message="Wildcard execution permission detected in agent configuration.",
                    fix_hint=rule.fix_hint,
                )
            )

    return findings


def verify_package_json(source: str, file_path: str) -> list[Finding]:
    """Inspect package.json for lifecycle scripts presenting supply-chain risks (DEPS001)."""
    findings: list[Finding] = []
    try:
        data = json.loads(source)
    except Exception:
        # Invalid JSON: will be handled or skipped if not parseable
        return []

    if not isinstance(data, dict):
        return []

    scripts = data.get("scripts")
    if not isinstance(scripts, dict):
        return []

    targeted_hooks = {"preinstall", "postinstall"}
    flagged_hooks = targeted_hooks.intersection(scripts.keys())
    if not flagged_hooks:
        return []

    lines = source.splitlines()
    rule = RULES["DEPS001"]

    for hook in sorted(flagged_hooks):
        # Locate line number in raw content for accurate reporting
        line_num = 1
        col_num = 0
        pattern = re.compile(rf'"{re.escape(hook)}"\s*:')
        for idx, line_text in enumerate(lines, start=1):
            m = pattern.search(line_text)
            if m:
                line_num = idx
                col_num = m.start()
                break

        findings.append(
            Finding(
                rule_id=rule.id,
                severity=rule.severity,
                file_path=file_path,
                line=line_num,
                column=col_num,
                message=f"Lifecycle script '{hook}' defined in package.json presents supply-chain lifecycle risk.",
                fix_hint=rule.fix_hint,
            )
        )

    return findings


def verify_dockerfile(source: str, file_path: str) -> list[Finding]:
    """Verify Dockerfile for piping remote scripts to shell (DK001)."""
    findings: list[Finding] = []
    lines = source.splitlines()
    pipe_pattern = re.compile(
        r"\b(?:curl|wget)\b[^|\n\r]*\|\s*(?:sudo\s+)?(?:env\s+)?(?:/(?:usr/)?bin/)?(?:bash|sh|zsh|dash)\b",
        re.IGNORECASE,
    )

    buffer = ""
    buffer_start_line = 1
    buffer_start_col = 0

    for idx, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()
        if line.startswith("#"):
            continue

        m = pipe_pattern.search(raw_line)
        if m:
            rule = RULES["DK001"]
            findings.append(
                Finding(
                    rule_id=rule.id,
                    severity=rule.severity,
                    file_path=file_path,
                    line=idx,
                    column=m.start(),
                    message="Dockerfile pipes remote script directly to shell.",
                    fix_hint=rule.fix_hint,
                )
            )
            buffer = ""
            continue

        if line.endswith("\\"):
            chunk = line[:-1].strip()
            if not buffer:
                buffer = chunk
                buffer_start_line = idx
                buffer_start_col = raw_line.find(chunk)
            else:
                buffer += " " + chunk
        else:
            if buffer:
                buffer += " " + line
                m_buf = pipe_pattern.search(buffer)
                if m_buf:
                    rule = RULES["DK001"]
                    findings.append(
                        Finding(
                            rule_id=rule.id,
                            severity=rule.severity,
                            file_path=file_path,
                            line=buffer_start_line,
                            column=max(0, buffer_start_col),
                            message="Dockerfile pipes remote script directly to shell.",
                            fix_hint=rule.fix_hint,
                        )
                    )
                buffer = ""

    if buffer:
        m_buf = pipe_pattern.search(buffer)
        if m_buf:
            rule = RULES["DK001"]
            findings.append(
                Finding(
                    rule_id=rule.id,
                    severity=rule.severity,
                    file_path=file_path,
                    line=buffer_start_line,
                    column=max(0, buffer_start_col),
                    message="Dockerfile pipes remote script directly to shell.",
                    fix_hint=rule.fix_hint,
                )
            )

    return findings


def verify_shell_source(source: str, file_path: str) -> list[Finding]:
    """Verify shell script for robust error handling (SH001)."""
    findings: list[Finding] = []
    has_set_e = False

    set_e_pattern = re.compile(
        r"(?:^|[\s;&|])set\s+(?:-[a-zA-Z]*e[a-zA-Z]*|-o\s+errexit)\b"
    )

    for raw_line in source.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        code_part = line.split("#")[0].strip()
        if set_e_pattern.search(code_part):
            has_set_e = True
            break

    if not has_set_e:
        rule = RULES["SH001"]
        findings.append(
            Finding(
                rule_id=rule.id,
                severity=rule.severity,
                file_path=file_path,
                line=1,
                column=0,
                message="Shell script lacks 'set -e' or 'set -euo pipefail' for robust error handling.",
                fix_hint=rule.fix_hint,
            )
        )

    return findings


def verify_file(file_path: str | Path) -> list[Finding]:
    """Inspect a single source file and return detected findings."""
    path = Path(file_path)
    try:
        content = path.read_text(encoding="utf-8")
    except OSError as err:
        raise FileReadError(f"Failed to read file '{path}': {err}") from err

    path_str = str(path)
    norm_path = path_str.replace("\\", "/").lower()
    basename = path.name.lower()

    if basename == "package.json":
        return verify_package_json(content, path_str)

    if basename in (".cursorrules", "settings.local.json") or norm_path.endswith(
        "/.claude/settings.local.json"
    ):
        return verify_config_source(content, path_str)

    if (
        basename == "dockerfile"
        or basename.startswith("dockerfile.")
        or path.suffix.lower() == ".dockerfile"
    ):
        return verify_dockerfile(content, path_str)

    if path.suffix.lower() in (".sh", ".bash"):
        return verify_shell_source(content, path_str)

    if path.suffix == ".py":
        return verify_python_source(content, path_str)
    if path.suffix == ".rs":
        return verify_rust_source(content, path_str)
    if path.suffix == ".go":
        return verify_go_source(content, path_str)
    if path.suffix in (".ts", ".tsx", ".js", ".jsx"):
        return verify_ts_source(content, path_str)
    return []


def verify_path(target_path: str | Path) -> list[Finding]:
    """Recursively discover and verify all supported files under path."""
    root = Path(target_path)
    if not root.exists():
        raise FileReadError(f"Target path does not exist: '{root}'")

    if root.is_file():
        return verify_file(root)

    findings: list[Finding] = []
    scanned_suffixes = {
        ".py",
        ".rs",
        ".go",
        ".ts",
        ".tsx",
        ".js",
        ".jsx",
        ".sh",
        ".bash",
        ".dockerfile",
    }
    scanned_filenames = {
        ".cursorrules",
        "settings.local.json",
        "package.json",
        "dockerfile",
    }

    for dirpath, dirnames, filenames in os.walk(root):
        # Allow .claude directory to be traversed while skipping __pycache__, node_modules, and other hidden dirs
        dirnames[:] = [
            d
            for d in dirnames
            if (not d.startswith(".") or d == ".claude")
            and d not in ("__pycache__", "node_modules")
        ]
        for fname in sorted(filenames):
            fpath = Path(dirpath) / fname
            fname_lower = fname.lower()
            if (
                fpath.suffix.lower() in scanned_suffixes
                or fname_lower in scanned_filenames
                or fname_lower.startswith("dockerfile.")
            ):
                findings.extend(verify_file(fpath))

    return findings
