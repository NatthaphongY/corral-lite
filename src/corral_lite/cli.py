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

"""Command-line interface for Corral-Lite static verification engine."""

from __future__ import annotations

import argparse
import io
import json
import logging
import sys
from typing import Any, Sequence

from corral_lite.ast_rules import Finding, RULES, Severity, VerificationError, verify_path

LOGGER = logging.getLogger("corral_lite.cli")

# Ensure safe UTF-8 encoding across environments
if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")

if sys.stderr.encoding and sys.stderr.encoding.lower() != "utf-8":
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8")


def _format_text(findings: list[Finding]) -> str:
    """Render findings into human-readable text."""
    if not findings:
        return "PASS: 0 findings detected across scanned targets.\n"

    lines: list[str] = []
    lines.append(f"Scanned targets reported {len(findings)} finding(s):")
    for f in findings:
        tag = "ERROR" if f.severity == Severity.BLOCKING else "WARN"
        lines.append(
            f"[{tag}] {f.rule_id} at {f.file_path}:{f.line}:{f.column} - {f.message}"
        )
        lines.append(f"  Fix hint: {f.fix_hint}")
    return "\n".join(lines) + "\n"


def _format_json(findings: list[Finding]) -> str:
    """Render findings as a structured JSON document."""
    items = [
        {
            "rule_id": f.rule_id,
            "severity": f.severity.value,
            "file_path": f.file_path,
            "line": f.line,
            "column": f.column,
            "message": f.message,
            "fix_hint": f.fix_hint,
        }
        for f in findings
    ]
    blocking_count = sum(1 for f in findings if f.severity == Severity.BLOCKING)
    payload = {
        "verdict": "PASSED" if blocking_count == 0 else "FAILED",
        "findings_count": len(findings),
        "blocking_count": blocking_count,
        "findings": items,
    }
    return json.dumps(payload, indent=2, ensure_ascii=False) + "\n"


def _format_sarif(findings: list[Finding]) -> str:
    """Render findings as a standard SARIF v2.1.0 document."""
    rules_table: list[dict[str, Any]] = []
    seen_rules = set()

    for rule_id, r in RULES.items():
        if rule_id not in seen_rules:
            seen_rules.add(rule_id)
            level = "error" if r.severity == Severity.BLOCKING else "warning"
            rules_table.append(
                {
                    "id": r.id,
                    "name": r.title,
                    "shortDescription": {"text": r.title},
                    "fullDescription": {"text": r.description},
                    "defaultConfiguration": {"level": level},
                    "help": {"text": r.fix_hint},
                }
            )

    results: list[dict[str, Any]] = []
    for f in findings:
        level = "error" if f.severity == Severity.BLOCKING else "warning"
        norm_path = f.file_path.replace("\\", "/")
        results.append(
            {
                "ruleId": f.rule_id,
                "level": level,
                "message": {"text": f.message},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": norm_path},
                            "region": {
                                "startLine": f.line,
                                "startColumn": f.column + 1,
                            },
                        }
                    }
                ],
            }
        )

    sarif_data = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "corral-lite",
                        "version": "0.3.0",
                        "informationUri": "https://github.com/NatthaphongY/corral-lite",
                        "rules": rules_table,
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(sarif_data, indent=2, ensure_ascii=False) + "\n"


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entry point for corral-lite."""
    parser = argparse.ArgumentParser(
        prog="corral-lite",
        description="Deterministic AST and pattern static verification engine.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    check_parser = subparsers.add_parser("check", help="Verify a target file or directory")
    check_parser.add_argument("path", help="Target source file or root directory to scan")
    check_parser.add_argument(
        "--format",
        choices=["text", "json", "sarif"],
        default="text",
        help="Diagnostic output format (default: text)",
    )

    args = parser.parse_args(argv)

    if args.command == "check":
        try:
            findings = verify_path(args.path)
        except VerificationError as err:
            LOGGER.error("Failed verification scan: %s", err)
            sys.stderr.write(f"Error during verification: {err}\n")
            return 2
        except Exception as err:
            LOGGER.error("Unexpected error in verification: %s", err)
            sys.stderr.write(f"Unexpected error: {err}\n")
            return 2

        if args.format == "json":
            output = _format_json(findings)
        elif args.format == "sarif":
            output = _format_sarif(findings)
        else:
            output = _format_text(findings)

        sys.stdout.write(output)

        has_blocking = any(f.severity == Severity.BLOCKING for f in findings)
        return 1 if has_blocking else 0

    return 0


if __name__ == "__main__":
    sys.exit(main())
