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

"""Corral-Lite: Deterministic AST and pattern static verification engine."""

__version__ = "0.4.0"

from corral_lite.ast_rules import (
    Finding,
    Rule,
    Severity,
    verify_dockerfile,
    verify_file,
    verify_go_source,
    verify_package_json,
    verify_path,
    verify_python_source,
    verify_rust_source,
    verify_shell_source,
    verify_ts_source,
)

__all__ = [
    "__version__",
    "Finding",
    "Rule",
    "Severity",
    "verify_dockerfile",
    "verify_file",
    "verify_go_source",
    "verify_package_json",
    "verify_path",
    "verify_python_source",
    "verify_rust_source",
    "verify_shell_source",
    "verify_ts_source",
]
