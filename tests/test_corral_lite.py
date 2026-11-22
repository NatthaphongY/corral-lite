"""Comprehensive test suite for Corral-Lite static verification engine."""

from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys

import pytest

from corral_lite.ast_rules import (
    FileReadError,
    RULES,
    Severity,
    verify_config_source,
    verify_file,
    verify_go_source,
    verify_package_json,
    verify_path,
    verify_python_source,
    verify_rust_source,
    verify_ts_source,
)
from corral_lite.cli import main


def test_rules_catalogue_definition():
    """Verify that all 16 expected rules are registered with proper metadata."""
    expected_rule_ids = {
        "PY001",
        "PY002",
        "PY003",
        "PY004",
        "PY005",
        "PY006",
        "PY007",
        "PY008",
        "RS001",
        "RS002",
        "PY009",
        "PY010",
        "RS003",
        "GO001",
        "TS001",
        "AGT001",
        "DEPS001",
    }
    assert set(RULES.keys()) == expected_rule_ids
    for rule_id in expected_rule_ids:
        rule = RULES[rule_id]
        assert rule.id == rule_id
        assert rule.title
        assert rule.description
        assert rule.fix_hint
        assert rule.severity in (Severity.BLOCKING, Severity.ADVISORY)


def test_py001_bare_or_broad_except_pass():
    code_bad = (
        "try:\n"
        "    x = 1\n"
        "except:\n"
        "    pass\n"
    )
    findings = verify_python_source(code_bad, "src/worker.py")
    assert any(f.rule_id == "PY001" and f.severity == Severity.BLOCKING for f in findings)

    code_broad = (
        "try:\n"
        "    x = 1\n"
        "except Exception:\n"
        "    pass\n"
    )
    findings_broad = verify_python_source(code_broad, "src/worker.py")
    assert any(f.rule_id == "PY001" for f in findings_broad)

    code_good = (
        "import logging\n"
        "try:\n"
        "    x = 1\n"
        "except Exception as err:\n"
        "    logging.error('failed: %s', err)\n"
    )
    findings_good = verify_python_source(code_good, "src/worker.py")
    assert not any(f.rule_id == "PY001" for f in findings_good)


def test_py002_mutable_default_args():
    code_bad = "def process(items=[]):\n    items.append(1)\n"
    findings = verify_python_source(code_bad, "src/worker.py")
    assert any(f.rule_id == "PY002" for f in findings)

    code_dict = "def build(cfg={}):\n    return cfg\n"
    findings_dict = verify_python_source(code_dict, "src/worker.py")
    assert any(f.rule_id == "PY002" for f in findings_dict)

    code_good = "def process(items=None):\n    target = items or []\n    return target\n"
    findings_good = verify_python_source(code_good, "src/worker.py")
    assert not any(f.rule_id == "PY002" for f in findings_good)


def test_py003_eval_exec():
    code_eval = "eval('1 + 1')"
    findings = verify_python_source(code_eval, "src/worker.py")
    assert any(f.rule_id == "PY003" for f in findings)

    code_exec = "exec('x = 2')"
    findings_exec = verify_python_source(code_exec, "src/worker.py")
    assert any(f.rule_id == "PY003" for f in findings_exec)


def test_py004_wildcard_import():
    code_wildcard = "from math import *"
    findings = verify_python_source(code_wildcard, "src/worker.py")
    assert any(f.rule_id == "PY004" and f.severity == Severity.ADVISORY for f in findings)

    code_explicit = "from math import sqrt"
    findings_good = verify_python_source(code_explicit, "src/worker.py")
    assert not any(f.rule_id == "PY004" for f in findings_good)


def test_py005_unguarded_json_loads():
    code_bad = "import json\ndata = json.loads('{}')"
    findings = verify_python_source(code_bad, "src/worker.py")
    assert any(f.rule_id == "PY005" and f.severity == Severity.ADVISORY for f in findings)

    code_guarded = (
        "import json\n"
        "try:\n"
        "    data = json.loads('{}')\n"
        "except ValueError:\n"
        "    data = {}\n"
    )
    findings_good = verify_python_source(code_guarded, "src/worker.py")
    assert not any(f.rule_id == "PY005" for f in findings_good)


def test_py006_subprocess_shell_true():
    code_bad = "import subprocess\nsubprocess.run('ls', shell=True)"
    findings = verify_python_source(code_bad, "src/worker.py")
    assert any(f.rule_id == "PY006" for f in findings)

    code_good = "import subprocess\nsubprocess.run(['ls', '-la'], check=True)"
    findings_good = verify_python_source(code_good, "src/worker.py")
    assert not any(f.rule_id == "PY006" for f in findings_good)


def test_py007_assert_in_non_test():
    code_prod = "assert 1 == 1"
    findings_prod = verify_python_source(code_prod, "src/worker.py")
    assert any(f.rule_id == "PY007" for f in findings_prod)

    # In test files, assert is permitted
    findings_test = verify_python_source(code_prod, "tests/test_worker.py")
    assert not any(f.rule_id == "PY007" for f in findings_test)


def test_py008_hardcoded_secret():
    # Construct target assignment string dynamically so scanner does not flag test file
    var_name = "api_" + "key"
    secret_val = "abcdef" + "1234567890"
    code_bad = f"{var_name} = '{secret_val}'"
    findings = verify_python_source(code_bad, "src/worker.py")
    assert any(f.rule_id == "PY008" for f in findings)

    code_env = f"import os\n{var_name} = os.environ.get('API_KEY')"
    findings_good = verify_python_source(code_env, "src/worker.py")
    assert not any(f.rule_id == "PY008" for f in findings_good)


def test_rs001_unguarded_unwrap_panic():
    code_bad = (
        "fn calculate() -> i32 {\n"
        "    let x: Option<i32> = None;\n"
        "    x.unwrap()\n"
        "}\n"
    )
    findings = verify_rust_source(code_bad, "src/main.rs")
    assert any(f.rule_id == "RS001" for f in findings)

    # In test files, unwrap is permitted
    findings_test = verify_rust_source(code_bad, "tests/test_main.rs")
    assert not any(f.rule_id == "RS001" for f in findings_test)

    # Inside #[cfg(test)], unwrap is permitted
    code_cfg_test = (
        "#[cfg(test)]\n"
        "mod tests {\n"
        "    fn run_test() {\n"
        "        let val = Some(1).unwrap();\n"
        "    }\n"
        "}\n"
    )
    findings_cfg = verify_rust_source(code_cfg_test, "src/lib.rs")
    assert not any(f.rule_id == "RS001" for f in findings_cfg)


def test_rs002_identical_branches():
    code_bad = (
        "fn check(cond: bool) -> i32 {\n"
        "    if cond {\n"
        "        return 1;\n"
        "    } else {\n"
        "        return 1;\n"
        "    }\n"
        "}\n"
    )
    findings = verify_rust_source(code_bad, "src/main.rs")
    assert any(f.rule_id == "RS002" for f in findings)

    code_good = (
        "fn check(cond: bool) -> i32 {\n"
        "    if cond {\n"
        "        return 1;\n"
        "    } else {\n"
        "        return 2;\n"
        "    }\n"
        "}\n"
    )
    findings_good = verify_rust_source(code_good, "src/main.rs")
    assert not any(f.rule_id == "RS002" for f in findings_good)


def test_py009_pickle_and_torch():
    code_bad_pickle_load = "import pickle\nwith open('data.pkl', 'rb') as f:\n    pickle.load(f)\n"
    f_pkl = verify_python_source(code_bad_pickle_load, "src/loader.py")
    assert any(f.rule_id == "PY009" and f.severity == Severity.BLOCKING for f in f_pkl)

    code_bad_pickle_loads = "import pickle\npickle.loads(b'data')\n"
    f_pkls = verify_python_source(code_bad_pickle_loads, "src/loader.py")
    assert any(f.rule_id == "PY009" for f in f_pkls)

    code_bad_torch = "import torch\nmodel = torch.load('model.pt')\n"
    f_torch_bad = verify_python_source(code_bad_torch, "src/model.py")
    assert any(f.rule_id == "PY009" for f in f_torch_bad)

    code_bad_torch_false = "import torch\nmodel = torch.load('model.pt', weights_only=False)\n"
    f_torch_false = verify_python_source(code_bad_torch_false, "src/model.py")
    assert any(f.rule_id == "PY009" for f in f_torch_false)

    code_good_torch = "import torch\nmodel = torch.load('model.pt', weights_only=True)\n"
    f_torch_good = verify_python_source(code_good_torch, "src/model.py")
    assert not any(f.rule_id == "PY009" for f in f_torch_good)


def test_py010_yaml_safe_loader():
    code_bad_yaml = "import yaml\nwith open('config.yml') as f:\n    cfg = yaml.load(f)\n"
    f_bad = verify_python_source(code_bad_yaml, "src/config.py")
    assert any(f.rule_id == "PY010" and f.severity == Severity.BLOCKING for f in f_bad)

    code_bad_yaml_unsafe = "import yaml\ncfg = yaml.load(stream, Loader=yaml.Loader)\n"
    f_unsafe = verify_python_source(code_bad_yaml_unsafe, "src/config.py")
    assert any(f.rule_id == "PY010" for f in f_unsafe)

    code_good_safe_loader = "import yaml\ncfg = yaml.load(stream, Loader=yaml.SafeLoader)\n"
    f_good1 = verify_python_source(code_good_safe_loader, "src/config.py")
    assert not any(f.rule_id == "PY010" for f in f_good1)

    code_good_csafe_loader = "import yaml\nfrom yaml import CSafeLoader\ncfg = yaml.load(stream, Loader=CSafeLoader)\n"
    f_good2 = verify_python_source(code_good_csafe_loader, "src/config.py")
    assert not any(f.rule_id == "PY010" for f in f_good2)

    code_good_safe_load = "import yaml\ncfg = yaml.safe_load(stream)\n"
    f_good3 = verify_python_source(code_good_safe_load, "src/config.py")
    assert not any(f.rule_id == "PY010" for f in f_good3)


def test_rs003_lock_across_await():
    code_bad = (
        "async fn handle_conn() -> Result<(), Error> {\n"
        "    let guard = state.lock();\n"
        "    async_op().await;\n"
        "    drop(guard);\n"
        "    Ok(())\n"
        "}\n"
    )
    f_bad = verify_rust_source(code_bad, "src/handler.rs")
    assert any(f.rule_id == "RS003" and f.severity == Severity.BLOCKING for f in f_bad)

    code_bad_no_drop = (
        "async fn handle_conn() {\n"
        "    let guard = state.lock();\n"
        "    async_op().await;\n"
        "}\n"
    )
    f_bad_no_drop = verify_rust_source(code_bad_no_drop, "src/handler.rs")
    assert any(f.rule_id == "RS003" for f in f_bad_no_drop)

    code_good = (
        "async fn handle_conn() {\n"
        "    let guard = state.lock();\n"
        "    drop(guard);\n"
        "    async_op().await;\n"
        "}\n"
    )
    f_good = verify_rust_source(code_good, "src/handler.rs")
    assert not any(f.rule_id == "RS003" for f in f_good)

    # In test files, RS003 is ignored
    f_test = verify_rust_source(code_bad, "tests/test_handler.rs")
    assert not any(f.rule_id == "RS003" for f in f_test)


def test_go001_discarded_error():
    code_bad1 = "package main\nfunc run() {\n    _ = err\n}\n"
    assert any(f.rule_id == "GO001" and f.severity == Severity.BLOCKING for f in verify_go_source(code_bad1, "pkg/worker.go"))

    code_bad2 = "package main\nfunc run() {\n    _, _ = doWork()\n}\n"
    assert any(f.rule_id == "GO001" for f in verify_go_source(code_bad2, "pkg/worker.go"))

    code_bad3 = "package main\nfunc run() {\n    val, _ := compute()\n}\n"
    assert any(f.rule_id == "GO001" for f in verify_go_source(code_bad3, "pkg/worker.go"))

    code_good = "package main\nfunc run() error {\n    val, err := compute()\n    if err != nil { return err }\n    return nil\n}\n"
    assert not any(f.rule_id == "GO001" for f in verify_go_source(code_good, "pkg/worker.go"))

    # Ignored in test files
    assert not any(f.rule_id == "GO001" for f in verify_go_source(code_bad1, "pkg/worker_test.go"))


def test_ts001_vacant_catch():
    code_bad_empty = "try { run(); } catch (e) {}"
    assert any(f.rule_id == "TS001" and f.severity == Severity.BLOCKING for f in verify_ts_source(code_bad_empty, "src/index.ts"))

    code_bad_comment_only = "try { run(); } catch (err) {\n  // ignore error\n  /* suppress */\n}"
    assert any(f.rule_id == "TS001" for f in verify_ts_source(code_bad_comment_only, "src/component.tsx"))

    code_good = "try { run(); } catch (e) {\n  console.error(e);\n}"
    assert not any(f.rule_id == "TS001" for f in verify_ts_source(code_good, "src/index.js"))


def test_agt001_hardcoded_secrets_and_wildcard_perms():
    code_bad_secret_sk = '{"api_key": "sk-1234567890abcdef"}'
    assert any(f.rule_id == "AGT001" and f.severity == Severity.BLOCKING for f in verify_config_source(code_bad_secret_sk, ".cursorrules"))

    code_bad_secret_ghp = '{"github_token": "ghp_1234567890abcdefghij"}'
    assert any(f.rule_id == "AGT001" for f in verify_config_source(code_bad_secret_ghp, ".claude/settings.local.json"))

    code_bad_secret_akia = '{"aws_key": "AKIAIOSFODNN7EXAMPLE"}'
    assert any(f.rule_id == "AGT001" for f in verify_config_source(code_bad_secret_akia, ".cursorrules"))

    code_bad_wildcard_bash = '{"permissions": ["Bash(*)"]}'
    assert any(f.rule_id == "AGT001" for f in verify_config_source(code_bad_wildcard_bash, ".claude/settings.local.json"))

    code_bad_wildcard_all = '{"permissions": ["*"]}'
    assert any(f.rule_id == "AGT001" for f in verify_config_source(code_bad_wildcard_all, ".cursorrules"))

    code_good = '{"permissions": ["Bash(git status)"], "env": "${API_KEY}"}'
    assert not any(f.rule_id == "AGT001" for f in verify_config_source(code_good, ".cursorrules"))


def test_deps001_lifecycle_scripts(tmp_path):
    # Positive tests: preinstall or postinstall scripts defined
    pkg_preinstall = json.dumps({
        "name": "suspicious-pkg",
        "version": "1.0.0",
        "scripts": {
            "preinstall": "node setup.js"
        }
    }, indent=2)
    findings_pre = verify_package_json(pkg_preinstall, "package.json")
    assert any(f.rule_id == "DEPS001" and f.severity == Severity.ADVISORY for f in findings_pre)
    assert any("preinstall" in f.message for f in findings_pre)

    pkg_postinstall = json.dumps({
        "name": "suspicious-pkg-2",
        "version": "1.0.0",
        "scripts": {
            "postinstall": "bash install.sh"
        }
    }, indent=2)
    findings_post = verify_package_json(pkg_postinstall, "package.json")
    assert any(f.rule_id == "DEPS001" and f.severity == Severity.ADVISORY for f in findings_post)
    assert any("postinstall" in f.message for f in findings_post)

    pkg_both = json.dumps({
        "name": "suspicious-pkg-both",
        "scripts": {
            "preinstall": "node pre.js",
            "postinstall": "node post.js"
        }
    }, indent=2)
    findings_both = verify_package_json(pkg_both, "package.json")
    assert len([f for f in findings_both if f.rule_id == "DEPS001"]) == 2

    # Negative tests: safe scripts (build, test, start) or no scripts
    pkg_clean = json.dumps({
        "name": "clean-pkg",
        "version": "1.0.0",
        "scripts": {
            "build": "tsc",
            "test": "jest",
            "start": "node index.js"
        }
    }, indent=2)
    findings_clean = verify_package_json(pkg_clean, "package.json")
    assert not any(f.rule_id == "DEPS001" for f in findings_clean)

    pkg_no_scripts = json.dumps({
        "name": "no-scripts-pkg",
        "version": "1.0.0"
    }, indent=2)
    findings_none = verify_package_json(pkg_no_scripts, "package.json")
    assert not any(f.rule_id == "DEPS001" for f in findings_none)

    # File and directory discovery test
    tmp_pkg = tmp_path / "package.json"
    tmp_pkg.write_text(pkg_postinstall, encoding="utf-8")
    file_findings = verify_file(tmp_pkg)
    assert any(f.rule_id == "DEPS001" for f in file_findings)

    path_findings = verify_path(tmp_path)
    assert any(f.rule_id == "DEPS001" for f in path_findings)


def test_cli_formats_and_exit_codes(capsys):
    repo_root = Path(__file__).resolve().parent.parent
    bad_py_path = repo_root / "examples" / "bad_sample.py"
    good_py_path = repo_root / "examples" / "good_sample.py"

    # Bad sample text format exit code 1
    code = main(["check", str(bad_py_path), "--format", "text"])
    assert code == 1
    out_text = capsys.readouterr().out
    assert "Scanned targets reported" in out_text

    # Bad sample json format
    code_json = main(["check", str(bad_py_path), "--format", "json"])
    assert code_json == 1
    out_json = capsys.readouterr().out
    try:
        payload = json.loads(out_json)
    except Exception as err:
        print(f"JSON decode failed: {err}")
        raise
    assert payload["verdict"] == "FAILED"
    assert payload["blocking_count"] > 0

    # Bad sample sarif format
    code_sarif = main(["check", str(bad_py_path), "--format", "sarif"])
    assert code_sarif == 1
    out_sarif = capsys.readouterr().out
    try:
        sarif = json.loads(out_sarif)
    except Exception as err:
        print(f"SARIF decode failed: {err}")
        raise
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"][0]["results"]) > 0

    # Good sample text format exit code 0
    code_good = main(["check", str(good_py_path), "--format", "text"])
    assert code_good == 0
    out_good = capsys.readouterr().out
    assert "PASS: 0 findings detected" in out_good


def test_self_check():
    """Verify that corral-lite code itself produces zero findings."""
    repo_src = Path(__file__).resolve().parent.parent / "src" / "corral_lite"
    findings = verify_path(repo_src)
    assert len(findings) == 0, f"Self-check findings: {findings}"
