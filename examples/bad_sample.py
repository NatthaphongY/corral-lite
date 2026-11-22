"""Sample Python code with deliberate defects for Corral-Lite testing."""

import json
import os
import subprocess
from math import *  # PY004: Wildcard import


def bad_handler():
    try:
        x = 1 / 0
    except Exception:
        pass  # PY001: Broad except silenced with pass


def append_item(item, container=[]):  # PY002: Mutable default argument
    container.append(item)
    return container


def execute_formula(code):
    return eval(code)  # PY003: Direct invocation of eval


def load_config_unsafe(raw_str):
    return json.loads(raw_str)  # PY005: Unguarded json.loads outside try-except


def list_directory(user_dir):
    subprocess.run(f"dir {user_dir}", shell=True)  # PY006: Subprocess with shell=True


def validate_positive(num):
    assert num > 0, "Number must be strictly positive"  # PY007: Assert outside test suite


API_KEY = "sk-live-99238472918374928374"  # PY008: Hardcoded secret assignment
