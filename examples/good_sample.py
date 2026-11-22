"""Sample clean, compliant Python code adhering to Corral-Lite standards."""

import json
import logging
import math
import os
import subprocess
from typing import Any, List, Optional

LOGGER = logging.getLogger(__name__)


def safe_handler() -> bool:
    """Properly handles exception with diagnostic logging."""
    try:
        x = 10 / 2
        return True
    except ZeroDivisionError as err:
        LOGGER.error("Division by zero encountered: %s", err)
        return False


def append_item(item: str, container: Optional[List[str]] = None) -> List[str]:
    """Uses immutable default argument."""
    target = container if container is not None else []
    target.append(item)
    return target


def execute_formula(value: float) -> float:
    """Uses explicit math operations rather than dynamic evaluation."""
    return math.sqrt(value)


def load_config_safe(raw_str: str) -> dict[str, Any]:
    """Safely handles json deserialization in a guarded try-except scope."""
    try:
        return json.loads(raw_str)
    except (json.JSONDecodeError, ValueError) as err:
        LOGGER.warning("Failed to decode configuration JSON: %s", err)
        return {}


def list_directory(user_dir: str) -> subprocess.CompletedProcess[str]:
    """Executes subprocess safely without shell=True."""
    return subprocess.run(
        ["cmd.exe", "/c", "dir", user_dir],
        capture_output=True,
        text=True,
        check=False,
    )


def validate_positive(num: int) -> int:
    """Uses explicit runtime exception validation rather than assert."""
    if num <= 0:
        raise ValueError("Number must be strictly positive")
    return num


def get_api_key() -> str:
    """Retrieves credentials dynamically from environment variables."""
    return os.environ.get("SERVICE_API_KEY", "")
