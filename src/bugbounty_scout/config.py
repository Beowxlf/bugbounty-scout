"""Configuration loading helpers."""

import json
from pathlib import Path
from typing import Any

import yaml


def load_data(path: Path) -> dict[str, Any]:
    """Load a YAML or JSON object from disk."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ValueError(f"Could not read {path}: {exc}") from exc

    try:
        data = (
            json.loads(text) if path.suffix.lower() == ".json" else yaml.safe_load(text)
        )
    except (json.JSONDecodeError, yaml.YAMLError) as exc:
        raise ValueError(f"Invalid configuration in {path}: {exc}") from exc

    if not isinstance(data, dict):
        raise ValueError(f"{path} must contain a mapping/object")
    return data


def dump_yaml(data: dict[str, Any], path: Path) -> None:
    """Write data as readable YAML."""
    path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
