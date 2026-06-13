"""Local workspace creation."""

from pathlib import Path

from bugbounty_scout.config import dump_yaml

WORKSPACE_DIRS = ("captures", "evidence", "findings", "reports")


def create_workspace(name: str, parent: Path | None = None) -> Path:
    """Create a safe local workspace without overwriting an existing path."""
    if not name.strip() or Path(name).name != name or name in {".", ".."}:
        raise ValueError("Workspace name must be a single non-empty directory name")
    root = (parent or Path.cwd()) / name
    if root.exists():
        raise FileExistsError(f"Workspace already exists: {root}")
    root.mkdir()
    for directory in WORKSPACE_DIRS:
        (root / directory).mkdir()
    dump_yaml(
        {
            "name": name,
            "version": 1,
            "safety": {
                "authorized_use_only": True,
                "redact_by_default": True,
                "network_requests": False,
            },
        },
        root / "workspace.yml",
    )
    return root
