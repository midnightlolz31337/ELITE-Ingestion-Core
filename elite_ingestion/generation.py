"""Stable read-only API for resolving a committed ingestion generation.

Consumers should use this module instead of reimplementing CURRENT.json
validation or depending on the CLI's private helper.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .cli import _read_current_pointer


def read_current_generation(pointer: Path) -> tuple[dict[str, Any], Path]:
    """Validate CURRENT.json and return its manifest and verified generation path.

    The returned path is the immutable generation referenced by the pointer.
    The function performs no writes and does not read or promote quarantined
    records. Callers remain responsible for parsing individual record files.
    """
    return _read_current_pointer(Path(pointer))
