"""Scan profile definitions for the web application security scanner."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, Optional

import json


@dataclass
class ScanProfile:
    """Configuration flags to enable or disable scanner checks.

    Attributes:
        name: Human readable name.
        checks: Mapping of check identifiers to a boolean that toggles execution.
        description: Optional explanation of the profile's intent.
        request_kwargs: Optional keyword arguments forwarded to the underlying
            :class:`requests.Session` object (e.g. timeout, headers).
    """

    name: str
    checks: Dict[str, bool] = field(default_factory=dict)
    description: str | None = None
    request_kwargs: Dict[str, Any] = field(default_factory=dict)

    def enabled_checks(self) -> Iterable[str]:
        """Return the identifiers of the checks that are enabled."""

        for check, enabled in self.checks.items():
            if enabled:
                yield check


DEFAULT_PROFILES: Dict[str, ScanProfile] = {
    "basic": ScanProfile(
        name="Basic",
        description="Lightweight scan focused on high-impact issues.",
        checks={
            "sql_injection": True,
            "xss": True,
            "security_headers": True,
        },
        request_kwargs={"timeout": 10},
    ),
    "full": ScanProfile(
        name="Full",
        description="Comprehensive scan covering all available checks.",
        checks={
            "sql_injection": True,
            "xss": True,
            "csrf": True,
            "security_headers": True,
            "ssl": True,
            "directory_traversal": True,
        },
        request_kwargs={"timeout": 20},
    ),
}


def load_profile(path_or_name: str) -> ScanProfile:
    """Load a scan profile by name or from a JSON file.

    The JSON representation mirrors the :class:`ScanProfile` dataclass. Unknown
    keys are ignored, allowing the format to be forward compatible.
    """

    if path_or_name in DEFAULT_PROFILES:
        return DEFAULT_PROFILES[path_or_name]

    profile_path = Path(path_or_name)
    if not profile_path.exists():
        raise FileNotFoundError(f"Profile '{path_or_name}' does not exist")

    data: Dict[str, Any] = json.loads(profile_path.read_text())
    checks = data.get("checks", {})
    description = data.get("description")
    request_kwargs = data.get("request_kwargs", {})
    name = data.get("name") or profile_path.stem
    return ScanProfile(
        name=name,
        checks={str(key): bool(value) for key, value in checks.items()},
        description=description,
        request_kwargs={str(key): value for key, value in request_kwargs.items()},
    )
