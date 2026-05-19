from __future__ import annotations

import configparser
from pathlib import Path

from .models import PanelConfig


def _parse_bool(value: str | None, default: bool) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "yes", "true", "on"}


def load_config(path: str | Path) -> list[PanelConfig]:
    config_path = Path(path)
    if not config_path.exists():
        raise FileNotFoundError(f"Config file not found: {config_path}")

    parser = configparser.ConfigParser()
    parser.read(config_path, encoding="utf-8")

    panels: list[PanelConfig] = []
    for section in parser.sections():
        if not section.startswith("panel."):
            continue
        name = section.removeprefix("panel.").strip() or section
        url = parser.get(section, "url", fallback="").strip().rstrip("/")
        api_key = parser.get(section, "api_key", fallback="").strip()
        if not url:
            raise ValueError(f"[{section}] missing url")
        if not api_key:
            raise ValueError(f"[{section}] missing api_key")
        timeout = parser.getfloat(section, "timeout", fallback=15.0)
        panels.append(
            PanelConfig(
                name=name,
                url=url,
                api_key=api_key,
                verify_ssl=_parse_bool(parser.get(section, "verify_ssl", fallback=None), True),
                timeout=timeout,
            )
        )

    if not panels:
        raise ValueError("No [panel.*] sections found in config")
    return panels
