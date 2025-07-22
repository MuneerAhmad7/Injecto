import urllib.parse as _u
import importlib
from pathlib import Path
from typing import Any
import requests
from rich import print

BASE_DIR = Path(__file__).resolve().parent.parent
DEFAULT_TECHS = {
    "union": "backend.injection.union_based",
    "boolean": "backend.injection.boolean_blind",
    "time": "backend.injection.time_blind",
    "error": "backend.injection.error_based",
    "oob": "backend.injection.oob_based",
}

def _discover_params(url: str) -> list[str]:
    """Return list of GET parameters in the URL."""
    parsed = _u.urlparse(url)
    return list(_u.parse_qs(parsed.query).keys())

def _load_module(name: str):
    return importlib.import_module(DEFAULT_TECHS[name])

def scan_target(url: str,
                techniques: list[str] | None = None,
                timeout: float = 8.0) -> list[dict[str, Any]]:
    """
    Scan one URL with selected techniques.
    Returns list of result dictionaries.
    """
    if techniques is None:
        techniques = list(DEFAULT_TECHS.keys())
    params = _discover_params(url)
    if not params:
        print(f"[yellow]No injectable parameters found in {url}[/]")
        return []

    headers = {"User-Agent": "Injekto/1.0"}
    results = []
    for tech in techniques:
        mod = _load_module(tech)
        for p in params:
            r = mod.test(url, p, headers=headers, timeout=timeout)
            results.append(r)
    return results
