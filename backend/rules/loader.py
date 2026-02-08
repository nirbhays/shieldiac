"""
ShieldIaC — Rule Discovery & Loading

Dynamically imports all rule modules so that rules self-register
with the global `RuleRegistry` on startup.
"""
from __future__ import annotations

import importlib
import logging
import pkgutil
from pathlib import Path
from typing import List

from backend.rules.base import RuleRegistry, registry

logger = logging.getLogger(__name__)

# ── Packages containing rule modules ─────────────────────────────────────

_RULE_PACKAGES = [
    "backend.rules.terraform",
    "backend.rules.kubernetes",
    "backend.rules.docker",
]


def discover_and_load_rules(extra_packages: List[str] | None = None) -> RuleRegistry:
    """Import every module inside each rule package so decorators fire.

    Returns the populated global registry.
    """
    packages = _RULE_PACKAGES + (extra_packages or [])
    for pkg_name in packages:
        try:
            pkg = importlib.import_module(pkg_name)
        except ModuleNotFoundError:
            logger.warning("Rule package %s not found — skipping", pkg_name)
            continue

        pkg_path = getattr(pkg, "__path__", None)
        if pkg_path is None:
            continue

        for _importer, module_name, _is_pkg in pkgutil.iter_modules(pkg_path):
            full_name = f"{pkg_name}.{module_name}"
            try:
                importlib.import_module(full_name)
                logger.debug("Loaded rule module: %s", full_name)
            except Exception:
                logger.exception("Failed to load rule module %s", full_name)

    logger.info(
        "Rule loading complete — %d rules registered (%s)",
        registry.count,
        registry.summary(),
    )
    return registry


def load_rules() -> RuleRegistry:
    """Convenience alias used by the application entry point."""
    return discover_and_load_rules()
