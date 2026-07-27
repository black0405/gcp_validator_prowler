"""Discover and run many checks, then write one consolidated report."""
from __future__ import annotations

import importlib
import inspect
import pkgutil
from typing import List, Optional, Type

from .base_check import BaseCheck
from .context import ValidationContext
from .models import CheckResult


def discover_check_classes(package_name: str = "checks",
                           service: Optional[str] = None) -> List[Type[BaseCheck]]:
    """Import every module under `checks` and collect BaseCheck subclasses."""
    pkg = importlib.import_module(package_name)
    found: dict = {}
    for mod in pkgutil.walk_packages(pkg.__path__, prefix=pkg.__name__ + "."):
        if mod.ispkg:
            continue
        module = importlib.import_module(mod.name)
        for _, obj in inspect.getmembers(module, inspect.isclass):
            if issubclass(obj, BaseCheck) and obj is not BaseCheck and obj.check_id:
                if obj.__module__ != module.__name__:
                    continue  # skip imported base classes
                if service and obj.service and obj.service != service:
                    continue
                found[obj.check_id] = obj
    return [found[k] for k in sorted(found)]


def run_checks(check_classes: List[Type[BaseCheck]], ctx: ValidationContext) -> List[CheckResult]:
    results: List[CheckResult] = []
    for cls in check_classes:
        ctx.log(f"running {cls.check_id}")
        try:
            results.append(cls().run(ctx))
        except Exception as exc:  # noqa: BLE001
            cr = CheckResult(check_id=cls.check_id, service=getattr(cls, "service", ""),
                             severity="", title=cls.check_id,
                             hub_link=f"https://hub.prowler.com/check/{cls.check_id}")
            cr.error = f"{type(exc).__name__}: {exc}"
            results.append(cr)
    return results
