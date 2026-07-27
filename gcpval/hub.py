"""Prowler Hub links + bundled check metadata (service, severity, title).

The Hub page for each check documents the exact logic Prowler applies; method
#2 (Prowler replica) references it, and it is emitted in the report so a
reviewer can open the source of truth for any finding.
"""
from __future__ import annotations

import functools
import json
import os
from typing import Dict

HUB_URL_TEMPLATE = "https://hub.prowler.com/check/{check_id}"

_DATA_PATH = os.path.join(os.path.dirname(__file__), "data", "gcp_checks.json")


def hub_link(check_id: str) -> str:
    return HUB_URL_TEMPLATE.format(check_id=check_id)


@functools.lru_cache(maxsize=1)
def _metadata() -> Dict[str, dict]:
    with open(_DATA_PATH, "r", encoding="utf-8-sig") as fh:
        return json.load(fh)


def meta(check_id: str) -> dict:
    """Return {service, severity, title, hub_link} for a check id."""
    m = dict(_metadata().get(check_id, {}))
    m.setdefault("service", "")
    m.setdefault("severity", "")
    m.setdefault("title", check_id)
    m["hub_link"] = hub_link(check_id)
    return m
