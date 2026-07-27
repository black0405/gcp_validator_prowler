"""Render per-finding audit evidence images (PNG).

Each image is a self-contained "evidence card" built from the data the tool
already collected: the check, the resource, every validation method's verdict
and detail, the raw configuration values read from the API (the proof), a UTC
capture timestamp, and a deep-link to the cloud console. Headless (Pillow only),
deterministic, and provenance-stamped for audit use.
"""
from __future__ import annotations

import json
import os
import re
from typing import Callable, List, Optional

from .models import CheckResult, METHOD_LABELS, Method, ResourceResult, Verdict

# Agreement / verdict colours (RGB).
_AGREE_FILL = {
    "AGREE": (95, 145, 65),
    "LIKELY_FALSE_POSITIVE": (200, 140, 30),
    "LIKELY_FALSE_NEGATIVE": (185, 60, 55),
    "INCONCLUSIVE": (110, 110, 115),
    "NO_PROWLER_FINDING": (70, 90, 120),
}
_VERDICT_COLOR = {
    Verdict.PASS: (60, 130, 60),
    Verdict.FAIL: (185, 55, 50),
    Verdict.NA: (120, 120, 125),
    Verdict.MANUAL: (55, 95, 165),
    Verdict.ERROR: (200, 120, 30),
}
_INK = (30, 32, 36)
_MUTED = (110, 112, 120)
_W = 1000
_MARGIN = 30


def _font(size: int, bold: bool = False):
    from PIL import ImageFont
    try:
        return ImageFont.load_default(size)          # Pillow >= 10.1 (scalable)
    except TypeError:
        pass
    for name in (("DejaVuSans-Bold.ttf" if bold else "DejaVuSans.ttf"),):
        try:
            return ImageFont.truetype(name, size)
        except OSError:
            continue
    return ImageFont.load_default()


def _safe(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", (s or "resource"))[:80].strip("_") or "resource"


def _wrap(draw, text: str, font, max_w: int) -> List[str]:
    out: List[str] = []
    for para in str(text).splitlines() or [""]:
        words, line = para.split(" "), ""
        for w in words:
            trial = (line + " " + w).strip()
            if draw.textlength(trial, font=font) <= max_w or not line:
                line = trial
            else:
                out.append(line)
                line = w
        out.append(line)
    return out or [""]


def _merged_evidence(rr: ResourceResult) -> dict:
    ev: dict = {}
    for method, mr in rr.methods.items():
        for k, v in (mr.evidence or {}).items():
            if k == "traceback":
                continue
            ev[f"{METHOD_LABELS.get(method, method.value)}:{k}"] = v
    return ev


class _Canvas:
    """Two-pass text layout: collect rows, then draw at the measured height."""
    def __init__(self):
        self.rows = []  # (text, font, color, indent, gap_before)

    def add(self, text, font, color=_INK, indent=0, gap=6):
        self.rows.append([text, font, color, indent, gap])

    def render(self, path, header_text, header_right, header_fill):
        from PIL import Image, ImageDraw
        tmp = Image.new("RGB", (_W, 10))
        d = ImageDraw.Draw(tmp)
        # expand wrapped rows
        flat = []
        for text, font, color, indent, gap in self.rows:
            for i, ln in enumerate(_wrap(d, text, font, _W - 2 * _MARGIN - indent)):
                flat.append((ln, font, color, indent, gap if i == 0 else 2))
        header_h = 70
        y = header_h + 14
        heights = []
        for ln, font, color, indent, gap in flat:
            asc, desc = font.getmetrics()
            lh = asc + desc + 4
            heights.append((y + gap, ln, font, color, indent, lh))
            y += gap + lh
        total_h = y + _MARGIN

        img = Image.new("RGB", (_W, total_h), (255, 255, 255))
        draw = ImageDraw.Draw(img)
        draw.rectangle([0, 0, _W, header_h], fill=header_fill)
        draw.text((_MARGIN, 16), header_text, font=_font(23, bold=True), fill=(255, 255, 255))
        hr_font = _font(16, bold=True)
        draw.text((_W - _MARGIN - draw.textlength(header_right, font=hr_font), 26),
                  header_right, font=hr_font, fill=(255, 255, 255))
        for yy, ln, font, color, indent, lh in heights:
            draw.text((_MARGIN + indent, yy), ln, font=font, fill=color)
        img.save(path, "PNG")


def _render_card(cr: CheckResult, rr: ResourceResult, link: str, provider: str,
                 scope_label: str, timestamp: str, path: str) -> None:
    f_h = _font(15, bold=True)
    f_b = _font(15)
    f_s = _font(13)
    f_mono = _font(13)

    agreement = rr.agreement()
    consensus = rr.consensus()
    header_fill = _AGREE_FILL.get(agreement, (70, 75, 85))

    c = _Canvas()
    c.add(cr.title or cr.check_id, f_h, _INK, gap=4)
    c.add(f"{provider}  ·  service: {cr.service}  ·  severity: {cr.severity}  ·  {scope_label}", f_s, _MUTED)
    c.add(f"Check ID: {cr.check_id}", f_b, gap=10)
    c.add(f"Hub reference: {cr.hub_link}", f_s, (40, 85, 160))

    c.add("Resource", f_h, _INK, gap=14)
    c.add(f"Name: {rr.resource_name or '(n/a)'}", f_b, indent=12)
    if rr.resource_id and rr.resource_id != rr.resource_name:
        c.add(f"ID: {rr.resource_id}", f_s, _MUTED, indent=12)
    loc = ", ".join(x for x in (rr.region, rr.project) if x)
    if loc:
        c.add(f"Location/Project: {loc}", f_s, _MUTED, indent=12)

    c.add("Verdicts", f_h, _INK, gap=14)
    pw = rr.prowler_status.value if rr.prowler_status else "—"
    c.add(f"Prowler: {pw}      Consensus: {consensus.value}      Result: {agreement}",
          f_b, header_fill, indent=12)
    if rr.prowler_detail:
        c.add(f"Prowler detail: {rr.prowler_detail}", f_s, _MUTED, indent=12)

    c.add("Validation methods", f_h, _INK, gap=14)
    for method, label in METHOD_LABELS.items():
        mr = rr.methods.get(method)
        if not mr:
            continue
        color = _VERDICT_COLOR.get(mr.verdict, _INK)
        c.add(f"{label:<18} {mr.verdict.value:<7} {mr.detail}", f_b, color, indent=12)

    ev = _merged_evidence(rr)
    if ev:
        c.add("Evidence (values read from the API)", f_h, _INK, gap=14)
        c.add(json.dumps(ev, indent=2, default=str), f_mono, (60, 62, 70), indent=12)

    c.add("Provenance", f_h, _INK, gap=14)
    c.add(f"Captured (UTC): {timestamp}   via {provider} API - validated by the Prowler cross-check tool",
          f_s, _MUTED, indent=12)
    if link:
        c.add(f"Console: {link}", f_s, (40, 85, 160), indent=12)

    right = agreement.replace("_", " ")
    c.render(path, cr.check_id, right, header_fill)


def write_evidence_images(
    check_results: List[CheckResult],
    out_dir: str,
    provider: str,
    scope_label: str,
    deeplink_fn: Optional[Callable[[CheckResult, ResourceResult], str]] = None,
    only_findings: bool = False,
) -> int:
    """Write one PNG per evaluated resource. Returns the number written.

    only_findings=True limits output to rows that disagree with Prowler
    (LIKELY_FALSE_POSITIVE / LIKELY_FALSE_NEGATIVE) — the audit exceptions.
    """
    from datetime import datetime, timezone
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    os.makedirs(out_dir, exist_ok=True)
    written = 0
    for cr in check_results:
        for rr in cr.resources:
            if only_findings and rr.agreement() not in ("LIKELY_FALSE_POSITIVE", "LIKELY_FALSE_NEGATIVE"):
                continue
            link = deeplink_fn(cr, rr) if deeplink_fn else ""
            name = _safe(rr.resource_name or rr.resource_id or "resource")
            path = os.path.join(out_dir, f"{cr.check_id}__{name}.png")
            try:
                _render_card(cr, rr, link, provider, scope_label, ts, path)
                written += 1
            except Exception as exc:  # noqa: BLE001 - never let evidence break a run
                print(f"[evidence] failed for {cr.check_id}/{name}: {exc}")
    return written
