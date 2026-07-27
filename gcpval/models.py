"""Core data models: verdicts, per-method results, per-resource results, check results."""
from __future__ import annotations

import enum
import traceback
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


class Verdict(str, enum.Enum):
    """Outcome of a single validation method (or of the overall consensus)."""
    PASS = "PASS"          # resource is compliant / not exposed
    FAIL = "FAIL"          # resource is non-compliant / exposed
    NA = "N/A"             # this method does not apply to this check
    ERROR = "ERROR"        # the method raised / could not complete
    MANUAL = "MANUAL"      # requires human judgement / no automated signal

    @property
    def is_definite(self) -> bool:
        return self in (Verdict.PASS, Verdict.FAIL)


class Method(str, enum.Enum):
    """The five validation methods requested by the spec."""
    API = "m1_api"                    # 1. simple direct API call
    PROWLER_REPLICA = "m2_prowler"    # 2. exact same check as Prowler (see hub link)
    LOGS = "m3_logs"                  # 3. validate from Cloud Audit / access logs
    ALTERNATE = "m4_alternate"        # 4. alternate check (inverse lookup / other API)
    EXPOSURE = "m5_exposure"          # 5. additional check (e.g. reach it from the internet)


METHOD_LABELS = {
    Method.API: "1. API",
    Method.PROWLER_REPLICA: "2. Prowler replica",
    Method.LOGS: "3. Logs",
    Method.ALTERNATE: "4. Alternate",
    Method.EXPOSURE: "5. Exposure",
}


@dataclass
class MethodResult:
    method: Method
    verdict: Verdict
    detail: str = ""
    evidence: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def na(cls, method: Method, reason: str) -> "MethodResult":
        return cls(method, Verdict.NA, reason)

    @classmethod
    def manual(cls, method: Method, reason: str) -> "MethodResult":
        return cls(method, Verdict.MANUAL, reason)

    @classmethod
    def error(cls, method: Method, exc: BaseException) -> "MethodResult":
        return cls(
            method,
            Verdict.ERROR,
            f"{type(exc).__name__}: {exc}",
            {"traceback": traceback.format_exc()},
        )

    @classmethod
    def ok(cls, method: Method, compliant: bool, detail: str, **evidence: Any) -> "MethodResult":
        return cls(method, Verdict.PASS if compliant else Verdict.FAIL, detail, dict(evidence))


# Agreement classifications shown in the report.
AGREE = "AGREE"
LIKELY_FALSE_POSITIVE = "LIKELY_FALSE_POSITIVE"    # Prowler FAIL, our consensus PASS
LIKELY_FALSE_NEGATIVE = "LIKELY_FALSE_NEGATIVE"    # Prowler PASS, our consensus FAIL
INCONCLUSIVE = "INCONCLUSIVE"                       # not enough automated signal
NO_PROWLER = "NO_PROWLER_FINDING"                   # nothing to compare against


@dataclass
class ResourceResult:
    """One resource evaluated across all five methods."""
    resource_id: str
    resource_name: str
    project: str = ""
    region: str = ""
    methods: Dict[Method, MethodResult] = field(default_factory=dict)
    prowler_status: Optional[Verdict] = None
    prowler_detail: str = ""

    def add(self, result: MethodResult) -> None:
        self.methods[result.method] = result

    def _definite_methods(self) -> List[MethodResult]:
        # Everything except the Prowler replica, which by design mirrors Prowler
        # and would bias the comparison.
        return [
            r for m, r in self.methods.items()
            if m != Method.PROWLER_REPLICA and r.verdict.is_definite
        ]

    def consensus(self) -> Verdict:
        definite = self._definite_methods()
        if not definite:
            return Verdict.MANUAL
        fails = sum(1 for r in definite if r.verdict is Verdict.FAIL)
        passes = sum(1 for r in definite if r.verdict is Verdict.PASS)
        if fails == 0:
            return Verdict.PASS
        if passes == 0:
            return Verdict.FAIL
        # Mixed signal: lean conservative (a confirmed problem outweighs a clean read).
        return Verdict.FAIL if fails >= passes else Verdict.PASS

    def agreement(self) -> str:
        if self.prowler_status is None:
            return NO_PROWLER
        cons = self.consensus()
        if not cons.is_definite:
            return INCONCLUSIVE
        if cons == self.prowler_status:
            return AGREE
        if self.prowler_status is Verdict.FAIL and cons is Verdict.PASS:
            return LIKELY_FALSE_POSITIVE
        if self.prowler_status is Verdict.PASS and cons is Verdict.FAIL:
            return LIKELY_FALSE_NEGATIVE
        return INCONCLUSIVE


@dataclass
class CheckResult:
    check_id: str
    service: str
    severity: str
    title: str
    hub_link: str
    resources: List[ResourceResult] = field(default_factory=list)
    error: Optional[str] = None

    def add(self, r: ResourceResult) -> None:
        self.resources.append(r)
