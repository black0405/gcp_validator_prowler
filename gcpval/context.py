"""Shared runtime context passed to every check."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .gcp_clients import GcpClients
from .prowler import ProwlerReport


@dataclass
class ValidationContext:
    project: str
    clients: GcpClients
    prowler: ProwlerReport
    # Behaviour toggles
    log_window_days: int = 90
    enable_exposure_probe: bool = False   # opt-in: makes real outbound connections
    probe_timeout: float = 4.0
    verbose: bool = False

    @classmethod
    def create(
        cls,
        project: str,
        prowler_path: str = "",
        credentials: Any = None,
        key_file: str = "",
        **opts: Any,
    ) -> "ValidationContext":
        clients = GcpClients(project=project, credentials=credentials, key_file=key_file or None)
        prowler = ProwlerReport.load(prowler_path) if prowler_path else ProwlerReport([])
        ctx = cls(project=project, clients=clients, prowler=prowler)
        for k, v in opts.items():
            if hasattr(ctx, k):
                setattr(ctx, k, v)
        return ctx

    def log(self, msg: str) -> None:
        if self.verbose:
            print(f"[gcpval] {msg}")
