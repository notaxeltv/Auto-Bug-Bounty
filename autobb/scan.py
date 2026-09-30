"""Scansione di vulnerabilita' note (nuclei) e port scan opzionale (naabu).

IMPORTANTE: nuclei viene usato esclusivamente in modalita' di rilevamento
basata su template pubblici. Questo modulo non implementa e non deve
implementare alcuna forma di exploitation attiva, brute force o attacco
offensivo: si tratta di detection non invasiva.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import List

from .config import Settings, Target
from .recon import LiveHost
from .utils import get_logger, run_cmd

_logger = get_logger(__name__)


@dataclass
class Finding:
    """Rappresenta un finding di sicurezza rilevato da nuclei."""

    template_id: str
    name: str
    severity: str
    host: str
    matched_at: str
    description: str = ""
    reference: List[str] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.reference is None:
            self.reference = []

    @property
    def fingerprint(self) -> str:
        """Identificatore stabile del finding, usato per il dedup nel diff."""
        return f"{self.template_id}::{self.matched_at}"


def run_nuclei(
    target: Target, settings: Settings, live_hosts: List[LiveHost]
) -> List[Finding]:
    """Esegue nuclei sugli host live e ritorna i finding rilevati.

    Se nuclei non e' installato, ritorna una lista vuota senza crashare.
    """
    if not live_hosts:
        return []

    urls = [host.url for host in live_hosts]

    args = [
        settings.tool_nuclei,
        "-silent",
        "-jsonl",
        "-severity",
        settings.nuclei_severity,
        "-rate-limit",
        str(settings.nuclei_rate_limit),
    ]
    args.extend(settings.nuclei_extra_args or [])

    lines = run_cmd(args, stdin_lines=urls)

    findings: List[Finding] = []
    for line in lines:
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            _logger.warning("run_nuclei: riga output non JSON valida, ignorata: %s", line[:200])
            continue

        info = data.get("info", {}) or {}
        finding = Finding(
            template_id=data.get("template-id", data.get("template_id", "")) or "",
            name=info.get("name", "") or "",
            severity=info.get("severity", "unknown") or "unknown",
            host=data.get("host", "") or "",
            matched_at=data.get("matched-at", data.get("matched_at", "")) or "",
            description=info.get("description", "") or "",
            reference=list(info.get("reference", []) or []),
        )
        findings.append(finding)

    # filtra i finding sulle severita' richieste dal target, se presenti
    if target.severities:
        allowed = {s.lower() for s in target.severities}
        findings = [f for f in findings if f.severity.lower() in allowed]

    _logger.info(
        "run_nuclei: %d finding rilevati per target '%s'", len(findings), target.name
    )
    return findings


def run_naabu(
    target: Target, settings: Settings, live_hosts: List[LiveHost]
) -> List[str]:
    """Port scan OPZIONALE tramite naabu (disattivato di default).

    Ritorna le righe di output grezze di naabu (host:porta). Non ha
    effetto se ``settings.naabu_enabled`` e' False, o se naabu non e'
    installato.
    """
    if not settings.naabu_enabled:
        _logger.info("run_naabu: naabu disabilitato via settings (naabu_enabled=False), salto")
        return []

    if not live_hosts:
        return []

    hosts = sorted({host.url for host in live_hosts})

    args = [
        settings.tool_naabu,
        "-silent",
        "-top-ports",
        str(settings.naabu_top_ports),
    ]
    results = run_cmd(args, stdin_lines=hosts)

    _logger.info(
        "run_naabu: %d righe di risultato per target '%s'", len(results), target.name
    )
    return results
