"""Recon: enumerazione sottodomini e probing di host live.

Tutte le funzioni usano ``run_cmd`` (vedi ``autobb.utils``) e quindi
degradano in modo controllato (lista vuota + warning) se il tool esterno
richiesto (subfinder, httpx) non e' installato.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import List

from .config import Settings, Target
from .utils import get_logger, run_cmd

_logger = get_logger(__name__)


@dataclass
class LiveHost:
    """Rappresenta un host risultato "live" dopo il probing HTTP."""

    url: str
    status_code: int = 0
    title: str = ""
    tech: List[str] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.tech is None:
            self.tech = []


def enumerate_subdomains(target: Target, settings: Settings) -> List[str]:
    """Enumera i sottodomini di ``target`` usando subfinder.

    Esegue "subfinder -d <dominio> -silent" per ogni dominio in
    ``target.domains`` e ritorna la lista di sottodomini unici e
    ordinati, includendo sempre il dominio radice.

    Se subfinder non e' installato, la funzione ritorna semplicemente i
    domini radice (nessun crash).
    """
    found = set()
    for domain in target.domains:
        found.add(domain)
        lines = run_cmd([settings.tool_subfinder, "-d", domain, "-silent"])
        for line in lines:
            sub = line.strip()
            if sub:
                found.add(sub)

    result = sorted(found)
    _logger.info(
        "enumerate_subdomains: trovati %d sottodomini per target '%s'",
        len(result),
        target.name,
    )
    return result


def probe_live_hosts(
    target: Target, settings: Settings, subdomains: List[str]
) -> List[LiveHost]:
    """Esegue httpx sui sottodomini forniti per individuare gli host live.

    Passa i sottodomini sullo stdin di httpx e parsa ogni riga di output
    come JSON. Righe non parsabili vengono ignorate con un warning.
    """
    if not subdomains:
        return []

    args = [
        settings.tool_httpx,
        "-silent",
        "-json",
        "-status-code",
        "-title",
        "-tech-detect",
        "-rate-limit",
        str(target.rate_limit_rps),
    ]
    lines = run_cmd(args, stdin_lines=subdomains)

    hosts: List[LiveHost] = []
    for line in lines:
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            _logger.warning("probe_live_hosts: riga httpx non JSON valida, ignorata: %s", line[:200])
            continue

        url = data.get("url") or data.get("input") or ""
        if not url:
            continue

        tech = data.get("tech") or []
        if isinstance(tech, str):
            tech = [tech]

        hosts.append(
            LiveHost(
                url=url,
                status_code=int(data.get("status_code") or data.get("status-code") or 0),
                title=data.get("title", "") or "",
                tech=list(tech),
            )
        )

    _logger.info(
        "probe_live_hosts: %d host live su %d sottodomini per target '%s'",
        len(hosts),
        len(subdomains),
        target.name,
    )
    return hosts
