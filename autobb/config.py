"""Modelli di configurazione e caricamento da file YAML.

Contiene il modello ``Target`` con il guardrail principale del progetto:
``ensure_authorized()``, che blocca qualsiasi operazione di rete verso
un target non esplicitamente autorizzato.
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

import yaml

from .utils import get_logger

_logger = get_logger(__name__)

CONFIG_DIR = Path("config")
TARGETS_FILE = CONFIG_DIR / "targets.yaml"
SETTINGS_FILE = CONFIG_DIR / "settings.yaml"
TARGETS_EXAMPLE_FILE = CONFIG_DIR / "targets.example.yaml"
SETTINGS_EXAMPLE_FILE = CONFIG_DIR / "settings.example.yaml"

DEFAULT_SEVERITIES = ["low", "medium", "high", "critical"]


class UnauthorizedTargetError(Exception):
    """Sollevata quando si tenta di scansionare un target non autorizzato."""


@dataclass
class Target:
    """Rappresenta un target di bug bounty configurato dall'utente.

    ATTENZIONE: ``authorized`` deve essere impostato a ``True`` solo se
    esiste un'autorizzazione esplicita e scritta (es. programma di bug
    bounty pubblico o contratto di pentest) a testare i domini elencati.
    """

    name: str
    domains: List[str] = field(default_factory=list)
    authorized: bool = False
    program_url: str = ""
    scope_notes: str = ""
    rate_limit_rps: int = 5
    severities: List[str] = field(default_factory=lambda: list(DEFAULT_SEVERITIES))

    def ensure_authorized(self) -> None:
        """Blocca l'esecuzione se il target non e' autorizzato.

        Deve essere chiamata PRIMA di qualsiasi chiamata di rete verso il
        target, sia in esecuzione singola (``run``) che in monitoraggio
        continuo (``watch``).

        Raises:
            UnauthorizedTargetError: se ``self.authorized`` e' ``False``.
        """
        if not self.authorized:
            raise UnauthorizedTargetError(
                f"Target '{self.name}' non e' autorizzato (authorized: false). "
                "Puoi scansionare un target SOLO con autorizzazione esplicita "
                "(programma di bug bounty pubblico o contratto di pentest). "
                "Imposta 'authorized: true' in config/targets.yaml solo dopo "
                "aver verificato di avere il permesso reale per farlo."
            )


@dataclass
class Settings:
    """Impostazioni globali dell'applicazione."""

    webhook_url: str = ""
    tool_subfinder: str = "subfinder"
    tool_httpx: str = "httpx"
    tool_naabu: str = "naabu"
    tool_nuclei: str = "nuclei"
    nuclei_severity: str = "low,medium,high,critical"
    nuclei_rate_limit: int = 150
    nuclei_extra_args: List[str] = field(default_factory=list)
    naabu_enabled: bool = False
    naabu_top_ports: int = 100
    default_interval_seconds: int = 3600
    data_dir: str = "data"


def _ensure_config_dir() -> None:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)


def init_config() -> None:
    """Crea config/targets.yaml e config/settings.yaml dai rispettivi template.

    Non sovrascrive file gia' esistenti.
    """
    _ensure_config_dir()

    if not TARGETS_FILE.exists():
        if TARGETS_EXAMPLE_FILE.exists():
            shutil.copyfile(TARGETS_EXAMPLE_FILE, TARGETS_FILE)
            _logger.info("Creato %s da template", TARGETS_FILE)
        else:
            _logger.warning(
                "Template %s non trovato: %s non creato", TARGETS_EXAMPLE_FILE, TARGETS_FILE
            )
    else:
        _logger.info("%s esiste già, non sovrascrivo", TARGETS_FILE)

    if not SETTINGS_FILE.exists():
        if SETTINGS_EXAMPLE_FILE.exists():
            shutil.copyfile(SETTINGS_EXAMPLE_FILE, SETTINGS_FILE)
            _logger.info("Creato %s da template", SETTINGS_FILE)
        else:
            _logger.warning(
                "Template %s non trovato: %s non creato", SETTINGS_EXAMPLE_FILE, SETTINGS_FILE
            )
    else:
        _logger.info("%s esiste già, non sovrascrivo", SETTINGS_FILE)


def load_targets(path: Optional[Path] = None) -> Dict[str, Target]:
    """Carica i target da un file YAML e ritorna un dict {nome: Target}."""
    targets_path = path or TARGETS_FILE
    if not targets_path.exists():
        _logger.warning(
            "File di configurazione target '%s' non trovato. Esegui 'autobb init' "
            "per crearlo da template.",
            targets_path,
        )
        return {}

    with open(targets_path, "r", encoding="utf-8") as fh:
        raw = yaml.safe_load(fh) or {}

    raw_targets = raw.get("targets", []) or []
    targets: Dict[str, Target] = {}
    for entry in raw_targets:
        name = entry.get("name")
        if not name:
            _logger.warning("Voce target senza 'name' ignorata: %s", entry)
            continue
        targets[name] = Target(
            name=name,
            domains=list(entry.get("domains", []) or []),
            authorized=bool(entry.get("authorized", False)),
            program_url=entry.get("program_url", "") or "",
            scope_notes=entry.get("scope_notes", "") or "",
            rate_limit_rps=int(entry.get("rate_limit_rps", 5)),
            severities=list(entry.get("severities", DEFAULT_SEVERITIES) or DEFAULT_SEVERITIES),
        )
    return targets


def get_target(name: str, path: Optional[Path] = None) -> Optional[Target]:
    """Ritorna il target con il nome indicato, o None se non trovato."""
    return load_targets(path).get(name)


def load_settings(path: Optional[Path] = None) -> Settings:
    """Carica le impostazioni globali da un file YAML."""
    settings_path = path or SETTINGS_FILE
    if not settings_path.exists():
        _logger.warning(
            "File di configurazione impostazioni '%s' non trovato. Uso i valori di "
            "default. Esegui 'autobb init' per crearlo da template.",
            settings_path,
        )
        return Settings()

    with open(settings_path, "r", encoding="utf-8") as fh:
        raw = yaml.safe_load(fh) or {}

    notifications = raw.get("notifications", {}) or {}
    tools = raw.get("tools", {}) or {}
    nuclei = raw.get("nuclei", {}) or {}
    naabu = raw.get("naabu", {}) or {}
    watch = raw.get("watch", {}) or {}
    paths = raw.get("paths", {}) or {}

    return Settings(
        webhook_url=notifications.get("webhook_url", "") or "",
        tool_subfinder=tools.get("subfinder", "subfinder") or "subfinder",
        tool_httpx=tools.get("httpx", "httpx") or "httpx",
        tool_naabu=tools.get("naabu", "naabu") or "naabu",
        tool_nuclei=tools.get("nuclei", "nuclei") or "nuclei",
        nuclei_severity=nuclei.get("severity", "low,medium,high,critical"),
        nuclei_rate_limit=int(nuclei.get("rate_limit", 150)),
        nuclei_extra_args=list(nuclei.get("extra_args", []) or []),
        naabu_enabled=bool(naabu.get("enabled", False)),
        naabu_top_ports=int(naabu.get("top_ports", 100)),
        default_interval_seconds=int(watch.get("default_interval_seconds", 3600)),
        data_dir=paths.get("data_dir", "data") or "data",
    )
