"""Calcolo del diff tra run successivi (nuovi sottodomini, nuovi finding).

Lo stato di ogni target viene persistito in
``<data_dir>/<target_name>/state.json`` e confrontato ad ogni nuova
esecuzione per individuare cosa e' cambiato rispetto al run precedente.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import List

from .scan import Finding
from .utils import get_logger

_logger = get_logger(__name__)

STATE_FILENAME = "state.json"


@dataclass
class RunResult:
    """Risultato del confronto tra lo stato corrente e quello precedente."""

    new_subdomains: List[str] = field(default_factory=list)
    new_findings: List[Finding] = field(default_factory=list)
    total_subdomains: int = 0
    total_findings: int = 0


def _state_path(data_dir: Path, target_name: str) -> Path:
    return Path(data_dir) / target_name / STATE_FILENAME


def _load_previous_state(data_dir: Path, target_name: str) -> dict:
    path = _state_path(data_dir, target_name)
    if not path.exists():
        return {"subdomains": [], "findings": []}

    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (json.JSONDecodeError, OSError) as exc:
        _logger.warning(
            "Impossibile leggere lo stato precedente da '%s' (%s): considero vuoto",
            path,
            exc,
        )
        return {"subdomains": [], "findings": []}


def _save_state(
    data_dir: Path, target_name: str, subdomains: List[str], findings: List[Finding]
) -> None:
    path = _state_path(data_dir, target_name)
    path.parent.mkdir(parents=True, exist_ok=True)

    state = {
        "subdomains": sorted(set(subdomains)),
        "findings": [
            {
                "template_id": f.template_id,
                "name": f.name,
                "severity": f.severity,
                "host": f.host,
                "matched_at": f.matched_at,
                "description": f.description,
                "reference": f.reference,
                "fingerprint": f.fingerprint,
            }
            for f in findings
        ],
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(state, fh, indent=2, ensure_ascii=False)


def compute_diff(
    data_dir: Path,
    target_name: str,
    subdomains: List[str],
    findings: List[Finding],
) -> RunResult:
    """Calcola i sottodomini e i finding nuovi rispetto al run precedente.

    Carica lo stato precedente da ``<data_dir>/<target_name>/state.json``,
    calcola le novita' rispetto al run corrente (usando il fingerprint per
    il dedup dei finding), salva il nuovo stato e ritorna un
    ``RunResult``.

    Al primo run (nessuno stato precedente), tutti i sottodomini e i
    finding correnti sono considerati nuovi. Se non c'e' nessun
    cambiamento rispetto al run precedente, ``new_subdomains`` e
    ``new_findings`` sono liste vuote.
    """
    data_dir = Path(data_dir)
    previous = _load_previous_state(data_dir, target_name)

    previous_subdomains = set(previous.get("subdomains", []) or [])
    previous_fingerprints = {
        entry.get("fingerprint")
        for entry in previous.get("findings", []) or []
        if entry.get("fingerprint")
    }

    current_subdomains = sorted(set(subdomains))
    new_subdomains = sorted(set(current_subdomains) - previous_subdomains)

    new_findings = [f for f in findings if f.fingerprint not in previous_fingerprints]

    _save_state(data_dir, target_name, current_subdomains, findings)

    result = RunResult(
        new_subdomains=new_subdomains,
        new_findings=new_findings,
        total_subdomains=len(current_subdomains),
        total_findings=len(findings),
    )

    _logger.info(
        "compute_diff[%s]: %d nuovi sottodomini, %d nuovi finding (totali: %d sub, %d finding)",
        target_name,
        len(new_subdomains),
        len(new_findings),
        result.total_subdomains,
        result.total_findings,
    )
    return result
