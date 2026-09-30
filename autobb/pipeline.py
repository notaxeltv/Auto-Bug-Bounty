"""Orchestratore del ciclo completo di recon + scan + diff + notifica."""

from __future__ import annotations

from pathlib import Path

from .config import Settings, Target
from .diff import RunResult, compute_diff
from .notify import format_message, send_notification
from .recon import enumerate_subdomains, probe_live_hosts
from .report import generate_finding_report
from .scan import run_naabu, run_nuclei
from .utils import get_logger

_logger = get_logger(__name__)


def run_cycle(target: Target, settings: Settings) -> RunResult:
    """Esegue un ciclo completo per ``target``.

    Ordine delle operazioni:
    1. ``target.ensure_authorized()`` - blocca se il target non e'
       autorizzato, PRIMA di qualsiasi chiamata di rete.
    2. ``enumerate_subdomains`` -> ``probe_live_hosts`` -> ``run_nuclei``
    3. ``run_naabu`` (side effect opzionale, disattivato di default)
    4. ``compute_diff`` per individuare le novita' rispetto al run precedente
    5. Se ci sono nuovi finding, genera le bozze di report
    6. Se ci sono novita' (sottodomini o finding), invia la notifica

    Returns:
        Il ``RunResult`` calcolato da ``compute_diff``.
    """
    target.ensure_authorized()

    _logger.info("run_cycle: avvio ciclo per target '%s'", target.name)

    subdomains = enumerate_subdomains(target, settings)
    live_hosts = probe_live_hosts(target, settings, subdomains)
    findings = run_nuclei(target, settings, live_hosts)

    # Port scan opzionale: side effect, non influenza il diff.
    run_naabu(target, settings, live_hosts)

    data_dir = Path(settings.data_dir)
    result = compute_diff(data_dir, target.name, subdomains, findings)

    if result.new_findings:
        for finding in result.new_findings:
            generate_finding_report(target, finding, data_dir)

    if result.new_subdomains or result.new_findings:
        message = format_message(target.name, result)
        send_notification(settings.webhook_url, message)
    else:
        _logger.info("run_cycle: nessuna novita' per target '%s', nessuna notifica inviata", target.name)

    return result
