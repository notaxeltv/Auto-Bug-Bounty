"""Notifiche via webhook (Slack/Discord/generico) sulle novita' rilevate."""

from __future__ import annotations

from .diff import RunResult
from .utils import get_logger

_logger = get_logger(__name__)


def format_message(target_name: str, result: RunResult) -> str:
    """Costruisce un messaggio testuale con le novita' rilevate per il target."""
    lines = [f"[autobb] Novita' per il target '{target_name}'"]

    if result.new_subdomains:
        lines.append(f"\nNuovi sottodomini ({len(result.new_subdomains)}):")
        for sub in result.new_subdomains:
            lines.append(f"  - {sub}")

    if result.new_findings:
        lines.append(f"\nNuovi finding ({len(result.new_findings)}):")
        for finding in result.new_findings:
            lines.append(
                f"  - [{finding.severity.upper()}] {finding.name} "
                f"({finding.template_id}) su {finding.matched_at}"
            )

    if not result.new_subdomains and not result.new_findings:
        lines.append("\nNessuna novita' rilevata in questo ciclo.")

    lines.append(
        "\nRicorda: i finding richiedono verifica manuale prima di qualsiasi "
        "submission. Nessuna azione automatica viene eseguita da autobb."
    )

    return "\n".join(lines)


def send_notification(webhook_url: str, message: str) -> bool:
    """Invia ``message`` a ``webhook_url`` via POST.

    Se ``webhook_url`` e' vuoto, salta l'invio (nessun errore). Se la
    libreria ``requests`` non e' installata, loggua un warning e non
    invia nulla.

    Returns:
        True se l'invio e' riuscito, False altrimenti (incluso il caso
        di skip volontario per webhook vuoto o libreria mancante).
    """
    if not webhook_url:
        _logger.info("send_notification: webhook_url vuoto, salto l'invio della notifica")
        return False

    try:
        import requests
    except ImportError:
        _logger.warning(
            "send_notification: libreria 'requests' non installata, impossibile "
            "inviare la notifica. Esegui 'pip install requests'."
        )
        return False

    payload = {"text": message, "content": message}
    try:
        response = requests.post(webhook_url, json=payload, timeout=15)
        response.raise_for_status()
    except Exception as exc:  # noqa: BLE001 - qualsiasi errore di rete non deve crashare
        _logger.error("send_notification: invio fallito verso '%s': %s", webhook_url, exc)
        return False

    _logger.info("send_notification: notifica inviata con successo a '%s'", webhook_url)
    return True
