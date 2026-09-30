"""Monitoraggio continuo: esegue run_cycle a intervalli regolari.

Pensato per essere eseguito dentro una sessione screen/tmux dedicata per
ciascun target (vedi scripts/start_watch_sessions.sh), in modo da poter
essere fermato o ispezionato indipendentemente per ogni target.
"""

from __future__ import annotations

import signal
import time
from typing import Optional

from .config import Settings, Target
from .pipeline import run_cycle
from .utils import get_logger

_logger = get_logger(__name__)


class _StopRequested(Exception):
    """Usata internamente per interrompere il loop in modo pulito."""


def watch(
    target: Target, settings: Settings, interval_seconds: Optional[int] = None
) -> None:
    """Esegue ``run_cycle`` in loop ogni ``interval_seconds`` secondi.

    Gestisce SIGINT e SIGTERM per fermarsi in modo pulito DOPO il
    completamento del ciclo corrente (non interrompe un ciclo a meta').

    Args:
        target: il target da monitorare (deve essere autorizzato: il
            controllo viene comunque ripetuto ad ogni ciclo da
            ``run_cycle`` -> ``target.ensure_authorized()``).
        settings: le impostazioni globali.
        interval_seconds: intervallo tra i cicli in secondi; se ``None``
            usa ``settings.default_interval_seconds``.
    """
    interval = interval_seconds if interval_seconds is not None else settings.default_interval_seconds

    stop_flag = {"requested": False}

    def _handle_signal(signum, _frame):
        _logger.info(
            "watch[%s]: segnale %s ricevuto, mi fermo dopo il ciclo corrente",
            target.name,
            signum,
        )
        stop_flag["requested"] = True

    previous_sigint = signal.signal(signal.SIGINT, _handle_signal)
    previous_sigterm = signal.signal(signal.SIGTERM, _handle_signal)

    _logger.info(
        "watch[%s]: avvio monitoraggio continuo (intervallo=%ds)", target.name, interval
    )

    try:
        while not stop_flag["requested"]:
            try:
                run_cycle(target, settings)
            except Exception as exc:  # noqa: BLE001 - non deve fermare il loop
                _logger.error("watch[%s]: errore durante il ciclo: %s", target.name, exc)

            if stop_flag["requested"]:
                break

            # Attesa interrompibile: controlla periodicamente il flag di stop
            # cosi' un segnale arrivato durante l'attesa viene onorato subito.
            elapsed = 0
            step = 1
            while elapsed < interval and not stop_flag["requested"]:
                time.sleep(min(step, interval - elapsed))
                elapsed += step
    finally:
        signal.signal(signal.SIGINT, previous_sigint)
        signal.signal(signal.SIGTERM, previous_sigterm)
        _logger.info("watch[%s]: monitoraggio terminato", target.name)
