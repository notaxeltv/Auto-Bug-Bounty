"""Utility di logging ed esecuzione sicura di comandi esterni.

Le funzioni qui definite sono pensate per non far mai crashare la
pipeline principale: se un binario esterno (subfinder, httpx, nuclei,
naabu, ...) non e' disponibile nel PATH, o l'esecuzione fallisce per
timeout o errore di sistema, viene loggato un warning/errore e viene
restituita una lista vuota al chiamante.
"""

from __future__ import annotations

import logging
import shutil
import subprocess
from typing import Iterable, List, Optional

_LOG_CONFIGURED = False


def get_logger(name: str) -> logging.Logger:
    """Ritorna un logger configurato in modo consistente per tutto il progetto."""
    global _LOG_CONFIGURED
    if not _LOG_CONFIGURED:
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        )
        _LOG_CONFIGURED = True
    return logging.getLogger(name)


_logger = get_logger(__name__)


def run_cmd(
    args: List[str],
    stdin_lines: Optional[Iterable[str]] = None,
    timeout: int = 900,
) -> List[str]:
    """Esegue un comando esterno e ritorna le righe di stdout come lista.

    Comportamento "degrada senza crashare":
    - Se il binario (``args[0]``) non e' presente nel PATH (verificato via
      ``shutil.which``), loggua un WARNING e ritorna ``[]``.
    - Se il comando va in timeout, loggua un ERROR e ritorna ``[]``.
    - Se si verifica un ``OSError`` durante l'esecuzione, loggua un ERROR
      e ritorna ``[]``.

    Args:
        args: lista di argomenti del comando, es. ``["subfinder", "-d", "example.com"]``.
        stdin_lines: righe opzionali da passare sullo stdin del processo.
        timeout: timeout in secondi (default 900).

    Returns:
        Lista di righe di stdout (senza newline finale), oppure lista vuota.
    """
    if not args:
        _logger.warning("run_cmd chiamato con lista di argomenti vuota")
        return []

    binary = args[0]
    if shutil.which(binary) is None:
        _logger.warning(
            "Binario '%s' non trovato nel PATH: salto l'esecuzione e ritorno "
            "una lista vuota. Installa il tool (vedi scripts/install_tools.sh) "
            "per abilitare questa funzionalita'.",
            binary,
        )
        return []

    input_data = None
    if stdin_lines is not None:
        input_data = "\n".join(stdin_lines) + "\n"

    try:
        result = subprocess.run(
            args,
            input=input_data,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        _logger.error(
            "Comando '%s' andato in timeout dopo %s secondi", " ".join(args), timeout
        )
        return []
    except OSError as exc:
        _logger.error("Errore di sistema eseguendo '%s': %s", " ".join(args), exc)
        return []

    if result.returncode != 0 and result.stderr:
        _logger.warning(
            "Comando '%s' terminato con codice %s. stderr: %s",
            " ".join(args),
            result.returncode,
            result.stderr.strip()[:500],
        )

    stdout = result.stdout or ""
    lines = [line for line in stdout.splitlines() if line.strip()]
    return lines
