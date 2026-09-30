"""Interfaccia a riga di comando di autobb, basata su click."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import click

from .config import (
    Target,
    UnauthorizedTargetError,
    get_target,
    init_config,
    load_settings,
    load_targets,
)
from .pipeline import run_cycle
from .scheduler import watch as watch_loop
from .utils import get_logger

_logger = get_logger(__name__)

REPORTS_SUBDIR = "reports"


@click.group()
def main() -> None:
    """autobb - framework di automazione ETICA per bug bounty.

    Scansiona SOLO target esplicitamente autorizzati. Nessuna
    exploitation attiva, nessuna submission automatica: sono sempre
    passaggi manuali.
    """


@main.command("init")
def cmd_init() -> None:
    """Crea config/targets.yaml e config/settings.yaml dai template."""
    init_config()
    click.echo("Configurazione inizializzata (o gia' presente) in config/.")
    click.echo(
        "Modifica config/targets.yaml e config/settings.yaml prima di eseguire scansioni."
    )


@main.command("list")
def cmd_list() -> None:
    """Elenca i target configurati con il loro stato di autorizzazione."""
    targets = load_targets()
    if not targets:
        click.echo("Nessun target configurato. Esegui 'autobb init' e modifica config/targets.yaml.")
        return

    for name, target in sorted(targets.items()):
        status = "AUTORIZZATO" if target.authorized else "NON AUTORIZZATO"
        domains = ", ".join(target.domains) if target.domains else "(nessun dominio)"
        click.echo(f"- {name} [{status}] domini: {domains}")


def _run_single_target(target: Target, settings) -> None:
    try:
        run_cycle(target, settings)
    except UnauthorizedTargetError as exc:
        click.echo(f"[SKIP] {exc}")


@main.command("run")
@click.option("--target", "target_name", default=None, help="Nome del target su cui eseguire un ciclo singolo.")
@click.option("--all", "run_all", is_flag=True, default=False, help="Esegue un ciclo su tutti i target configurati.")
def cmd_run(target_name: Optional[str], run_all: bool) -> None:
    """Esegue un ciclo singolo (recon + scan + diff + notifica) su uno o tutti i target."""
    if not target_name and not run_all:
        raise click.UsageError("Specifica --target NOME oppure --all")

    settings = load_settings()

    if run_all:
        targets = load_targets()
        if not targets:
            click.echo("Nessun target configurato.")
            return
        for target in targets.values():
            click.echo(f"== Target: {target.name} ==")
            _run_single_target(target, settings)
        return

    target = get_target(target_name)
    if target is None:
        click.echo(f"Target '{target_name}' non trovato in config/targets.yaml.")
        return

    _run_single_target(target, settings)


@main.command("watch")
@click.option("--target", "target_name", required=True, help="Nome del target da monitorare in continuo.")
@click.option("--interval", "interval_seconds", type=int, default=None, help="Intervallo in secondi tra i cicli (default: da settings).")
def cmd_watch(target_name: str, interval_seconds: Optional[int]) -> None:
    """Monitoraggio continuo di un target (loop con gestione SIGINT/SIGTERM)."""
    settings = load_settings()
    target = get_target(target_name)
    if target is None:
        click.echo(f"Target '{target_name}' non trovato in config/targets.yaml.")
        return

    try:
        target.ensure_authorized()
    except UnauthorizedTargetError as exc:
        click.echo(f"[SKIP] {exc}")
        return

    watch_loop(target, settings, interval_seconds)


@main.command("reports")
@click.option("--target", "target_name", required=True, help="Nome del target di cui elencare le bozze di report.")
def cmd_reports(target_name: str) -> None:
    """Elenca le bozze di report generate per un target."""
    settings = load_settings()
    reports_dir = Path(settings.data_dir) / target_name / REPORTS_SUBDIR

    if not reports_dir.exists():
        click.echo(f"Nessuna bozza di report trovata per '{target_name}' (directory '{reports_dir}' non esiste).")
        return

    report_files = sorted(reports_dir.glob("*.md"))
    if not report_files:
        click.echo(f"Nessuna bozza di report trovata per '{target_name}' in '{reports_dir}'.")
        return

    click.echo(f"Bozze di report per '{target_name}':")
    for report_file in report_files:
        click.echo(f"  - {report_file}")


if __name__ == "__main__":
    main()
