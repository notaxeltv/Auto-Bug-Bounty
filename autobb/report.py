"""Generazione di BOZZE di report Markdown per i finding rilevati.

Ogni report generato e' esplicitamente marcato come BOZZA: NON deve
essere sottomesso automaticamente a nessun programma di bug bounty. La
submission resta sempre un passaggio manuale, dopo che un umano ha
completato la checklist di verifica.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path

from .config import Target
from .scan import Finding
from .utils import get_logger

_logger = get_logger(__name__)

REPORTS_SUBDIR = "reports"


def _slugify(value: str) -> str:
    value = value.strip().lower()
    value = re.sub(r"[^a-z0-9]+", "-", value)
    return value.strip("-") or "report"


def generate_finding_report(target: Target, finding: Finding, data_dir: Path) -> Path:
    """Genera una BOZZA di report Markdown per ``finding`` e ritorna il path.

    Il file viene creato in ``<data_dir>/<target_name>/reports/`` con un
    nome derivato dal template_id e dal timestamp, per evitare
    sovrascritture accidentali tra run diversi.
    """
    data_dir = Path(data_dir)
    reports_dir = data_dir / target.name / REPORTS_SUBDIR
    reports_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now(timezone.utc)
    timestamp_str = timestamp.strftime("%Y%m%dT%H%M%SZ")
    filename = f"{timestamp_str}_{_slugify(finding.template_id)}.md"
    path = reports_dir / filename

    reference_lines = (
        "\n".join(f"- {ref}" for ref in finding.reference) if finding.reference else "- (nessun riferimento disponibile)"
    )

    content = f"""# [BOZZA - NON SOTTOMETTERE AUTOMATICAMENTE] {finding.name or finding.template_id}

> **ATTENZIONE**: questo e' un report generato automaticamente da autobb.
> E' una **BOZZA** che richiede revisione umana completa. NON va inviata
> al programma di bug bounty finche' la checklist sottostante non e'
> stata completata manualmente.

## Informazioni generali

- **Target**: {target.name}
- **Program URL**: {target.program_url or "(non specificato)"}
- **Template ID**: {finding.template_id}
- **Severita' (dichiarata dal template)**: {finding.severity}
- **Host**: {finding.host}
- **Matched at**: {finding.matched_at}
- **Timestamp generazione**: {timestamp.isoformat()}

## Descrizione

{finding.description or "(nessuna descrizione disponibile dal template)"}

## Riferimenti

{reference_lines}

## Checklist di verifica manuale (DA COMPLETARE PRIMA DI QUALSIASI SUBMISSION)

- [ ] Ho verificato manualmente che si tratti di un VERO POSITIVO (non falso positivo del template)
- [ ] Ho verificato che il target/host sia effettivamente in SCOPE per il programma indicato
- [ ] Ho valutato l'IMPATTO reale della vulnerabilita' nel contesto specifico
- [ ] Ho documentato i PASSI DI RIPRODUZIONE completi e riproducibili
- [ ] Ho rispettato i RATE LIMIT e le regole del programma durante ogni verifica aggiuntiva
- [ ] Ho verificato di non aver eseguito alcuna forma di exploitation attiva oltre al rilevamento
- [ ] Solo dopo aver completato quanto sopra, procedo alla submission MANUALE sulla piattaforma del programma

---
*Generato automaticamente da autobb - questa e' una bozza, la submission resta sempre manuale.*
"""

    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content)

    _logger.info("generate_finding_report: bozza creata in '%s'", path)
    return path
