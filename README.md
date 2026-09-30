# autobb — Automazione ETICA per Bug Bounty

`autobb` è un framework Python di supporto per programmi di **bug bounty
autorizzati**: automatizza le fasi di *recon* (enumerazione sottodomini,
probing di host live) e di *vulnerability scanning* basato su template
pubblici, calcola il diff tra run successivi, invia notifiche sulle
novità e genera **bozze** di report da revisionare manualmente.

## Cosa fa

- **Recon**: enumera i sottodomini di ogni target (`subfinder`) e
  individua gli host live via probing HTTP (`httpx`, con status code,
  titolo, tech detection).
- **Scanning**: esegue `nuclei` sugli host live usando i template
  pubblici di vulnerabilità, filtrando per severità configurabile.
- **Port scan opzionale**: `naabu`, disattivato di default, da attivare
  solo se il programma/scope lo consente esplicitamente.
- **Diff tra run**: confronta ogni esecuzione con lo stato precedente
  salvato su disco, individuando nuovi sottodomini e nuovi finding
  (deduplicati tramite fingerprint), sia al primo run che nei successivi.
- **Notifiche**: invia un messaggio (webhook Slack/Discord/generico) con
  le novità rilevate, se configurato.
- **Bozze di report**: per ogni nuovo finding genera un file Markdown in
  `data/<target>/reports/`, con una checklist di verifica manuale.
- **Monitoraggio continuo**: `autobb watch` esegue il ciclo a intervalli
  regolari, pensato per girare dentro una sessione `screen`/`tmux`
  dedicata per target (vedi `scripts/start_watch_sessions.sh`).

## Cosa NON fa (e perché)

- **Nessuna exploitation attiva**: `autobb` esegue solo detection non
  invasiva basata su template pubblici (nuclei) e recon passivo/attivo
  non distruttivo (subfinder, httpx, naabu opzionale). Non contiene e
  non deve contenere logica di exploitation, brute force o attacco
  offensivo.
- **Nessuna scansione senza `authorized: true`**: ogni target ha un
  campo `authorized` nella configurazione. `Target.ensure_authorized()`
  viene chiamato **prima di qualsiasi chiamata di rete**, sia in `run`
  che in `watch`. Se il target non è autorizzato, il comando mostra
  `[SKIP]` con un messaggio chiaro e **non esegue alcuna richiesta** verso
  il target.
- **Nessuna submission o incasso automatico di ricompense**: i report
  generati sono sempre **bozze** marcate come tali, con una checklist da
  completare manualmente (verifica del vero positivo, dello scope,
  dell'impatto, dei passi di riproduzione, del rispetto dei rate limit)
  prima di qualsiasi invio al programma. La submission e la riscossione
  di eventuali ricompense restano sempre azioni umane e manuali.

## Installazione

```bash
pip install -e .
./scripts/install_tools.sh   # installa subfinder/httpx/nuclei/naabu via "go install"
```

`scripts/install_tools.sh` richiede Go installato e disponibile nel
`PATH`; se manca, lo script termina con un errore chiaro invece di
proseguire silenziosamente.

Nota: anche senza i tool esterni installati, `autobb` funziona: ogni
funzione che invoca un binario esterno mancante registra un warning e
ritorna un risultato vuoto, senza mai far crashare la pipeline.

## Setup

```bash
autobb init
```

Questo comando crea `config/targets.yaml` e `config/settings.yaml` a
partire dai template `config/targets.example.yaml` e
`config/settings.example.yaml` (se non esistono già). Questi due file
"reali" sono in `.gitignore` e non vanno mai committati con dati reali.

Edita `config/targets.yaml` per aggiungere i tuoi target:

```yaml
targets:
  - name: my-program
    domains:
      - my-target.com
    authorized: true   # SOLO se hai un'autorizzazione esplicita e reale
    program_url: "https://bugbounty.my-target.com"
    scope_notes: "In scope: *.my-target.com"
    rate_limit_rps: 5
    severities: [low, medium, high, critical]
```

Edita `config/settings.yaml` per configurare webhook di notifica, nomi
dei binari dei tool, parametri di nuclei/naabu e l'intervallo di
monitoraggio.

## Uso della CLI

| Comando | Descrizione |
|---|---|
| `autobb init` | Crea `targets.yaml`/`settings.yaml` da template. |
| `autobb list` | Elenca i target con stato `AUTORIZZATO`/`NON AUTORIZZATO`. |
| `autobb run --target NOME` | Esegue un ciclo singolo (recon+scan+diff+notifica) su un target. |
| `autobb run --all` | Esegue un ciclo singolo su tutti i target configurati. |
| `autobb watch --target NOME [--interval N]` | Monitoraggio continuo (loop) di un target. |
| `autobb reports --target NOME` | Elenca le bozze di report generate per un target. |

Se un target non è autorizzato, `run`/`watch` mostrano `[SKIP]` con un
messaggio esplicativo e terminano senza errori e senza eseguire alcuna
richiesta di rete.

Per il monitoraggio continuo su più target contemporaneamente, usa:

```bash
./scripts/start_watch_sessions.sh
```

che avvia una sessione `tmux` dedicata (`autobb-<nome-target>`) per
ciascun target autorizzato, saltando quelle già attive.

## Struttura del progetto

```
autobb/
  __init__.py       # versione e scopo del progetto
  utils.py           # logging e run_cmd (esecuzione sicura di tool esterni)
  config.py          # Target, Settings, ensure_authorized, load/init config
  recon.py           # enumerate_subdomains, probe_live_hosts
  scan.py            # run_nuclei, run_naabu, Finding
  diff.py            # compute_diff, RunResult, persistenza dello stato
  notify.py          # format_message, send_notification (webhook)
  report.py          # generate_finding_report (bozze Markdown)
  pipeline.py        # run_cycle: orchestratore del ciclo completo
  scheduler.py       # watch: loop continuo con gestione SIGINT/SIGTERM
  cli.py             # CLI click (init/list/run/watch/reports)
config/
  targets.example.yaml    # template target
  settings.example.yaml   # template impostazioni
scripts/
  install_tools.sh            # installa i tool ProjectDiscovery via go install
  start_watch_sessions.sh     # avvia sessioni tmux per i target autorizzati
tests/
  test_diff.py, test_config.py, test_report.py
data/                # stato persistito e bozze di report (gitignored)
```

## Uso responsabile

`autobb` è uno strumento di supporto, non un sistema "autonomo" di bug
hunting. Usalo solo:

- su domini/asset per cui hai un'autorizzazione esplicita e scritta
  (programma di bug bounty pubblico con questi asset in scope, o
  contratto di pentest firmato);
- rispettando i rate limit e le regole di scope del programma (il
  parametro `rate_limit_rps` esiste proprio per questo);
- trattando ogni finding come un'ipotesi da verificare manualmente, non
  come un risultato pronto per la submission;
- senza mai attivare funzionalità di exploitation attiva, brute force o
  attacco: questo progetto non le implementa e non deve implementarle.

La responsabilità legale ed etica dell'uso di questo strumento è
sempre dell'utente.

## Test

```bash
pip install -e .
pip install pytest
pytest -q
```
