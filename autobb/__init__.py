"""autobb - Automazione ETICA per Bug Bounty (recon + vulnerability scanning).

Questo pacchetto fornisce un framework di supporto per programmi di bug
bounty AUTORIZZATI: enumerazione di sottodomini, probing di host live,
scansione di vulnerabilità note tramite template pubblici, calcolo del
diff tra run successivi, notifiche e generazione di BOZZE di report.

Principi guida (guardrail):
- Nessuna scansione viene eseguita se il target non è marcato
  esplicitamente come ``authorized: true`` nella configurazione.
- Nessuna funzionalità di exploitation attiva, brute force o attacco
  offensivo: il progetto si limita a recon passivo/attivo non invasivo
  e a scansioni basate su template di vulnerabilità pubblici (nuclei).
- Nessuna submission o incasso automatico di ricompense: i report
  generati sono sempre BOZZE da revisionare e inviare manualmente,
  dopo verifica umana (vero positivo, scope, impatto, riproduzione).
- Ogni interazione con un tool esterno degrada in modo controllato
  (log di warning) se il binario non è disponibile, senza mai
  interrompere l'intera pipeline con un crash.

Usa questo strumento esclusivamente nell'ambito di programmi di bug
bounty o penetration test per cui hai un'autorizzazione esplicita e
scritta dal proprietario del target.
"""

__version__ = "0.1.0"
