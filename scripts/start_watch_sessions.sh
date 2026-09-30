#!/usr/bin/env bash
#
# Avvia una sessione tmux dedicata per ciascun target AUTORIZZATO
# presente in config/targets.yaml, eseguendo il monitoraggio continuo
# ("autobb watch --target <nome>"). Salta i target non autorizzati e le
# sessioni tmux gia' attive.

set -euo pipefail

if ! command -v tmux >/dev/null 2>&1; then
  echo "ERRORE: 'tmux' non trovato nel PATH. Installalo per usare questo script." >&2
  exit 1
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}"

# Ottiene la lista dei target autorizzati, uno per riga, tramite
# autobb.config.load_targets (evita di duplicare il parsing YAML in bash).
AUTHORIZED_TARGETS="$(python3 -c '
from autobb.config import load_targets

for name, target in load_targets().items():
    if target.authorized:
        print(name)
')"

if [ -z "${AUTHORIZED_TARGETS}" ]; then
  echo "Nessun target AUTORIZZATO trovato in config/targets.yaml. Nulla da avviare."
  exit 0
fi

while IFS= read -r target_name; do
  [ -z "${target_name}" ] && continue

  session_name="autobb-${target_name}"

  if tmux has-session -t "${session_name}" 2>/dev/null; then
    echo "[SKIP] Sessione tmux '${session_name}' gia' attiva."
    continue
  fi

  echo "[START] Avvio sessione tmux '${session_name}' per il target '${target_name}'..."
  tmux new-session -d -s "${session_name}" -c "${REPO_ROOT}" \
    "python3 -m autobb.cli watch --target ${target_name}"
done <<< "${AUTHORIZED_TARGETS}"

echo "Fatto. Usa 'tmux ls' per vedere le sessioni attive e 'tmux attach -t autobb-<nome>' per collegarti."
