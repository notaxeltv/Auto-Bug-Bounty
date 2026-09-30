#!/usr/bin/env bash
#
# Installa i tool di ProjectDiscovery usati da autobb (subfinder, httpx,
# nuclei, naabu) tramite "go install", e aggiorna i template di nuclei.
#
# Richiede Go installato e disponibile nel PATH.

set -euo pipefail

if ! command -v go >/dev/null 2>&1; then
  echo "ERRORE: 'go' non trovato nel PATH." >&2
  echo "Installa Go (https://go.dev/dl/) e riprova." >&2
  exit 1
fi

echo "==> Installazione subfinder..."
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

echo "==> Installazione httpx..."
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

echo "==> Installazione nuclei..."
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

echo "==> Installazione naabu..."
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest

GOBIN="$(go env GOBIN)"
if [ -z "${GOBIN}" ]; then
  GOBIN="$(go env GOPATH)/bin"
fi

echo "==> Tool installati in: ${GOBIN}"
echo "    Assicurati che questa directory sia nel tuo PATH."

if command -v nuclei >/dev/null 2>&1; then
  echo "==> Aggiornamento template nuclei..."
  nuclei -update-templates || echo "AVVISO: aggiornamento template nuclei non riuscito (continuo comunque)."
else
  echo "AVVISO: 'nuclei' non trovato nel PATH dopo l'installazione (controlla GOBIN)."
  echo "        Salto l'aggiornamento dei template."
fi

echo "==> Installazione completata."
