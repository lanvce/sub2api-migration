#!/bin/bash
# Deploy hk-migration-sidecar onto the host that already runs new-api.
# Usage (on server): bash deploy.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
ENV_FILE="${ROOT}/.env"
COMPOSE="docker compose -f ${ROOT}/docker-compose.yml --env-file ${ENV_FILE}"

if [[ ! -f "${ENV_FILE}" ]]; then
  echo "missing ${ENV_FILE}" >&2
  exit 1
fi

echo "==> building image"
${COMPOSE} build

echo "==> starting"
${COMPOSE} up -d --remove-orphans

echo "==> health"
for i in 1 2 3 4 5 6 7 8 9 10; do
  if curl -fsS http://127.0.0.1:8290/health >/dev/null; then
    echo "healthy"
    curl -fsS http://127.0.0.1:8290/health
    echo
    exit 0
  fi
  sleep 1
done
echo "sidecar failed health check" >&2
${COMPOSE} logs --tail=80
exit 1
