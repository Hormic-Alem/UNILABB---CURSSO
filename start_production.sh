#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

export FLASK_DEBUG="${FLASK_DEBUG:-false}"
export SESSION_COOKIE_SECURE="${SESSION_COOKIE_SECURE:-false}"

if [[ -z "${SECRET_KEY:-}" ]]; then
  echo "ERROR: Debes definir SECRET_KEY antes de iniciar en producción." >&2
  exit 1
fi

exec gunicorn --bind 0.0.0.0:${PORT:-8000} --workers ${WEB_CONCURRENCY:-2} "app:app"
