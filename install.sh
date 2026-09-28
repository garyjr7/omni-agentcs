#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

command -v docker >/dev/null 2>&1 || { echo "Docker no está instalado" >&2; exit 1; }
docker compose version >/dev/null 2>&1 || { echo "Docker Compose v2 no está instalado" >&2; exit 1; }

if [[ ! -f .env ]]; then
  cp .env.example .env
  echo "Se creó .env. Define PostgreSQL, JWT y el administrador antes de continuar." >&2
  exit 2
fi

required=(POSTGRES_PASSWORD JWT_SECRET_KEY NEXUS_ADMIN_EMAIL NEXUS_ADMIN_PASSWORD)
for key in "${required[@]}"; do
  value="$(sed -n "s/^${key}=//p" .env | tail -n 1)"
  [[ -n "$value" ]] || { echo "Falta $key en .env" >&2; exit 2; }
done

jwt_secret="$(sed -n 's/^JWT_SECRET_KEY=//p' .env | tail -n 1)"
admin_password="$(sed -n 's/^NEXUS_ADMIN_PASSWORD=//p' .env | tail -n 1)"
[[ ${#jwt_secret} -ge 32 ]] || { echo "JWT_SECRET_KEY debe tener al menos 32 caracteres" >&2; exit 2; }
[[ ${#admin_password} -ge 12 ]] || { echo "NEXUS_ADMIN_PASSWORD debe tener al menos 12 caracteres" >&2; exit 2; }

mkdir -p data
docker compose build
docker compose up -d backend worker frontend
docker compose ps
echo "NEXUS inició. API local: http://127.0.0.1:${NEXUS_BACKEND_PORT:-8000}/health"
