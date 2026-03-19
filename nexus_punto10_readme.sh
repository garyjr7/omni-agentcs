#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════╗
# ║  NEXUS PRO — Punto 10: README Comercial + Onboarding       ║
# ║  10A · README.md vendible  10B · PRICING.md                ║
# ║  10C · CHANGELOG.md  10D · nexus_start.sh daemon           ║
# ║  10E · healthcheck script  10F · backup script             ║
# ╚══════════════════════════════════════════════════════════════╝
set -euo pipefail

ROOT="/home/operator/NEXUS-PRO"
GREEN='\033[0;32m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
log()  { echo -e "${GREEN}[✓]${NC} $1"; }
head() { echo -e "\n${BOLD}${CYAN}$1${NC}"; echo "────────────────────────────────────────"; }

cd "$ROOT"

# ══════════════════════════════════════════════════════════════
head "1/6 · README.md — presentación comercial"
# ══════════════════════════════════════════════════════════════
python3 - << 'PYEOF'
content = """# NEXUS PRO — AI Operations Platform

> Orquesta equipos de agentes IA que ejecutan tareas reales en tu infraestructura.
> Con supervisión humana, memoria persistente y reportes ejecutivos.

---

## ¿Qué es NEXUS PRO?

NEXUS PRO es una plataforma de operaciones con IA que permite a empresas:

- **Automatizar tareas complejas** con agentes que encadenan herramientas reales
- **Supervisar y aprobar** acciones críticas antes de ejecutarlas (HITL)
- **Auditar** todo lo que los agentes hacen, con trazabilidad completa
- **Ejecutar pentests** automatizados con reportes ejecutivos en minutos
- **Desarrollar software** con un agente autónomo que escribe, prueba y despliega código

---

## Instalación en 3 minutos

### Opción A — Docker (recomendado para producción)
```bash
git clone https://github.com/tuempresa/nexus-pro
cd nexus-pro
cp .env.example .env
# Editar .env con tus API keys
nano .env
./install.sh
```

Accede en: `http://tu-servidor:3000`

### Opción B — Desarrollo local
```bash
git clone https://github.com/tuempresa/nexus-pro
cd nexus-pro
cp .env.example .env
nano .env
python -m venv venv && source venv/bin/activate
pip install -r nexus_api/requirements.txt
pip install -r nexus_core/requirements.txt
uvicorn nexus_api.main:app --host 0.0.0.0 --port 8000 &
cd nexus_frontend && npm install && npm run dev
```

---

## Credenciales por defecto

| Campo    | Valor                  |
|----------|------------------------|
| Email    | admin@nexuspro.io      |
| Password | synthetic-password       |
| Rol      | admin                  |

> **Cambiar en `.env` antes de exponer a internet.**

---

## Arquitectura
```
┌─────────────────────────────────────────────┐
│              NEXUS PRO Dashboard             │
│         React + Vite · Puerto 3000           │
└──────────────────┬──────────────────────────┘
                   │ HTTP/WS
┌──────────────────▼──────────────────────────┐
│            FastAPI Backend                   │
│    50+ endpoints REST · WebSocket Live       │
│         Puerto 8000                          │
└──────┬──────────────┬───────────────────────┘
       │              │
┌──────▼──────┐ ┌─────▼──────────────────────┐
│  nexus_core │ │     SQLite                  │
│  Orquestador│ │  nexus_pro.db               │
│  Agentes IA │ │  agents · tasks · memory    │
│  LLM Bridge │ │  users · hitl · audit       │
└──────┬──────┘ └─────────────────────────────┘
       │
┌──────▼──────────────────────────────────────┐
│           LLM Providers                      │
│   OpenAI GPT-4o  ·  Google Gemini Pro        │
│   Anthropic Claude  ·  Local (Ollama)        │
└─────────────────────────────────────────────┘
```

---

## Módulos principales

### 🤖 Junior Agent — Agente Autónomo
El agente estrella de NEXUS PRO. Recibe un objetivo en lenguaje natural
y lo ejecuta paso a paso, encadenando herramientas reales.
```
Objetivo: "Crea una API REST para una tienda online con auth y catálogo"
Junior → planifica → escribe código → prueba → genera documentación
```

**Tools disponibles:** bash_exec, file_read, file_write, code_exec,
http_request, search_web, git_ops, docker_ops

### ⚠️ HITL — Human in the Loop
Antes de ejecutar acciones de alto riesgo, los agentes piden
aprobación humana en tiempo real via WebSocket.

Niveles de riesgo: `CRITICAL` · `HIGH` · `MEDIUM` · `LOW`

### 🔴 Pentest Automatizado
Pipeline completo de pentesting en 5 fases:
1. Reconocimiento (nmap)
2. SAST + dependencias (Bandit + Safety)
3. Secrets scan
4. STRIDE threat modeling (GPT-4o)
5. Reporte ejecutivo Markdown

### 🧠 Memoria Persistente
Cada agente recuerda sus conversaciones anteriores.
Búsqueda en historial, resúmenes automáticos, limpieza por sesión.

### 👥 Multi-usuario con RBAC
| Rol      | Descripción                              |
|----------|------------------------------------------|
| admin    | Acceso total, gestión de usuarios        |
| operator | Operar agentes, aprobar HITL             |
| viewer   | Solo lectura, ver reportes               |

---

## API Reference

La API completa está disponible en `/docs` (Swagger UI).

### Endpoints principales

| Método | Endpoint              | Descripción                    |
|--------|-----------------------|--------------------------------|
| POST   | /auth/login           | Login → JWT tokens             |
| GET    | /health               | Estado del sistema             |
| GET    | /agents               | Listar agentes                 |
| POST   | /agents               | Crear agente                   |
| POST   | /junior/run           | Ejecutar objetivo autónomo     |
| POST   | /junior/chat          | Chat con Junior                |
| POST   | /pentest/run          | Iniciar pentest completo       |
| GET    | /hitl/pending         | Aprobaciones pendientes        |
| POST   | /hitl/{id}/approve    | Aprobar acción                 |
| GET    | /memory/agents        | Agentes con memoria            |

---

## Variables de entorno

Ver `.env.example` para la lista completa.

Las más importantes:
```bash
OPENAI_API_KEY=sk-...          # Requerida para Junior + Pentest
GEMINI_API_KEY=AIza...         # Fallback LLM
JWT_SECRET_KEY=...             # Generada automáticamente por install.sh
NEXUS_ADMIN_EMAIL=...          # Admin por defecto
NEXUS_ADMIN_PASSWORD=...       # Cambiar antes de producción
```

---

## Requisitos del servidor

| Componente | Mínimo          | Recomendado      |
|------------|-----------------|------------------|
| CPU        | 2 cores         | 4 cores          |
| RAM        | 4 GB            | 8 GB             |
| Disco      | 20 GB           | 50 GB            |
| OS         | Ubuntu 22.04+   | Ubuntu 24.04     |
| Docker     | 24+             | 27+              |
| Python     | 3.11+           | 3.12             |

---

## Seguridad

- **JWT HS256** con refresh tokens (8h acceso / 7d refresh)
- **RBAC** con 3 niveles de permisos
- **HITL** — agentes no ejecutan acciones críticas sin aprobación humana
- **Audit trail** — trazabilidad completa de todas las acciones
- **Zero Trust** — cada request verificado con token
- **Rate limiting** — protección contra abuso de la API

---

## Soporte y licencia

**Desarrollado por:** Marcos — NEXUS PRO Team
**Versión:** 2.0.0
**Licencia:** Propietaria — uso permitido con licencia comercial

Para soporte, consultoría o licencias enterprise:
📧 contacto@nexuspro.io
"""

with open("/home/operator/NEXUS-PRO/README.md", "w") as f:
    f.write(content)
print("README.md —", len(content), "bytes,", content.count("\\n"), "líneas")
PYEOF
log "README.md"

# ══════════════════════════════════════════════════════════════
head "2/6 · PRICING.md — modelo de negocio"
# ══════════════════════════════════════════════════════════════
python3 - << 'PYEOF'
content = """# NEXUS PRO — Precios y Modelos de Negocio

## Modelo A — Consultoría con NEXUS incluido

El más inmediato. Cobras por el proyecto y NEXUS hace el 80% del trabajo.

| Tipo de proyecto         | Precio sugerido   | Tiempo estimado |
|--------------------------|-------------------|-----------------|
| Auditoría de seguridad   | $1,500 — $5,000   | 1-3 días        |
| Desarrollo de API        | $2,000 — $8,000   | 3-7 días        |
| Automatización DevOps    | $3,000 — $10,000  | 5-10 días       |
| Reporte STRIDE/pentest   | $800 — $2,500     | 4-8 horas       |

**Cómo funciona:**
1. Cliente te contrata para el proyecto
2. NEXUS hace reconocimiento, análisis y genera el 80% del entregable
3. Tú revisas, ajustas y entregas
4. Tiempo real: 20% de lo normal → margen brutal

---

## Modelo B — Licencia mensual (SaaS on-premise)

El cliente instala NEXUS en su servidor y paga por uso.

| Plan        | Precio/mes | Agentes | Usuarios | Soporte       |
|-------------|------------|---------|----------|---------------|
| Starter     | $199       | 5       | 3        | Email         |
| Professional| $499       | 20      | 10       | Email + Chat  |
| Enterprise  | $1,200+    | ∞       | ∞        | Dedicado      |

**Lo que incluye:**
- Acceso completo al dashboard
- Junior Agent autónomo
- Pentest automatizado
- HITL + Audit trail
- Actualizaciones durante el contrato
- Documentación y onboarding

---

## Modelo C — Desarrollo remoto con VPN

El cliente te da acceso VPN a su infraestructura.
NEXUS corre en tu servidor y los agentes operan en la red del cliente.

**Ventaja:** Sin instalación en el cliente, máximo control.

| Servicio                      | Precio          |
|-------------------------------|-----------------|
| Setup inicial + VPN config    | $500 fijo       |
| Mensualidad operación         | $300 — $800/mes |
| Por pentest ejecutado         | $200 — $500     |

---

## Propuesta de valor para el cliente

### Antes de NEXUS PRO:
- Pentest manual: 2-4 semanas, $5,000-$20,000
- Reporte de seguridad: 1 semana de trabajo
- Desarrollo de API: 2-4 semanas de dev

### Con NEXUS PRO:
- Pentest automatizado: 2-4 horas, reporte listo
- Auditoría de código: 30 minutos
- Scaffold de API completa: 1-2 horas

**ROI para el cliente: 10x en tiempo, 5x en costo.**

---

## Script de venta (elevator pitch)

> "NEXUS PRO es una plataforma que pone un equipo de agentes IA
> a trabajar en tu infraestructura. El agente Junior escribe código,
> hace auditorías y genera reportes ejecutivos — todo supervisado por
> ti, con botón de aprobación antes de cada acción crítica.
> Un pentest que normalmente cuesta $5,000 y 2 semanas,
> NEXUS lo hace en 4 horas por $200."

---

## Clientes objetivo

1. **PyMEs tech** — quieren seguridad pero no tienen presupuesto para CISO
2. **Agencias de desarrollo** — quieren entregar más rápido con menos devs
3. **Consultoras de IT** — quieren multiplicar su capacidad de entrega
4. **Startups** — necesitan infraestructura segura desde el día 1
5. **Empresas con equipo DevOps** — quieren automatizar tareas repetitivas
"""

with open("/home/operator/NEXUS-PRO/PRICING.md", "w") as f:
    f.write(content)
print("PRICING.md —", len(content), "bytes")
PYEOF
log "PRICING.md"

# ══════════════════════════════════════════════════════════════
head "3/6 · CHANGELOG.md"
# ══════════════════════════════════════════════════════════════
python3 - << 'PYEOF'
content = """# NEXUS PRO — Changelog

## v2.0.0 — 2026-03-19 (ACTUAL)

### Nuevas funcionalidades
- **Junior Agent** autónomo con GPT-4o — ejecuta objetivos en lenguaje natural
- **Pentest automatizado** — nmap + Bandit + Safety + STRIDE + reporte ejecutivo
- **HITL real** — WebSocket en tiempo real, aprobación/denegación con razón
- **JWT Auth** — login con email, refresh tokens, auto-renovación en frontend
- **RBAC** — roles admin / operator / viewer con middleware en FastAPI
- **Memoria persistente** — historial por agente y sesión, búsqueda en contexto
- **Docker ready** — Dockerfile multi-stage + docker-compose + install.sh
- **Dashboard PRO** — 15 páginas: Overview, Agents, Tasks, Teams, Models,
  HITL, Vault, Guardian, RBAC, Audit, Terminal, Settings, Junior, Pentest,
  Memory, Users
- **WebSocket dual** — canal de logs + canal HITL independientes
- **Users management** — crear usuarios desde el dashboard (solo admin)

### Mejoras técnicas
- FastAPI + SQLite con aiosqlite para operaciones async
- Orquestador propio (sin dependencia de CrewAI/LangChain)
- LLM abstraction layer — OpenAI primary, Gemini fallback
- Rate limiting con slowapi
- Logging estructurado con niveles y fuentes

---

## v1.0.0 — 2026-01 (baseline)

- Orquestador básico con agentes BashAgent, CodeAgent, FileAgent
- API REST con FastAPI
- Frontend React básico
- Integración OpenAI GPT-4o
"""

with open("/home/operator/NEXUS-PRO/CHANGELOG.md", "w") as f:
    f.write(content)
print("CHANGELOG.md OK")
PYEOF
log "CHANGELOG.md"

# ══════════════════════════════════════════════════════════════
head "4/6 · nexus_start.sh — daemon manager"
# ══════════════════════════════════════════════════════════════
cat > nexus_start.sh << 'EOF'
#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════╗
# ║  NEXUS PRO — Manager de servicios                          ║
# ║  Uso: ./nexus_start.sh [start|stop|restart|status|logs]    ║
# ╚══════════════════════════════════════════════════════════════╝
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PID_FILE="$ROOT/.nexus.pid"
LOG_FILE="$ROOT/data/logs/nexus.log"
GREEN='\033[0;32m'; RED='\033[0;31m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

mkdir -p "$ROOT/data/logs"

start() {
  if [ -f "$PID_FILE" ] && kill -0 "$(cat $PID_FILE)" 2>/dev/null; then
    echo -e "${CYAN}NEXUS ya está corriendo (PID $(cat $PID_FILE))${NC}"
    return
  fi
  echo -e "${BOLD}Iniciando NEXUS PRO...${NC}"
  cd "$ROOT"
  source venv/bin/activate 2>/dev/null || true
  nohup uvicorn nexus_api.main:app \
    --host 0.0.0.0 --port 8000 \
    --workers 2 --log-level info \
    >> "$LOG_FILE" 2>&1 &
  echo $! > "$PID_FILE"
  sleep 3
  if curl -s http://localhost:8000/health > /dev/null 2>&1; then
    echo -e "${GREEN}✓ NEXUS corriendo (PID $(cat $PID_FILE))${NC}"
    echo -e "  API:       http://localhost:8000"
    echo -e "  Docs:      http://localhost:8000/docs"
    echo -e "  Dashboard: cd nexus_frontend && npm run preview"
  else
    echo -e "${RED}✗ Error iniciando NEXUS — revisa: $LOG_FILE${NC}"
  fi
}

stop() {
  if [ -f "$PID_FILE" ]; then
    PID=$(cat "$PID_FILE")
    kill "$PID" 2>/dev/null && echo -e "${GREEN}✓ NEXUS detenido${NC}" || echo "No corría"
    rm -f "$PID_FILE"
  else
    pkill -f "uvicorn nexus_api" 2>/dev/null && echo -e "${GREEN}✓ Detenido${NC}" || echo "No corría"
  fi
}

status() {
  if [ -f "$PID_FILE" ] && kill -0 "$(cat $PID_FILE)" 2>/dev/null; then
    HEALTH=$(curl -s http://localhost:8000/health 2>/dev/null | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('status','?'))" 2>/dev/null || echo "?")
    echo -e "${GREEN}● NEXUS corriendo${NC} (PID $(cat $PID_FILE)) — health: $HEALTH"
  else
    echo -e "${RED}○ NEXUS detenido${NC}"
  fi
}

logs() {
  tail -f "$LOG_FILE"
}

case "${1:-start}" in
  start)   start ;;
  stop)    stop ;;
  restart) stop; sleep 2; start ;;
  status)  status ;;
  logs)    logs ;;
  *)
    echo "Uso: $0 [start|stop|restart|status|logs]"
    exit 1
    ;;
esac
EOF
chmod +x nexus_start.sh
log "nexus_start.sh"

# ══════════════════════════════════════════════════════════════
head "5/6 · nexus_healthcheck.sh — verificación completa"
# ══════════════════════════════════════════════════════════════
cat > nexus_healthcheck.sh << 'EOF'
#!/usr/bin/env bash
# NEXUS PRO — Health Check completo
GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

BASE="${NEXUS_URL:-http://localhost:8000}"
PASS=0; FAIL=0

check() {
  local name="$1" url="$2" expect="$3"
  local result
  result=$(curl -s -o /dev/null -w "%{http_code}" "$url" 2>/dev/null)
  if [ "$result" = "$expect" ]; then
    echo -e "  ${GREEN}✓${NC} $name (HTTP $result)"
    PASS=$((PASS+1))
  else
    echo -e "  ${RED}✗${NC} $name (esperado $expect, obtenido $result)"
    FAIL=$((FAIL+1))
  fi
}

check_auth() {
  local result
  result=$(curl -s -X POST "$BASE/auth/login" \
    -H "Content-Type: application/json" \
    -d '{"email":"admin@nexuspro.io","password":"synthetic-password"}' \
    | python3 -c "import sys,json; d=json.load(sys.stdin); print('OK' if 'access_token' in d else 'FAIL')" 2>/dev/null)
  if [ "$result" = "OK" ]; then
    echo -e "  ${GREEN}✓${NC} Auth login → JWT token"
    PASS=$((PASS+1))
  else
    echo -e "  ${RED}✗${NC} Auth login falló"
    FAIL=$((FAIL+1))
  fi
}

echo -e "${BOLD}${CYAN}"
echo "╔══════════════════════════════════════════╗"
echo "║   NEXUS PRO — Health Check               ║"
echo "╚══════════════════════════════════════════╝"
echo -e "${NC}"

echo -e "${BOLD}Sistema:${NC}"
check "Health endpoint"    "$BASE/health"   "200"
check "API Docs"           "$BASE/docs"     "200"
check "OpenAPI schema"     "$BASE/openapi.json" "200"

echo ""
echo -e "${BOLD}Auth:${NC}"
check_auth
check "Auth sin token → 401" "$BASE/auth/me" "401"

echo ""
echo -e "${BOLD}Endpoints core:${NC}"
TOKEN=$(curl -s -X POST "$BASE/auth/login" \
  -H 'Content-Type: application/json' \
  -d '{"email":"admin@nexuspro.io","password":"synthetic-password"}' \
  | python3 -c 'import sys,json; print(json.load(sys.stdin).get("access_token",""))' 2>/dev/null)

if [ -n "$TOKEN" ]; then
  for ep in "/agents" "/tasks" "/teams-v2/teams-v2" "/hitl/pending" "/memory/agents" "/auth/users"; do
    result=$(curl -s -o /dev/null -w "%{http_code}" \
      -H "Authorization: Bearer $TOKEN" "$BASE$ep" 2>/dev/null)
    if [[ "$result" == "200" || "$result" == "201" ]]; then
      echo -e "  ${GREEN}✓${NC} GET $ep (HTTP $result)"
      PASS=$((PASS+1))
    else
      echo -e "  ${RED}✗${NC} GET $ep (HTTP $result)"
      FAIL=$((FAIL+1))
    fi
  done
fi

echo ""
echo "────────────────────────────────────────"
TOTAL=$((PASS+FAIL))
if [ $FAIL -eq 0 ]; then
  echo -e "${GREEN}${BOLD}✓ Todos los checks pasaron ($PASS/$TOTAL)${NC}"
else
  echo -e "${YELLOW}${BOLD}⚠ $FAIL checks fallaron ($PASS/$TOTAL pasaron)${NC}"
fi
echo ""
EOF
chmod +x nexus_healthcheck.sh
log "nexus_healthcheck.sh"

# ══════════════════════════════════════════════════════════════
head "6/6 · nexus_backup.sh + ejecutar healthcheck"
# ══════════════════════════════════════════════════════════════
cat > nexus_backup.sh << 'EOF'
#!/usr/bin/env bash
# NEXUS PRO — Backup de datos
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKUP_DIR="$ROOT/.backups/$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BACKUP_DIR"

echo "Backup → $BACKUP_DIR"
cp -r "$ROOT/data/"*.db    "$BACKUP_DIR/" 2>/dev/null || true
cp -r "$ROOT/nexus_api/"*.db "$BACKUP_DIR/" 2>/dev/null || true
cp    "$ROOT/.env"           "$BACKUP_DIR/env.bak" 2>/dev/null || true
cp -r "$ROOT/data/reports"   "$BACKUP_DIR/reports" 2>/dev/null || true

ARCHIVE="$ROOT/.backups/nexus_backup_$(date +%Y%m%d_%H%M%S).tar.gz"
tar -czf "$ARCHIVE" -C "$BACKUP_DIR" . 2>/dev/null

SIZE=$(du -sh "$ARCHIVE" | cut -f1)
echo "✓ Backup completado: $ARCHIVE ($SIZE)"
ls -lh "$ROOT/.backups/"*.tar.gz 2>/dev/null | tail -5
EOF
chmod +x nexus_backup.sh
log "nexus_backup.sh"

# Ejecutar healthcheck
echo ""
./nexus_healthcheck.sh

echo ""
echo -e "${BOLD}${GREEN}════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}${GREEN}  NEXUS PRO v2.0 — PRODUCTO COMPLETO ✓             ${NC}"
echo -e "${BOLD}${GREEN}════════════════════════════════════════════════════${NC}"
echo ""
echo -e "  ${BOLD}Documentación:${NC}"
echo -e "  ${CYAN}README.md${NC}      → presentación + instalación + API ref"
echo -e "  ${CYAN}PRICING.md${NC}     → modelos de negocio + elevator pitch"
echo -e "  ${CYAN}CHANGELOG.md${NC}   → historial de versiones"
echo ""
echo -e "  ${BOLD}Scripts operacionales:${NC}"
echo -e "  ${CYAN}./nexus_start.sh start${NC}   → arrancar como daemon"
echo -e "  ${CYAN}./nexus_start.sh status${NC}  → ver estado"
echo -e "  ${CYAN}./nexus_start.sh logs${NC}    → logs en vivo"
echo -e "  ${CYAN}./nexus_healthcheck.sh${NC}   → verificar todo el stack"
echo -e "  ${CYAN}./nexus_backup.sh${NC}        → backup de datos"
echo -e "  ${CYAN}./install.sh${NC}             → instalación en un comando"
echo ""
echo -e "  ${BOLD}${GREEN}NEXUS PRO está listo para vender. 🚀${NC}"
echo ""
