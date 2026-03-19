# NEXUS PRO — AI Operations Platform

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
