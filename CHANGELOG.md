# OmniAgentCS — Changelog

## v3.0.0 — 2026-10-02 (ACTUAL)

Rename del producto a **OmniAgentCS** (BAJIOWARE). El núcleo de gobernanza se
mantiene: alcance firmado con HMAC, cadena de auditoría encadenada por hash,
aprobaciones durables y la regla de oro "un modelo propone, nunca afirma éxito".
Cadena ofensiva completa (recon → explotación → post-explotación → C2 Sliver →
reporte), planner determinista por fases y playbooks. Interfaz de terminal con
cabecera compacta de marca BAJIOWARE / Team Red.

---

## v2.0.0 — 2026-03-19 (lineage NEXUS)

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
