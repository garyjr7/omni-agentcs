# OmniAgentCS — Changelog

## v3.0.0-rc5 — 2026-11-17

Release candidate de corrección sobre el árbol saneado de `rc4`. El fixture
`hijack_v3.ndjson` conservaba la IP de laboratorio `10.0.0.5`, que su propia
prueba de anonimización rechaza; se sustituyó por la dirección documental
`192.0.2.10` y se actualizó el objetivo del test de regresión. La suite completa
vuelve a pasar (4.949 passed, 55 skipped) y la versión pasa a `3.0.0rc5`.

## v3.0.0-rc4 — 2026-11-17

Release candidate de saneamiento. Se eliminaron del árbol y de todo el
historial `docs/missions/`, los fixtures DPAPI reales, el NDJSON de Hijack v3
antiguo y los tests con flags/credenciales de laboratorio; los fixtures nuevos
son sintéticos. `install.sh` ya no cae a un paquete de PyPI si falla Git, el
README y SECURITY describen el aislamiento parcial real (SEC-01/SEC-02), el
wheel excluye tests y documentación, y la versión pasa a `3.0.0rc4`. Los SHA y
tags anteriores quedan obsoletos por la reescritura de historia.

## v3.0.0-rc3 — 2026-11-12

Release candidate privado, superado por `rc4`. Licencia Apache-2.0, gate de
tipado estricto bloqueante, corrección de `PostgresControlStore` y suite de CI
determinista. La etiqueta `rc3` fue recreada durante la reescritura de historia;
la referencia pública saneada es `v3.0.0-rc4`.

## v3.0.0b1 — 2026-11-06 (BETA)

Primer tag del repositorio: cierra la semana 1 del plan de release con los gates
mecánicos en verde (`make syntax lint test`: 4.853 passed, 53 skipped) y el
árbol sin cambios pendientes.

### Interfaz
- Cada llamada y cada resultado ocupan **una línea conversacional**
  (`> Ejecutando nmap en 10.0.0.1...`, `✓ nmap: 3 puertos abiertos (21, 22, 80)`).
  El argv completo y el cuerpo plegado siguen a una expansión (`ctrl+o`), con el
  número de líneas ocultas visible.

### Bucle del agente
- `task_complete` **espera al job en segundo plano** antes de cerrar: el cierre
  apagaba el proceso y `cancel_all()` mataba el escaneo que el usuario pidió.
- Una micro-tarea ("solo escanea puertos") cierra sin arrastrar los TODO del plan
  del engagement; la puerta de evidencia sigue aplicando.
- La acción inventada `wait` se rechaza explicando cómo llega el resultado, en
  lugar de la corrección genérica que llevaba al modelo a preguntar al humano.
- El objetivo inmediato limita el run: el plan global es contexto, no una orden
  de ejecución (sustituye la filosofía de kill chain obligatoria).

### Tools
- 88 tools gobernadas (+`nexus.system.execute_and_parse`,
  +`nexus.system.discover_tools`).
- Perfil por defecto de cinco tools; el resto se revela por run al cargar una
  skill o al descubrir un grupo (`NEXUS_TOOL_PROFILE=open` lo desactiva). El
  catálogo durable sigue siendo la autoridad del gateway y la auditoría.
- `execute_and_parse` reutiliza el sustrato del shell (sandbox, scope, auditoría,
  artifact) y parsea el artifact completo con un registro cerrado (`nmap`,
  `text`).
- `create_plan`/`update_plan` responden a un `fact_type` inválido con la lista
  cerrada de los aceptados, en lugar de un fallo que invita a re-adivinar.

### Documentación y gobernanza
- `README.md` y `SECURITY.md` dejan de declarar estados falsos: en ese beta la
  licencia era `Authorized Use Only` (desde rc3 es Apache-2.0) y `oci_network`
  (SEC-03) está implementado con proxy SOCKS5 scope-gobernado
  ([ADR-004](docs/adr/ADR-004-sandbox-modes.md)).

---

## v3.0.0 — 2026-10-02 (no publicado: el tag llega tras este beta)

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
