# NEXUS Codebase Technical Map

**Repository analyzed:** `/home/operator/NEXUS`  
**Analysis date:** 2026-06-09  
**Declared product version:** NEXUS PRO `2.0.0`  
**Repository state:** clean Git worktree at analysis time

## 1. Executive Summary

NEXUS is a monorepo for an AI operations platform. It combines:

1. A FastAPI control-plane API (`nexus_api`).
2. A custom asynchronous agent runtime (`nexus_core`).
3. A React/Vite administration dashboard (`nexus_frontend`).
4. SQLite persistence plus optional ChromaDB vector storage.
5. External daemons for autonomous monitoring and factory execution.
6. Generated customer/sample projects, reports, pentest results, and historical installer/patch scripts.

The repository is not a uniformly finished production system. The strongest implemented paths are SQLite-backed CRUD, JWT authentication, basic LLM provider abstraction, agent task execution, HITL state handling, pentest scanning/report generation, and several dashboard integrations. Other advertised surfaces are mock UI, simulated pipelines, stale legacy adapters, or disconnected implementations.

The largest operational problem is hard-coded deployment coupling. Many active modules reference `/home/operator/NEXUS-PRO` or `/home/operator/BW-AI`, while this checkout is `/home/operator/NEXUS`. Those paths also conflict with the Docker filesystem (`/nexus`). Several features therefore fail or write outside the intended data volume unless paths happen to exist.

## 2. Project Structure

The tree below includes all authored runtime areas and all repository artifacts. Repetitive generated logs and reports are grouped by type, with their contained filenames listed.

```text
.
├── .backups/                         Historical source backups, not imported at runtime.
│   ├── 20260318_215324/
│   │   └── main.py.bak               Snapshot of an earlier main module.
│   └── fix_20260318_220635/
│       └── projects.py.bak           Snapshot of an earlier projects router.
├── .dockerignore                     Docker build-context exclusions.
├── .env.example                      Environment template for LLM, JWT, ports, DB, and data paths.
├── .gitignore                        Git exclusions.
├── .md                               Empty/miscellaneous root Markdown artifact.
├── .nexus_api.pid                    Runtime PID marker for local API process.
├── .nexus_factory.pid                Runtime PID marker for factory daemon.
├── .nexus_jarvis.pid                 Runtime PID marker for Junior/Jarvis daemon.
├── CHANGELOG.md                      Claimed v1/v2 product changes.
├── CODEBASE_MAP.md                   This technical map.
├── Dockerfile.backend                Python 3.11 multi-stage backend image.
├── Dockerfile.frontend               Node 20 Vite build served by nginx.
├── PRICING.md                        Commercial positioning and pricing, not runtime code.
├── README.md                         Product overview, installation, architecture, and API summary.
├── bajioware_landing/
│   └── index.html                    Standalone marketing landing page.
├── data/                             Persistent/generated runtime data and generated projects.
│   ├── factory/
│   │   ├── templates/
│   │   │   ├── pentest_scope.md      Input template for pentest engagements.
│   │   │   └── software_requirements.md Input template for software factory projects.
│   │   └── projects/                 AI-generated project outputs; not part of NEXUS runtime.
│   │       ├── bin-ghost/             Generated FastAPI-style project with duplicated layers.
│   │       │   ├── Dockerfile         Generated container scaffold.
│   │       │   ├── README.md          Generated project documentation.
│   │       │   ├── api_docs.md        Generated API notes.
│   │       │   ├── app/auth.py        Generated auth implementation.
│   │       │   ├── backend/auth.py    Alternative generated auth module.
│   │       │   ├── backend/database.py Generated backend DB module.
│   │       │   ├── backend/models.py  Generated backend models.
│   │       │   ├── db/database.py     Alternative generated DB module.
│   │       │   ├── models/user.py     Generated user model.
│   │       │   ├── docker-compose.yml Generated service scaffold.
│   │       │   └── tests/test_app.py  Generated smoke tests.
│   │       ├── proyecto/              Generated generic FastAPI project.
│   │       │   ├── .gitignore         Generated ignores.
│   │       │   ├── Dockerfile         Generated image.
│   │       │   ├── README.md          Generated documentation.
│   │       │   ├── app/config.py      Generated configuration.
│   │       │   ├── app/main.py        Generated packaged entry point.
│   │       │   ├── app/models.py      Generated packaged models.
│   │       │   ├── database.py        Generated top-level DB implementation.
│   │       │   ├── db/database.py     Duplicate generated DB implementation.
│   │       │   ├── docker-compose.yml Generated service definition.
│   │       │   ├── main.py            Generated top-level entry point.
│   │       │   ├── models.py          Duplicate generated models.
│   │       │   └── requirements.txt   Generated Python dependencies.
│   │       ├── restaurante_bajioware/ Generated restaurant API project.
│   │       │   ├── Dockerfile, docker-compose.yml, README.md
│   │       │   ├── main.py            Generated FastAPI application.
│   │       │   ├── auth.py            Generated authentication.
│   │       │   ├── config.py          Generated settings.
│   │       │   ├── database.py        Generated persistence.
│   │       │   ├── middleware.py      Generated HTTP middleware.
│   │       │   ├── seeds.py           Generated seed data.
│   │       │   ├── requirements.txt   Generated dependencies.
│   │       │   ├── app/security.py    Additional generated security helper.
│   │       │   ├── models/taco.py     Pydantic/domain taco model.
│   │       │   ├── models/taco_orm.py ORM taco model.
│   │       │   ├── features/functional_requirements.md Requirements artifact.
│   │       │   ├── api_docs/api_documentation.md API artifact.
│   │       │   └── tests/test_app.py  Generated tests.
│   │       ├── zapateria_bajioware/   Generated shoe-store full-stack project.
│   │       │   ├── Dockerfile, docker-compose.yml, README.md, .gitignore
│   │       │   ├── main.py, database.py, migrations.py, seeds.py
│   │       │   ├── security_hardening.py Security helper.
│   │       │   ├── requirements.txt   Backend dependencies.
│   │       │   ├── app/main.py        Packaged generated API.
│   │       │   ├── app/db/database.py Packaged DB layer.
│   │       │   ├── app/models/models.py Packaged models.
│   │       │   ├── backend/auth.py, config.py, main.py, middleware.py
│   │       │   ├── models/models.py, models/orm.py
│   │       │   ├── frontend/package.  Malformed/incomplete package manifest filename.
│   │       │   ├── frontend/public/index.html
│   │       │   ├── frontend/src/App.js, App.css, index.js
│   │       │   └── tests/test_app.py
│   │       └── zapateria_v2/          Early generated shoe-store scaffold.
│   │           ├── Dockerfile, docker-compose.yml, README.md
│   │           └── app/auth.py, app/database.py, app/models/product.py
│   ├── junior_workspace/              Junior-generated files, manuals, and execution logs.
│   │   ├── NEXUS_PRO_Manual.md
│   │   ├── NEXUS_PRO_Manual_v2.md
│   │   ├── NEXUS_PRO_Manual_v3.md     Successive generated manuals.
│   │   ├── junior_*_log.json          29 per-run Junior execution logs.
│   │   ├── reporte_ejecutivo.txt      Generated executive report.
│   │   ├── todo_api.py
│   │   ├── todo_api_v2.py             Generated TODO API iterations.
│   │   ├── zero_trust_components.txt
│   │   ├── zero_trust_stride_results.txt Security analysis artifacts.
│   │   └── zapateria/
│   │       ├── main.py, models.py, routes.py, requirements.txt Generated mini-project.
│   ├── logs/
│   │   ├── jarvis_report.json         Latest autonomous Jarvis report.
│   │   ├── junior_cycle.txt           Last Junior cycle marker/output.
│   │   └── junior_report.json         Latest Junior report consumed by API.
│   ├── pentest/
│   │   ├── pentest_9ad06a2b_raw.json
│   │   ├── pentest_9ede4090_raw.json
│   │   └── pentest_d8f41e76_raw.json  Raw pentest scan results.
│   ├── reports/                       Generated Markdown/text reports; not executable code.
│   │   ├── Arquitectura_Zero_Trust_para_Sucursal_Bancaria.md
│   │   ├── Finalización_de_la_Fase_2_del_Proyecto_Zapateria_BAJIOWARE.md
│   │   ├── Junior_PROYECTO:_BIN-GHOST"_para_jr"
│   │   ├── Junior_PROYECTO:_Restaurante_BAJIOWAR.md
│   │   ├── Manual_Completo_de_Usuario_para_NEXUS_PRO.md
│   │   ├── PentestReport_*.md         Three generated pentest reports.
│   │   ├── Progreso_*.md, Reporte_*.md, Resumen_*.md Project/status reports.
│   │   ├── STRIDE__home_operator_NEXUS-PRO.md
│   │   └── zerotrust_banbajio.md
│   ├── nexus_pro.db-shm               SQLite shared-memory sidecar.
│   └── nexus_pro.db-wal               SQLite write-ahead-log sidecar.
├── docker/
│   ├── entrypoint.sh                  Starts `nexus_core.main` in background, then Uvicorn.
│   └── nginx.conf                     Serves SPA and proxies `/api`, `/ws`, and `/health`.
├── docker-compose.yml                 Backend, frontend, and ChromaDB deployment.
├── factory_runner.py                  External daemon that consumes approved factory projects.
├── install.sh                         Interactive Docker installation and secret generation.
├── junior_jarvis.py                   Autonomous monitoring/proposal daemon.
├── nexus_api/                         FastAPI API and control-plane persistence.
│   ├── __init__.py                    Package marker/version placeholder.
│   ├── main.py                        Authoritative FastAPI app and lifecycle wiring.
│   ├── main.bak_20260311_183024.py    Historical app backup.
│   ├── main.py.save, main.py.save.1   Editor/source snapshots.
│   ├── requirements.txt               Backend dependency ranges.
│   ├── config.py                      Pydantic settings for API/project paths.
│   ├── core/config.py                 Small alternate core settings object.
│   ├── auth/
│   │   ├── __init__.py                Package marker.
│   │   ├── service.py                 Active SQLite user/JWT service.
│   │   ├── deps.py                    Active bearer-token/RBAC dependencies.
│   │   ├── models.py                  User/login/token Pydantic models.
│   │   ├── router.py                  Alternate auth router, not mounted by `main.py`.
│   │   ├── security.py                Alternate password/JWT helpers.
│   │   ├── schemas.py                 Alternate auth schemas.
│   │   ├── dependencies.py            Alternate OAuth2 dependencies.
│   │   └── database.py                Separate SQLAlchemy `nexus_users.db` schema; connected at lifespan but not used by active auth routes.
│   ├── db/
│   │   ├── __init__.py                Package marker.
│   │   └── database.py                Main tools/agents/teams/tasks/API-key SQLite CRUD.
│   ├── routes/
│   │   ├── __init__.py                Package marker.
│   │   ├── auth.py                    Active login, refresh, users, and registration API.
│   │   ├── agents.py                  Agent configuration CRUD and direct LLM chat.
│   │   ├── tasks.py                   Task CRUD/background execution.
│   │   ├── teams_v2.py                Persistent team CRUD.
│   │   ├── tools.py                   Tool catalog CRUD.
│   │   ├── models.py                  LLM API key storage and remote model detection.
│   │   ├── junior.py                  Autonomous Junior runs, sessions, chat, dispatch.
│   │   ├── pentest.py                 Pentest execution, status, reports, quick scan.
│   │   ├── hitl.py                    HITL REST controls and WebSocket channel.
│   │   ├── memory.py                  Persistent conversational memory REST API.
│   │   ├── factory.py                 Requirements analysis, approval, software/pentest pipelines.
│   │   ├── jarvis.py                  Notifications, proposals, chat history, daemon control.
│   │   ├── scheduler.py               APScheduler job CRUD.
│   │   ├── ws_logs.py                 Global/channel WebSocket log fan-out.
│   │   ├── projects.py                In-memory simulated project pipeline and WebSocket.
│   │   ├── guardian.py                Security scanner adapter.
│   │   ├── plans.py                   Plan persistence/approval/execution adapter.
│   │   ├── killswitch.py              Separate generated kill-switch API.
│   │   ├── testagent.py               Syntax/lint/security/Docker-test adapter.
│   │   ├── docagent.py                Technical-document memory adapter.
│   │   ├── composite.py               Filesystem/project/patch/health composite tools.
│   │   ├── project_manager.py         Legacy `/home/operator/BW-AI` project DB adapter.
│   │   └── nexus.py                   Broken legacy NexusService status/goal adapter.
│   ├── scheduler/
│   │   ├── __init__.py                Package marker.
│   │   ├── manager.py                 APScheduler lifecycle and JSON job registry.
│   │   └── manager.py.bak             Earlier scheduler implementation.
│   └── services/
│       ├── __init__.py                Package marker.
│       ├── __init_py                  Malformed duplicate package artifact.
│       ├── factory_service.py         Factory schema, parser, plans, project/pentest persistence.
│       ├── memory_service.py          Message/summary persistence and search.
│       ├── project_service.py         Small project service abstraction.
│       ├── workspace_manager.py       Workspace directory/template utility.
│       ├── nexus_service.py           Placeholder/deprecated service facade.
│       └── integration_guide.md       Notes explicitly describing uncompleted NexusService integration.
├── nexus_core/                        Agent runtime and orchestration library.
│   ├── __init__.py                    Package marker.
│   ├── main.py                        Standalone demonstration program, not a durable service loop.
│   ├── README.md                      Alpha core documentation; partly stale.
│   ├── requirements.txt               Core dependency ranges.
│   ├── Makefile                       Install/run/test/lint/clean commands.
│   ├── run_nexus.sh                   Venv launcher for the standalone demo.
│   ├── setup_nexus.sh                 Core venv/environment setup.
│   ├── plan_maestro.md                Design/project plan artifact.
│   ├── nexus_state.json               Persisted orchestrator task state.
│   ├── agent_team_manager.py          Role-based software-development team workflow and FastAPI router.
│   ├── team_orchestrator.py           Separate DB-backed team/event/lesson implementation.
│   ├── workflow_manager.py            In-memory DAG execution over EventBus/Orchestrator.
│   ├── composite_tools.py             High-level filesystem analysis and patch helpers.
│   ├── junior_bridge.py               API/core bridge around Junior execution.
│   ├── agents/
│   │   ├── __init__.py                Package marker.
│   │   ├── base.py                    Agent contracts, metadata, lifecycle, and statistics.
│   │   ├── registry.py                Async agent registration and capability selection.
│   │   ├── dynamic_agent.py           LLM reasoning plus real/local tool dispatch.
│   │   ├── junior_agent.py            Multi-step objective planner/executor.
│   │   ├── pentest_agent.py           Security scanner pipeline and report generator.
│   │   ├── data_analyst.py            Minimal data-analysis agent.
│   │   └── generated/
│   │       ├── __init__.py            Package marker.
│   │       ├── bashagent.py           Shell execution agent.
│   │       ├── codeagent.py           Code generation/execution agent.
│   │       ├── dataanalysisagent.py   Generated analysis agent.
│   │       ├── fileagent.py           File operations agent.
│   │       ├── loganalyzeragent.py    Minimal log analysis agent.
│   │       ├── reportgenerationagent.py Report generation agent.
│   │       ├── guardian_agent.py      Secret/Bandit/Git scanning and incident DB.
│   │       ├── kill_switch_agent.py   File-backed critical-operation approval state.
│   │       ├── plan_agent.py          File-backed plans and sequential execution.
│   │       ├── test_agent.py          Test result DB and local/Docker quality checks.
│   │       ├── doc_agent.py           Technical-doc/incident DB plus optional Chroma index.
│   │       └── project_manager_agent.py Legacy project manager.
│   ├── core/
│   │   ├── __init__.py                Package marker.
│   │   ├── event_bus.py               Async typed publish/subscribe bus.
│   │   ├── orchestrator.py            Priority queue, dispatch, retries, health, checkpoints.
│   │   ├── planner.py                 Goal-to-task planner.
│   │   ├── agent_factory.py           Dynamic agent class generation/registration.
│   │   └── agent_generator.py         LLM-generated agent source helper.
│   ├── hitl/
│   │   ├── __init__.py                Package marker.
│   │   └── manager.py                 In-memory approval requests, risk rules, WS listeners.
│   ├── llm/
│   │   ├── __init__.py                Package marker.
│   │   ├── abstraction.py             OpenAI/Gemini/Ollama clients, factory, fallback wrapper.
│   │   ├── abstraction.py.bak         Earlier LLM abstraction.
│   │   ├── openai_provider.py         Small legacy OpenAI wrapper.
│   │   └── gemini_provider.py         Small legacy Gemini wrapper.
│   ├── memory/
│   │   ├── __init__.py                Package marker.
│   │   ├── models.py                  `MemoryRecord` dataclass.
│   │   ├── store.py                   Local persistent Chroma store.
│   │   └── manager.py                 Task/knowledge convenience wrapper.
│   ├── vector/
│   │   ├── __init__.py                Package marker.
│   │   ├── embeddings.py              Placeholder/simple embedding client.
│   │   ├── store.py                   In-memory vector store.
│   │   └── memory.py                  Embedding/store facade.
│   ├── skills/
│   │   ├── __init__.py                Package marker.
│   │   ├── base.py                    Skill interface.
│   │   ├── registry.py                In-memory skill registry.
│   │   ├── file_reader.py             Async file read skill.
│   │   ├── http_client.py             HTTP GET skill.
│   │   ├── nmap_scan.py               Nmap subprocess skill.
│   │   └── nuclei_scan.py             Nuclei subprocess skill.
│   ├── state/
│   │   ├── __init__.py                Package marker.
│   │   └── manager.py                 JSON-backed task/system state.
│   ├── utils/
│   │   ├── __init__.py                Package marker.
│   │   ├── logger.py                  Structured JSON/console logging.
│   │   └── security.py                Validation, rate limiting, audit, sandbox helper.
│   ├── planner/__init__.py             Empty package placeholder.
│   ├── workforce/__init__.py           Empty package placeholder.
│   └── tests/
│       ├── conftest.py                 Fixtures and mock agent.
│       ├── pytest.ini                  Test markers/configuration.
│       └── unit/
│           ├── test_event_bus.py       EventBus behavior tests.
│           ├── test_security.py        Validation/security tests.
│           └── test_state_manager.py   State persistence tests.
├── nexus_frontend/                     React administration SPA.
│   ├── package.json                    npm scripts and semver dependency ranges.
│   ├── package-lock.json               Exact npm dependency lock.
│   ├── vite.config.js                  Vite dev server and `/api`/`/ws` proxies.
│   ├── eslint.config.js                ESLint 9 flat configuration.
│   ├── index.html                      Vite HTML entry.
│   ├── README.md                       Unmodified React/Vite template documentation.
│   ├── .env                            Frontend-local environment values.
│   ├── .gitignore                      Frontend ignores.
│   ├── public/favicon.svg              App icon.
│   ├── public/icons.svg                Shared SVG icon asset.
│   └── src/
│       ├── main.jsx                    React DOM bootstrap.
│       ├── App.jsx                     Authentication guard and page switcher.
│       ├── App.css                     Main component styling.
│       ├── index.css                   Global design system/theme.
│       ├── api/client.js               Axios client, refresh interceptor, API facade.
│       ├── hooks/useNexusData.js       Polling React Query hooks.
│       ├── hooks/useWebSocket.js       Logs and HITL WebSocket clients.
│       ├── store/authStore.js          Persisted Zustand auth state.
│       ├── store/nexusStore.js         UI, logs, health, task, HITL state.
│       ├── components/layout/Sidebar.jsx Navigation.
│       ├── components/layout/TopBar.jsx Health, notifications, user controls.
│       ├── components/ui/index.jsx     Cards, badges, buttons, metrics.
│       ├── components/ui/Form.jsx      Form controls.
│       ├── components/ui/Modal.jsx     Modal shell.
│       ├── pages/Login.jsx             JWT login.
│       ├── pages/Overview.jsx          Live health summary plus static phase list.
│       ├── pages/Agents.jsx            Agent CRUD UI.
│       ├── pages/Tasks.jsx             Task CRUD/run/cancel UI.
│       ├── pages/Teams.jsx             Team CRUD UI; currently calls wrong URL.
│       ├── pages/Models.jsx            API key/model management.
│       ├── pages/HITL.jsx              Pending approvals UI.
│       ├── pages/Junior.jsx            Chat, proposals, daemon, objective execution.
│       ├── pages/Pentest.jsx           Pentest run/status/report UI.
│       ├── pages/Memory.jsx            Persistent memory browser.
│       ├── pages/Factory.jsx           Requirements/factory approval UI.
│       ├── pages/Users.jsx             Admin user creation/listing.
│       ├── pages/Settings.jsx          Health/model status settings view.
│       ├── pages/Guardian.jsx          Scanner trigger plus mock threat rows.
│       ├── pages/Terminal.jsx          Restricted client-side command simulation.
│       ├── pages/Vault.jsx             Mock secrets UI.
│       ├── pages/Audit.jsx             Mock audit UI.
│       ├── pages/RBAC.jsx              Static RBAC matrix.
│       └── assets/hero.png, react.svg, vite.svg Image/template assets.
├── nexus_start.sh                      Local process manager for API/factory/Jarvis.
├── nexus_healthcheck.sh                Curl-based API/auth/core smoke checks.
├── nexus_backup.sh                     Archives DBs, reports, and `.env`.
├── nexus_upgrade.sh                    Historical upgrade script with fixed old paths.
├── nexus_backend_complete.sh           Historical code-generation/overwrite script.
├── nexus_frontend_real.sh              Historical frontend-generation script.
├── nexus_frontend_setup.sh             Historical frontend setup script.
├── nexus_fix_dynamic_agents.sh         Historical patch script.
├── nexus_fix_final.sh                  Historical patch script.
├── nexus_pages.sh                      Historical page-generation script.
├── nexus_punto1_llm_real.sh            Milestone generator for LLM integration.
├── nexus_punto2_junior.sh              Milestone generator for Junior.
├── nexus_punto3_pentest.sh             Milestone generator for pentest.
├── nexus_punto4_hitl.sh                Milestone generator for HITL.
├── nexus_punto5_dashboard.sh           Milestone generator for dashboard.
├── nexus_punto6_docker.sh              Milestone generator for Docker.
├── nexus_punto7_auth.sh                Milestone generator for auth.
├── nexus_punto8_users.sh               Milestone generator for users.
├── nexus_punto9_memory.sh              Milestone generator for memory.
├── nexus_punto10_readme.sh             Milestone generator for docs/pricing.
├── nexus_punto11_factory.sh            Milestone generator for software factory.
├── nexus_punto12_jarvis.sh             Milestone generator for daemons/Jarvis.
└── nexus_punto13_security.sh           Milestone generator for security/landing page.
```

## 3. Tech Stack

### Runtime Languages

| Area | Language | Declared/runtime version |
|---|---|---|
| Backend/core | Python | `3.11+`; Docker pins `python:3.11-slim` |
| Frontend | JavaScript/JSX ES modules | Node `20` in Docker |
| Shell/ops | Bash | GNU/Linux-oriented |
| Persistence | SQLite SQL | SQLite with WAL in main CRUD |
| Web/static | HTML/CSS/SVG | Browser/nginx |

### Backend Libraries

Versions in Python requirements are mostly lower bounds, not locked versions:

| Library | Declared version | Use |
|---|---:|---|
| FastAPI | `>=0.111.0` | REST/WebSocket API |
| Uvicorn | `>=0.30.0` | ASGI server |
| Pydantic | `>=2.7.0` | Request/settings models |
| pydantic-settings | `>=2.3.0` | Environment configuration |
| databases | unpinned | Alternate async user DB connection |
| aiosqlite | unpinned | Async SQLite driver |
| SQLAlchemy | transitive/undeclared directly | Auth metadata and APScheduler store |
| APScheduler | unpinned | Interval/cron jobs |
| python-jose | unpinned | JWT |
| passlib + bcrypt `<4.0.0` | unpinned / capped | Password hashing |
| httpx | `>=0.27.0` | Provider calls and internal HTTP |
| OpenAI SDK | `>=1.35.0` | OpenAI chat completions |
| google-generativeai | `>=0.7.0` | Gemini client |
| google-genai | unpinned | Additional Google SDK |
| ChromaDB | unpinned | Local/vector memory |
| Docker SDK | unpinned | Declared, though most Docker calls use CLI |
| pytest | `>=8.2.0` | Tests |
| pytest-asyncio | `>=0.23.7` | Async tests |
| pytest-cov | `>=5.0.0` | Coverage |

Container build additionally installs `bandit`, `safety`, `slowapi`, and crypto/multipart extras. Active code imports `psutil`, but neither Python requirements file declares it. `sqlalchemy` is also imported directly but only likely supplied transitively by APScheduler.

### Frontend Libraries

`package.json` ranges:

| Library | Range | Use |
|---|---:|---|
| React / React DOM | `^19.2.4` | UI |
| React Router DOM | `^7.13.1` | Installed, but app uses a Zustand page switch rather than routes |
| TanStack React Query | `^5.91.0` | Fetching, polling, mutations |
| Axios | `^1.13.6` | REST client |
| Zustand | `^5.0.12` | Auth/global UI state |
| Recharts | `^3.8.0` | Charts |
| Lucide React | `^0.577.0` | Icons |
| date-fns | `^4.1.0` | Date formatting |
| Vite | `^8.0.0` | Build/dev server |
| ESLint | `^9.39.4` | Linting |
| `@vitejs/plugin-react` | `^6.0.0` | JSX transform/HMR |

The lockfile is npm lockfile version 3 and resolves exact transitive versions. The checkout does not contain a usable local install: `npm run build` cannot find Vite, and `npm run lint` falls back to system ESLint 6.4.0.

### Infrastructure

| Component | Configuration |
|---|---|
| Backend image | Multi-stage Python 3.11, nmap/curl/git/sqlite runtime |
| Frontend image | Node 20 build, nginx runtime |
| ChromaDB | `chromadb/chroma:latest`, persistent volume |
| Network | Docker bridge `10.0.0.1/16` |
| Data | Host bind `./data` to `/nexus/data` |
| API | Port 8000 |
| Frontend | Host 3000 to nginx 80 |
| Chroma | Host 8001 to container 8000 |

## 4. Core Modules and Responsibilities

### FastAPI Application

`nexus_api/main.py`:

- Initializes the active user service indirectly at router import.
- Connects a separate, mostly unused SQLAlchemy user DB.
- Initializes main SQLite CRUD tables.
- Starts APScheduler.
- Creates EventBus, StateManager, AgentRegistry, NexusOrchestrator, LLM wrapper, MemoryManager, WorkflowManager, and HITL manager.
- Registers BashAgent, CodeAgent, FileAgent, Junior, and DB-defined DynamicAgents.
- Mounts static routers at import time and the role-based `/teams` router during lifespan.
- Uses broad exception handling, allowing startup to report healthy even when major components failed.
- Adds permissive CORS and security headers.

### Core Orchestration

`NexusOrchestrator`:

- Accepts tasks into an `asyncio.PriorityQueue`.
- Persists task state in `StateManager`.
- Selects agents by capability through `AgentRegistry`.
- Runs up to five tasks concurrently.
- Retries failures with exponential backoff.
- Publishes lifecycle events.
- Saves JSON checkpoints and resumes tasks marked running/retry.

Important caveat: `_dispatch_loop` holds the concurrency semaphore only while creating the task, not for the full task lifetime. The intended concurrency limit is therefore not actually enforced.

`EventBus`:

- In-process async pub/sub.
- Typed event enum and event payload.
- Sequentially invokes subscribed handlers.
- No external broker or durable queue.

`StateManager`:

- Stores `TaskState` objects in memory.
- Loads/saves JSON to `nexus_state.json` or configured path.
- Provides create/update/query by status.
- Single-process persistence, no locking across Uvicorn workers.

`AgentRegistry`:

- Async register/unregister/get.
- Selects best available agent by capability and load/statistics.
- Provides health and aggregate stats.
- Registry is per process; two Uvicorn workers have separate registries/HITL state.

### Agent Layer

`BaseAgent`:

- Defines metadata, capabilities, lifecycle, health, availability, and statistics.
- Wraps subclass `execute()` with timeout, error handling, and metrics.

`DynamicAgent`:

- Converts DB agent configuration to metadata.
- Uses an LLM planner to choose a tool and parameters.
- Evaluates HITL risk before tool execution.
- Executes local tools and optionally asks the LLM to interpret output.
- Falls back to payload-based tool selection when LLM planning fails.

Implemented tools: shell, file read/write/list/delete, HTTP, Python execution, nmap, report generation, direct LLM, Git CLI, Docker CLI, basic SAST patterns, STRIDE template, API request, nuclei CLI.

Stub tools: `web_search`, `sql_query`, `memory_search`, and `memory_write` return success notes without doing the operation.

`JuniorAgent`:

- Converts an objective into a sequence of planned steps.
- Executes steps through `ToolExecutor`.
- Supports result placeholder substitution.
- Persists per-run logs in Junior workspace.
- Uses deterministic fallback plans without an LLM.

`PentestAgent`:

- Runs nmap, Bandit, Safety, secret scanning, HTTP header checks, STRIDE, LLM correlation, and Markdown/raw JSON report output.
- Gracefully degrades when tools/LLM are unavailable.
- Performs real subprocess/network actions when dependencies and target are available.

### Human Approval and Safety

`HITLManager`:

- Classifies tools and command content into risk levels.
- Creates in-memory pending requests.
- Pauses the calling coroutine on an `asyncio.Event`.
- Broadcasts new/approved/denied/timeout events to WebSocket listeners.
- Keeps up to 100 history entries.

Limitations:

- State is not persisted.
- State is process-local and incompatible with reliable multi-worker operation.
- Not all execution paths pass through HITL. `tasks.py` can run shell commands directly, generated agents call subprocesses directly, and factory/Jarvis daemons are outside this manager.
- A separate generated kill-switch system exists but is not integrated into `DynamicAgent` or the orchestrator.

### Workflow and Team Systems

There are three overlapping implementations:

1. `WorkflowManager`: in-memory DAG over orchestrator events.
2. `AgentTeamManager`: role-based planner/coder/tester/reviewer/deployer/documenter workflow, mounted at `/teams`.
3. `team_orchestrator.py`: separate SQLite-backed team/event/lesson orchestrator.

They do not share a unified model or persistence layer. The dashboard uses a fourth concept: persistent configuration-only teams from `routes/teams_v2.py`.

### Memory Systems

There are also multiple memory implementations:

1. `memory_service.py`: active SQLite chat messages/summaries used by `/memory`.
2. `nexus_core/memory`: Chroma persistent task/knowledge records.
3. `nexus_core/vector`: simple in-memory vector implementation.
4. `doc_agent.py`: technical docs in SQLite with optional Chroma indexing.
5. Jarvis chat history in a separate `updates.db`.

The Docker Chroma service is not wired to the active `/memory` API. `MemoryStore` uses a local persistent Chroma path rather than `CHROMA_HOST`.

### Frontend

The frontend is a single-page dashboard without URL routing. `App.jsx` selects pages from Zustand state. Authentication is persisted to local storage. Axios attaches JWT tokens and attempts refresh on 401. React Query provides polling.

Real-data pages: Login, Overview health, Agents, Tasks, Models, HITL, Junior, Pentest, Memory, Factory, Users, Settings.

Static/mock/degraded pages: Audit, Vault, RBAC, parts of Guardian, Terminal, and static parts of Overview.

## 5. Data Models and Schemas

### Main SQLite Database

Intended location is `NEXUS_DB_PATH`, but `nexus_api/db/database.py` ignores it and hard-codes `/home/operator/NEXUS-PRO/data/nexus_pro.db`.

| Table | Main fields | Purpose |
|---|---|---|
| `tools` | `id`, `name`, `category`, `description`, JSON `config`, `is_builtin`, `created_at` | Tool catalog |
| `agents` | identity, role, model/provider, generation config, JSON tools, HITL mode, status/stats | Persistent dynamic-agent configuration |
| `teams` | identity, specialization, strategy, JSON agent IDs, HITL, status/stats | Dashboard team configuration |
| `tasks` | name/type/status/priority, agent/team, JSON payload, cron, progress/result/error/timestamps | Executable task records |
| `api_keys` | alias/provider, masked and plaintext key, JSON models, status | Provider credentials and model detection |
| `nexus_users` | email/name, password hash, role, active, timestamps | Active application users |
| `agent_memory` | agent/session/role/content/summary/token estimate/time | Conversation records |
| `memory_summaries` | agent/session/summary/count/time | Context summaries |
| `factory_projects` | customer/type/status, JSON requirements/plan, approval/time | Software factory projects |
| `factory_phases` | project, phase number/name/status, JSON agents/tools, result/times | Factory phase execution |
| `pentest_engagements` | customer/type/status, scope/plan/findings, approval/time | Factory pentest engagements |
| `jarvis_notifications` | message/type/detail/time/read | Dashboard notifications |

Security issue: `api_keys.key_value` stores provider secrets in plaintext despite the UI claiming encrypted vault behavior.

### Jarvis Updates Database

`data/junior_updates/updates.db` is created at runtime:

| Table | Purpose |
|---|---|
| `junior_updates` | Autonomous improvement proposals and approval state |
| `junior_chats` | Chat session metadata |
| `junior_messages` | Chat messages |

### Generated-Agent Databases

Mostly located under hard-coded `/home/operator/BW-AI`:

| Table | Module |
|---|---|
| `security_incidents` | Guardian findings |
| `test_results` | TestAgent results |
| `technical_docs` | Documented reusable solutions |
| `incident_reports` | Incident root-cause/remediation records |
| `teams`, `team_agents`, `team_events`, `team_lessons` | Separate team orchestrator |

### Alternate User Database

`nexus_api/auth/database.py` defines `nexus_api/nexus_users.db` with a `users` table (`username`, email, hash, active, role). The app connects it during lifespan, but active routes use `nexus_users` in the main DB instead. This is redundant/dead architecture.

### In-Memory Models

- `TaskState`, `SystemState`, `TaskStatus`
- `AgentMetadata`, `AgentStats`, `AgentCapability`
- `Event`, `EventType`
- `WorkflowNode`, `WorkflowInstance`, workflow/node status enums
- `HITLRequest`, risk/status enums
- `TeamExecution`, `TeamMember`, `AgentTaskResult`, team/role enums
- `LLMConfig`, `LLMMessage`, `LLMResponse`, provider enum
- Junior `_sessions` and Projects `_projects` dictionaries

## 6. API Surface

Paths below are effective mounted paths from `nexus_api/main.py`. Unless noted, many routes do not require authentication because auth dependencies are applied only in selected routers.

### Base and Documentation

| Method | Path | Purpose |
|---|---|---|
| GET | `/` | Product/version metadata |
| GET | `/health` | Component status summary |
| GET | `/docs` | Swagger UI |
| GET | `/redoc` | ReDoc |
| GET | `/openapi.json` | OpenAPI schema |

### Authentication and Users

| Method | Path | Purpose |
|---|---|---|
| POST | `/auth/login` | Email/password login, access + refresh JWT |
| POST | `/auth/refresh` | Rotate tokens |
| GET | `/auth/me` | Current user |
| POST | `/auth/logout` | Stateless acknowledgement |
| GET | `/auth/users` | Admin user list |
| POST | `/auth/users` | Admin user creation |
| POST | `/auth/register` | Public legacy registration; security exposure |

### Agents, Tools, Models

| Method | Path | Purpose |
|---|---|---|
| GET | `/agents` | DB agent configurations |
| GET | `/agents/registry` | Live per-process agents |
| GET | `/agents/{agent_id}` | Agent configuration |
| POST | `/agents` | Create DB agent |
| PUT | `/agents/{agent_id}` | Update DB agent |
| POST | `/agents/{agent_id}/tools` | Assign tools |
| DELETE | `/agents/{agent_id}` | Delete DB agent |
| POST | `/agents/{agent_id}/chat` | Direct configured-agent LLM chat |
| GET | `/tools` | Tool catalog |
| GET | `/tools/categories` | Category counts |
| POST | `/tools` | Create custom tool metadata |
| DELETE | `/tools/{tool_id}` | Delete non-built-in metadata |
| GET | `/models/keys` | Stored API keys, masked response |
| POST | `/models/keys` | Store plaintext key and detect models |
| POST | `/models/keys/{key_id}/detect` | Re-detect provider models |
| DELETE | `/models/keys/{key_id}` | Delete key |
| GET | `/models/available` | Flattened detected model list |
| GET | `/models/catalog` | Static provider/model catalog |

### Tasks and Scheduling

| Method | Path | Purpose |
|---|---|---|
| GET | `/tasks` | List/filter tasks |
| GET | `/tasks/{task_id}` | Task record |
| POST | `/tasks` | Create; `unique` runs immediately |
| POST | `/tasks/{task_id}/run` | Background run |
| POST | `/tasks/{task_id}/cancel` | Marks cancelled; does not stop subprocess/coroutine |
| DELETE | `/tasks/{task_id}` | Soft-delete status |
| GET | `/scheduler/jobs` | List jobs |
| POST | `/scheduler/jobs` | Add interval/cron dummy job |
| DELETE | `/scheduler/jobs/{job_id}` | Remove job |

Scheduler jobs call `_dummy_agent_task`, which only logs and sleeps; they do not dispatch real agents.

### Persistent Teams (`teams_v2`)

| Method | Path | Purpose |
|---|---|---|
| GET | `/teams-v2` | List configurations |
| GET | `/teams-v2/{team_id}` | Team |
| POST | `/teams-v2` | Create |
| PUT | `/teams-v2/{team_id}` | Update |
| DELETE | `/teams-v2/{team_id}` | Delete |
| POST | `/teams-v2/{team_id}/agents` | Add agent |
| DELETE | `/teams-v2/{team_id}/agents/{agent_id}` | Remove agent |

The frontend incorrectly calls `/teams-v2/teams-v2...`, so the Teams page is currently disconnected.

### Runtime Agent Teams (`AgentTeamManager`)

These routes are added during lifespan:

| Method | Path | Purpose |
|---|---|---|
| POST | `/teams/create` | Create role-based execution |
| POST | `/teams/{execution_id}/run` | Start execution |
| GET | `/teams/{execution_id}/status` | Execution status |
| POST | `/teams/{execution_id}/approve` | Human decision |
| GET | `/teams/` | List in-memory executions |
| GET | `/teams/pending-approvals` | Waiting executions |

### Junior and Jarvis

| Method | Path | Purpose |
|---|---|---|
| POST | `/junior/run` | Start autonomous objective |
| GET | `/junior/status/{task_id}` | DB status |
| GET | `/junior/sessions` | In-process completed sessions |
| GET | `/junior/sessions/{session_id}` | Session |
| POST | `/junior/chat` | Stateless quick LLM chat |
| POST | `/junior/dispatch` | Intended internal dispatch, but background tasks are never attached to response |
| GET | `/jarvis/notifications` | Notifications |
| POST | `/jarvis/notifications/{nid}/read` | Mark one read |
| POST | `/jarvis/notifications/read-all` | Mark all read |
| GET | `/jarvis/updates` | Proposals by status |
| GET | `/jarvis/updates/all` | All proposals |
| POST | `/jarvis/updates/{uid}/approve` | Approve and execute through Junior |
| POST | `/jarvis/updates/{uid}/deny` | Deny |
| DELETE | `/jarvis/updates/{uid}` | Delete |
| GET | `/jarvis/chats` | Sessions |
| POST | `/jarvis/chats` | Create session |
| GET | `/jarvis/chats/{session_id}/messages` | History |
| POST | `/jarvis/chats/{session_id}/messages` | Contextual LLM chat |
| DELETE | `/jarvis/chats/{session_id}` | Delete session/messages |
| GET | `/jarvis/status` | Daemon/log/report status |
| POST | `/jarvis/start` | Spawn daemon |
| POST | `/jarvis/stop` | `pkill` daemon |
| GET | `/jarvis/report` | Latest JSON report |

### Pentest and Guardian

| Method | Path | Purpose |
|---|---|---|
| POST | `/pentest/run` | Start full pentest task |
| GET | `/pentest/status/{task_id}` | Task status |
| GET | `/pentest/reports` | Report files |
| GET | `/pentest/reports/{filename}` | Report content |
| POST | `/pentest/quick-scan` | Local secrets/header scan |
| POST | `/guardian/scan/full` | Full generated Guardian scan |
| POST | `/guardian/scan/secrets` | Secrets scan |
| POST | `/guardian/scan/bandit` | Bandit scan |
| POST | `/guardian/scan/commits` | Recent Git scan |
| GET | `/guardian/incidents` | Open incidents |

### HITL

| Method | Path | Purpose |
|---|---|---|
| GET | `/hitl/pending` | Pending requests |
| GET | `/hitl/history` | In-memory history |
| GET | `/hitl/count` | Count |
| POST | `/hitl/{hitl_id}/approve` | Approve |
| POST | `/hitl/{hitl_id}/deny` | Deny |
| POST | `/hitl/approve-all` | Bulk approve |
| POST | `/hitl/deny-all` | Bulk deny |
| WS | `/ws/hitl` | Initial pending snapshot, event stream, ping/pong, approve/deny commands |

WebSocket event envelope: `{"type":"hitl","event":...,"data":...,"timestamp":...}`. Events are `connected`, `new_request`, `approved`, `denied`, and `timeout`.

### Memory

| Method | Path | Purpose |
|---|---|---|
| GET | `/memory/agents` | Agents with records |
| GET | `/memory/agents/{agent_id}` | Context and summary |
| GET | `/memory/agents/{agent_id}/stats` | Counts/sessions |
| GET | `/memory/agents/{agent_id}/search?q=` | SQL LIKE search |
| POST | `/memory/messages` | Add message |
| POST | `/memory/summaries` | Add summary |
| DELETE | `/memory/agents/{agent_id}` | Clear agent/session |

### Factory

| Method | Path | Purpose |
|---|---|---|
| GET | `/factory/templates` | Requirements/scope templates |
| POST | `/factory/analyze` | Parse requirements and create plan |
| POST | `/factory/projects/{project_id}/approve` | Approve and launch phases |
| GET | `/factory/projects` | List |
| GET | `/factory/projects/{project_id}` | Project + phases |
| POST | `/factory/pentest/analyze` | Parse scope/create engagement |
| POST | `/factory/pentest/{engage_id}/approve` | Launch pentest |
| GET | `/factory/pentest` | List engagements |
| GET | `/factory/pentest/{engage_id}` | Engagement |

### Simulated Projects

| Method | Path | Purpose |
|---|---|---|
| POST | `/projects/` | Create in-memory project |
| GET | `/projects/` | List |
| GET | `/projects/{project_id}` | Detail |
| DELETE | `/projects/{project_id}` | Delete |
| WS | `/projects/ws/{project_id}` | Simulated five-step progress stream |

WebSocket events: `pipeline_start`, `log_line`, `pipeline_done`, `ping`, `error`.

### Logs WebSocket

| Method | Path | Purpose |
|---|---|---|
| WS | `/ws/logs` | All log messages |
| WS | `/ws/logs/{channel}` | Channel-filtered messages |

Clients receive a connected message and periodic ping; application logs are broadcast through `WSLogHandler` only when that handler is attached.

### Plans, Kill Switch, Test, Docs, Composite, Legacy

| Prefix | Endpoints |
|---|---|
| `/plans` | `POST /create`, `GET /pending`, `GET /list`, `GET /{id}`, `POST /approve/{id}`, `/reject/{id}`, `/execute/{id}` |
| `/killswitch` | `GET /status`, `/pending`; `POST /request`, `/approve/{id}`, `/reject/{id}`, `/emergency/stop`, `/emergency/resume` |
| `/testagent` | `POST /syntax`, `/lint`, `/security`, `/full`, `/sandbox`; `GET /history` |
| `/docagent` | `POST /incident`, `/solution`, `/search`; `GET /analyze/incidents`, `/recent` |
| `/composite` | `POST /explore`, `/analyze`, `/patch`; `GET /health` |
| `/project-manager` | `POST /create`; `GET /list`, `/{id}`; `PATCH /status` |
| no prefix (`nexus.py`) | `GET /status`, `POST /goal`; broken because `nexus_svc` is undefined |

The unprefixed legacy `/status` collides conceptually with other status APIs and fails at dependency resolution.

## 7. Entry Points and Processes

### Docker

`docker compose up` starts:

1. `chromadb`.
2. `backend`, after Chroma health.
3. `frontend`, after backend health.

Backend entrypoint starts:

```text
python -m nexus_core.main &
uvicorn nexus_api.main:app --workers 2
```

This is problematic:

- `nexus_core.main` is a finite demo that invokes nmap against `scanme.nmap.org`, manipulates sample memory, and exits after demo tasks. It is not a durable orchestrator service.
- FastAPI already creates its own orchestrator.
- Two Uvicorn workers duplicate scheduler, state manager, registry, HITL, and lifespan startup.
- Hard-coded host paths bypass `/nexus/data`.

Frontend nginx:

- Serves Vite output.
- Rewrites `/api/*` to backend `/*`.
- Proxies `/ws/*`.
- Serves SPA fallback.

### Local Development

Documented:

```bash
uvicorn nexus_api.main:app --host 0.0.0.0 --port 8000
cd nexus_frontend && npm install && npm run dev
```

`nexus_start.sh` starts three local background processes:

1. Uvicorn with one worker.
2. `factory_runner.py --daemon --interval 20`.
3. `junior_jarvis.py --interval 60`.

It does not start the frontend despite printing dashboard port 3000.

### Standalone Core

`python -m nexus_core.main` or `nexus_core/run_nexus.sh` runs the demonstration workflow. It is useful as an integration demo, but unsafe as a default production background process because it performs real nmap and external provider work.

### External Daemons

`factory_runner.py` polls approved projects and calls the API to execute Junior phases.

`junior_jarvis.py` periodically collects host metrics, scans project state, creates notifications/proposals, and writes JSON/log files. It depends on undeclared `psutil`.

## 8. Module Dependency Graph

```text
React pages
  -> nexus_frontend/src/api/client.js
  -> FastAPI routers
     -> auth.service / db.database / memory_service / factory_service
     -> app.state.llm
     -> app.state.registry
     -> app.state.hitl
     -> generated agent helpers

nexus_api.main lifespan
  -> init main and alternate auth DBs
  -> APScheduler
  -> EventBus
  -> StateManager
  -> AgentRegistry
  -> NexusOrchestrator
  -> LLMFactory -> OpenAIClient / GeminiClient / OllamaClient
  -> MemoryManager -> Chroma MemoryStore
  -> WorkflowManager -> EventBus + NexusOrchestrator
  -> AgentTeamManager router
  -> static/generated agents + DynamicAgents + JuniorAgent

NexusOrchestrator
  -> StateManager
  -> AgentRegistry -> BaseAgent subclasses
  -> EventBus

DynamicAgent
  -> LLM reasoning
  -> HITLManager
  -> ToolExecutor

JuniorAgent
  -> LLM/fallback planner
  -> ToolExecutor
  -> workspace logs

PentestAgent
  -> SecurityScanner subprocess/network checks
  -> LLM analysis
  -> Markdown + JSON reports

Factory API / factory_runner
  -> factory SQLite tables
  -> internal HTTP login
  -> `/junior/run` and polling

Jarvis API / daemon
  -> main SQLite notifications
  -> updates SQLite chats/proposals
  -> LLM
  -> Junior task execution
```

Key disconnected dependencies:

- Docker Chroma is not used by active API memory.
- Persistent teams are not used by `AgentTeamManager`.
- Scheduler does not dispatch real tasks.
- Kill switch does not stop orchestrator/tasks/tools.
- `NexusService` is not initialized.
- Alternate auth SQLAlchemy DB is not used for authentication.

## 9. Implemented vs Scaffolded or Incomplete

### Implemented, with Operational Caveats

| Feature | Status |
|---|---|
| JWT login/refresh/current user/admin user creation | Implemented against SQLite |
| Agent/tool/team/task/API-key CRUD | Implemented against SQLite, but hard-coded DB path breaks portability |
| OpenAI/Gemini/Ollama abstraction | Implemented; requires installed SDKs and valid configuration |
| Agent registry/orchestrator/state/event bus | Substantive implementation; concurrency and multi-worker issues remain |
| Dynamic local tools | Many perform real filesystem, shell, HTTP, nmap, Git, Docker actions |
| Junior objective execution | Implemented with LLM and deterministic fallback |
| Pentest pipeline/reports | Implemented with graceful degradation |
| HITL manager/WebSocket/UI | Implemented in-process; not global or universally enforced |
| SQLite memory API/UI | Implemented |
| Jarvis chat and proposal persistence | Implemented, path/dependency caveats |
| Frontend auth refresh and primary CRUD screens | Substantive implementation |

### Explicitly Simulated or Mocked

| Feature | Evidence |
|---|---|
| `/projects` pipeline | Fixed sleeps/progress labels; comment says future WorkflowManager |
| Audit page | Hard-coded `MOCK` rows |
| Vault page | Hard-coded `MOCK_SECRETS`; no backend vault |
| RBAC page | Static matrix |
| Guardian threat feed | `THREATS_MOCK` rows; scan trigger itself is real |
| Terminal | Client-side predefined commands, not an actual shell |
| Scheduler task | `_dummy_agent_task` logs/sleeps only |
| Core demo agents | Return fixed sample records/report/security results |
| Web search/SQL/vector-memory tools | Return “integration pending” notes |

### Broken or Disconnected

1. **Path mismatch:** active code expects `/home/operator/NEXUS-PRO` or `/home/operator/BW-AI`; actual checkout is `/home/operator/NEXUS`; Docker uses `/nexus`.
2. **Main CRUD DB ignores `NEXUS_DB_PATH`:** agents/tasks/tools/teams/models can use a different DB than auth/factory/memory.
3. **Teams frontend URL is wrong:** `/teams-v2/teams-v2` versus `/teams-v2`.
4. **Factory LLM construction is invalid:** `NexusLLM(primary='openai', fallback='gemini')` passes strings where clients are required, then calls nonexistent `chat_async`; exceptions are caught and stored as “LLM unavailable.”
5. **Factory errors are marked completed:** phase exceptions are persisted as `completed` with warning; project is marked completed regardless.
6. **Factory internal HTTP hard-codes localhost:8000 and old paths.**
7. **`/junior/dispatch` does not run its background task:** it creates a standalone `BackgroundTasks` object that FastAPI never executes.
8. **Legacy `/status` and `/goal` are broken:** `nexus_svc` is undefined.
9. **Legacy project-manager points to `/home/operator/BW-AI/nexus_api/database.db`.**
10. **Active app connects an unused alternate auth DB.**
11. **Auth register is unauthenticated:** arbitrary users can self-register with a requested role, including potentially `admin`.
12. **Most control endpoints lack auth/RBAC:** agent creation, task shell execution, keys, guardian, kill switch, plans, and tools are publicly callable if API is reachable.
13. **API keys are stored plaintext.**
14. **Rate limiting is claimed but not mounted in active FastAPI app.**
15. **Audit trail is claimed but dashboard is mock and no unified immutable audit store exists.**
16. **HITL is bypassable through direct task shell fallback and generated subprocess agents.**
17. **Task cancel does not cancel running work.**
18. **Multi-worker deployment fragments in-memory state and duplicates scheduler/lifespan side effects.**
19. **Core concurrency semaphore is released immediately after task creation.**
20. **Jarvis prompt contains literal `{system_context}` because it is escaped inside an f-string.**
21. **Frontend production fallback URLs are tied to `10.0.0.1`.**
22. **CORS combines wildcard origins with credentials.**
23. **Chroma Docker auth variable references `/chroma/auth`, but no auth file is mounted.**
24. **Chroma health path `/api/v1/heartbeat` may not match current `latest` image API; image is unpinned.**
25. **Generated project outputs show duplication/malformed files and are not validated as working applications.**

### Stale or Historical Artifacts

- `nexus_punto*.sh`, `nexus_*complete.sh`, `nexus_fix*.sh`, and frontend generator scripts are code-writing migration history, not startup dependencies.
- Backup/save files are not imported.
- `nexus_core/README.md` uses obsolete class names in its sample and claims a missing `LICENSE`.
- `nexus_frontend/README.md` is the default Vite template.
- `integration_guide.md` explicitly documents placeholder service integration.
- Empty `planner` and `workforce` packages are scaffolds.

## 10. Verification Performed

Static verification completed:

- Enumerated all repository files and directories excluding `.git`.
- Traced every FastAPI route decorator and mount prefix.
- Traced active internal imports.
- Enumerated all SQL `CREATE TABLE` statements.
- Inspected Docker, nginx, environment, npm, and Python manifests.
- Located mocks, placeholders, TODO/stub notes, and hard-coded paths.

Runtime verification could not be completed in the current checkout:

- `python3 -m pytest nexus_core/tests -q` failed because `pytest` is not installed.
- Importing `nexus_api.main` failed because `fastapi` is not installed.
- `npm run build` failed because local Vite is not installed.
- `npm run lint` used system ESLint `6.4.0`, which cannot read the ESLint 9 flat config.

No dependency installation was performed during analysis.

## 11. Practical Architecture Assessment

NEXUS is best characterized as a feature-rich alpha/prototype with several genuinely functional subsystems, surrounded by milestone-generated code and overlapping implementations. It is not currently portable or secure enough for the production claims in the README.

The shortest path to a coherent system is:

1. Centralize all paths/configuration and remove `/home/operator/NEXUS-PRO` and `/home/operator/BW-AI`.
2. Use one SQLite database interface and one user schema.
3. Run one API worker until in-memory state moves to shared persistence.
4. Put auth/RBAC on all mutating and sensitive routes.
5. Unify teams, memory, projects, and kill-switch concepts.
6. Replace simulated/success-placeholder behavior with explicit `501 Not Implemented` or real integrations.
7. Add backend API tests and frontend integration tests around the actual mounted paths.
8. Pin Python, Chroma, and container dependency versions and validate a clean Docker build.
