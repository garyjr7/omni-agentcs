# Auditoría Técnica — OMNI

_Generada el 2026-11-06 por auditoría automatizada con criterios senior._

- Objeto auditado: workspace `/home/operator/omni-agentcs` (paquete `omniagentcs` v3.0.0), HEAD `61ae348`.
- Alcance de la evidencia: código en disco (691 ficheros `.py`), tests ejecutados en este entorno, CLI ejecutada, documentación del repo. No se ha ejecutado ningún ataque contra objetivos ni se ha tocado `~/.config/omni`.
- Entorno de medición: Linux Kali 2026.3, 4 vCPU, 3,8 GB RAM, Python 3.14.8 (el `pyproject.toml` declara `>=3.12`).

---

## 0. Resumen ejecutivo

- **Veredicto de madurez: Alpha** (motor funcional y con ingeniería real de gobernanza; no es release-grade).
- **Nota global: 6,3/10**.
- **¿Está el autor imaginándose cosas? Parcial.** El núcleo que el README describe (88 tools, scope HMAC, gateway único, aprobaciones durables, TUI, reportes) existe y se puede comprobar. Lo que no resiste la comprobación son 6 afirmaciones documentales concretas: el CHANGELOG v2 describe un producto web (FastAPI/JWT/RBAC/dashboard) que no está en el árbol, el README dice que no hay licencia cuando sí la hay, el estado de `oci_network` se contradice entre módulo y `SECURITY.md`, y las cifras de tests del backlog están desactualizadas. Detalle en §3 y Anexo C.

### Top 5 fortalezas reales

1. **Punto único de gobernanza por tool.** `nexus_core/kernel/tool_gateway.py` (`ToolGateway.invoke`) aplica, en este orden y en un solo sitio: validación de esquema → autenticación de scope → validador de scope → RoE → policy → aprobación durable → hooks → journal → ejecución → post-condición → aserciones → auditoría. Evidencia: `tool_gateway.py`, método `invoke` (757 líneas); el orden es verificable en el propio código.
2. **Volumen y amplitud de tests.** 4.906 tests recolectados en 371 ficheros; **4.852 pasan, 1 falla, 53 omitidos en 249,75 s** (`pytest nexus_core/tests -q -p no:cacheprovider`). No es una suite de fachada: cubre gateway, parser, journal, TUI y handlers.
3. **Catálogo durable grande y clasificado.** `tool_catalog()` devuelve **88 tools** y coincide con `docs/missions/audit-v1/catalog.json` (`tool_count: 88`). Riesgo: 26 `high`, 26 `medium`, 20 `read_only`, 14 `low`, 2 `destructive`; 61 exigen scope; hay un test de consistencia (`nexus_core/tests/unit/test_catalog_ledger_consistency.py`).
4. **Documentación de seguridad honesta.** `SECURITY.md` declara abiertamente SEC-01 (egress del shell fuera de scope), SEC-02 (lectura del host en local), SEC-03 (`oci_network`), SEC-05 (plugins sin firma) y SEC-07 (rol del aprobador). `nexus_core/kernel/sandbox_modes.py` publica `GUARANTEES` con `filesystem_isolation=False` y `network_isolation=False` para `local` y `local_strict`: la tabla dice la verdad, no la aspiracional.
5. **Bucle ReAct con journal durable y deduplicación de efectos.** `InvocationJournal` + `step_key` derivado por el motor, estados `prepared/running/succeeded/unknown`, fencing por `lease_id`, y respuestas explícitas `tool_already_invoked` / `tool_in_flight` (`tool_gateway.py`, ramas de reutilización). Es un diseño poco habitual en herramientas de este tipo.

### Top 5 riesgos críticos

1. **La suite y el lint están rojos en HEAD.** `make test` falla en `nexus_core/tests/integration/test_tui_pty_integrity.py:109` (reproducible en solitario, 2,63 s) y `ruff check nexus_core omni.py nexus_worker.py --select F,E9` sale con código 1 por 3 `F401` en `nexus_core/tests/unit/test_background_wait.py`. El job `cli` de CI ejecuta exactamente `make syntax lint test` (`.github/workflows/ci.yml`): **CI no puede estar verde**.
2. **El modo por defecto no aísla nada.** `SandboxMode.LOCAL_STRICT` declara `filesystem_isolation=False`, `network_isolation=False`, `process_isolation=False`, `user_isolation=False` (`sandbox_modes.py`, `GUARANTEES`). El agente corre con los privilegios del operador y la allowlist de argv es léxica. Solo **7 de 88** tools declaran `sandbox_required=True`.
3. **El scope firmado no cubre el egress del shell universal.** Es SEC-01, abierto y admitido en `SECURITY.md:74`: `python3 -c`, `ssh`, `openssl s_client` o `/dev/tcp` no se inspeccionan. Un objetivo hostil puede convertir una inyección de prompt en tráfico fuera del engagement.
4. **Licencia contradictoria.** `README.md:984` afirma «Por definir. Este repositorio no incluye todavía una licencia de distribución», pero `LICENSE` existe y es una licencia propietaria «Authorized Use Only» que restringe redistribución. Cualquier consumidor que se fíe del README asume un régimen legal falso.
5. **El árbol auditado no es el árbol desplegable.** `git status --porcelain` muestra **27 ficheros modificados y 7 sin trackear**, incluidos handlers nuevos (`nexus_core/tools/handlers/discover_tools.py`, `execute_and_parse.py`, `nexus_core/tools/output_parsers/`, `nexus_core/tools/profiles.py`) y tests nuevos. No hay commit ni tag que corresponda a lo que se está ejecutando.

---

## 1. Inventario de evidencia

### 1.1 Estructura del proyecto — [REAL]

```text
omni-agentcs/
├── omni.py                  entry point del CLI (main)
├── nexus_worker.py          worker durable
├── pyproject.toml           packaging + mypy + entry point
├── Makefile                 gates: syntax, lint, test, typecheck, lock
├── install.sh               instalador (pipx/venv)
├── requirements-dev.lock    lock con hashes
├── nexus_core/
│   ├── kernel/              gateway, policy, auditoría, approvals, sandbox, store
│   ├── scope/               engagements y validación HMAC
│   ├── agent/               29 módulos (react_coordinator 6.150 líneas)
│   ├── tools/               89 handlers, registry (88 tools), parsers
│   ├── cli/                 REPL, TUI (19 módulos), doctor, setup, wizard
│   ├── llm/                 proveedores + selector dinámico + límites
│   ├── report/              Markdown/HTML/JSON + datos ATT&CK
│   ├── provisioner/         catálogo e instalación aprobada
│   ├── integrations/        Metasploit RPC, Sliver, MCP
│   ├── playbooks/           3 playbooks YAML + loader
│   ├── config/              TOML, XDG, secretos
│   └── tests/               371 ficheros de test
├── bench/autonomy/          benchmark sintético offline
├── docs/                    133 ficheros Markdown (misiones, ADR, auditorías)
├── scripts/                 utilidades manuales (MSF, probes, locks)
└── .github/workflows/ci.yml 3 jobs
```

Métricas reproducibles en Anexo B. No hay `examples/` ni `demos/`.

### 1.2 Punto de entrada y comandos — [REAL]

- Entry point declarado: `pyproject.toml` → `[project.scripts] omni = "omni:main"`; `omni.py:main(argv)`.
- `omni --version` → `omni 3.0.0`.
- Flags verificados con `omni.py --help`: `--doctor`, `--setup`, `--config`, `--config-path`, `--list-engagements`, `--new-engagement`, `--scope`, `--valid-hours`, `--roe`, `--resume`, `--resume-policy`, `--trust-mode`, `--autospawn`, `--supervisor-budget`, `--about`, `--banner`, `--no-tui`, `--no-fullscreen`, `--no-color`, `--json`, `--format`, `--output`.
- Subcomandos: `run`, `tool` (con `--list`), `report`, `update`, `auth`, `secrets`, `hooks`, `resume`, `engage`.
- REPL: comandos `/` documentados en README (`/ask`, `/scope`, `/engage_*`, `/tools`, `/history`, `/approvals`, `/trust`, `/sessions`, `/session`, `/detach`, `/kill-session`, `/findings`, `/facts`, `/plan`, `/panel`, `/expand`, `/playbook`, `/loot`, `/report`, `/timeline`, `/sliver`, `/implants`, `/exploit view-live`).

Comprobaciones ejecutadas: `omni --help` (4,503 s), `omni --version` (2,859 s), `omni --doctor --json --no-wizard` (JSON válido con `os`, `hardware`, `paths`…), `omni tool --list` (listado real de 88 tools), `omni --about` (banner con 88 tools).

### 1.3 Dependencias — [REAL] con reservas

- Runtime (`pyproject.toml`): `openai>=1.109,<2`, `pydantic>=2.13.4,<3`, `httpx>=0.27.0`, `python-dotenv>=1.0.1`, `google-genai>=1.30,<2`, `msgpack>=1.2.1,<2`, `sliver-py>=0.0.19`, `psycopg[binary]==3.3.4`, `prompt_toolkit>=3.0,<4`, `rich>=13,<15`, `mcp>=2.3,<3`, `keyring>=25.7,<26`, `paramiko>=3.4,<6`, `jsonschema>=4.23,<5`, `pyyaml>=6.0,<7`. Total: 15.
- Dev: `pytest`, `pytest-asyncio`, `pytest-cov`, `ruff`, `mypy>=2.4,<3`, `pip-audit`; lock con hashes (`requirements-dev.lock`) e instalación `--require-hashes` en CI.
- **CVE: [NO VERIFICABLE] localmente.** `python -m pip_audit` no está instalado en `.venv` (`No module named pip_audit`). CI lo ejecuta con `continue-on-error: true` y el propio workflow documenta el advisory abierto: `paramiko 3.5.1` / `PYSEC-2026-2858`, sin release corregida, que respalda `nexus.post.*`.

### 1.4 Tests y CI — [PARCIAL]

- 371 ficheros de test, 4.906 tests recolectados (`--collect-only`), 4.852 pasan, **1 falla**, 53 omitidos.
- Fallo reproducible: `nexus_core/tests/integration/test_tui_pty_integrity.py::test_logs_stay_inside_the_router_on_a_real_pty` (`assert []` en la línea 109; falla también en solitario en 2,63 s).
- Cobertura: **no medible en este entorno**. Dos intentos de `--cov=nexus_core` sobre la suite completa terminaron con `Killed` (exit 137, OOM) con 3,8 GB de RAM. Una ejecución parcial (`--cov=nexus_core/kernel` con un solo fichero de test) da 37% del paquete kernel, dato **no representativo**. No hay `--cov` ni umbral de cobertura en CI ni en el `Makefile`.
- CI (`.github/workflows/ci.yml`): job `cli` (`make syntax lint test`, `pip-audit` no bloqueante, `make typecheck` incremental), job `postgres` (servicio PostgreSQL 17, `make test-postgres` + concurrencia), job `secrets` (gitleaks). Configuración correcta en forma; **estado real de las ejecuciones en GitHub: [NO VERIFICABLE]** desde este entorno. Por los dos gates rojos locales, un push de HEAD haría fallar el job `cli`.
- Tests E2E de red: opt-in con `NEXUS_E2E=1`, no ejecutados aquí (requieren binarios, servicios y alcance).

### 1.5 Documentación — [PARCIAL]

- 133 ficheros `.md`; `README.md` de 1.127 líneas; `SECURITY.md`, `BACKLOG.md`, `CHANGELOG.md`, `OMNI.md`, `LICENSE`, `docs/missions/` con auditorías previas (`AUDITORIA_EXTERNA_OMNI_2026-10-22.md`, `AUDITORIA_ARQUITECTONICA_MCP_PTY_2026-10-21.md`), planes, informes de salas y ADR.
- Discrepancias verificadas: licencia (README:984 vs `LICENSE`), CHANGELOG v2 (ver 1.5/Anexo C), cifras de tests obsoletas (`BACKLOG.md` cita 2.421 / 3.112 / 2.667 “passed”; hoy son 4.852), estado contradictorio de `oci_network` (`sandbox_modes.py` docstring dice implementado; `SECURITY.md:76` dice no implementado).
- Documentación accionable: `omni --doctor --json`, `omni --setup`, `make syntax lint test`, `python bench/autonomy/run.py --json` funcionan tal como se documentan.

### 1.6 Módulos de IA / agentes / orquestador — [REAL]

- Proveedores: `nexus_core/llm/abstraction.py` define `OpenAIClient`, `DeepSeekClient`, `GeminiClient`, `OllamaClient`, `FakeLLMClient`; `nexus_core/llm/anthropic_client.py` define `AnthropicClient`. Seis clientes, coherentes con `README.md:71`.
- Selector dinámico: `nexus_core/llm/dynamic_selector.py` (`_ClientFactory`), límites en `nexus_core/llm/limits.py`.
- Agente: `agent/react.py` (entry point), `agent/react_coordinator.py` (6.150 líneas), `agent/parser.py` (338 líneas, extracción tolerante + validación Pydantic estricta), `agent/planner.py` (2.169), `agent/subagents.py` (971), `agent/supervisor.py`, `agent/telemetry`, `agent/coverage.py`.
- Orquestación: planner determinista por fases, playbooks declarativos (`nexus_core/playbooks/*.yaml`), `AgentSupervisor` con raíz durable, presupuesto (`BudgetLedger`) y auto-spawn opt-in (documentado como cerrado en `BACKLOG.md`, Fase 2).
- Benchmark de autonomía ejecutado: `bench/autonomy/run.py --json` → 13/13 escenarios, 4/4 objetivos con evidencia verificable, provenance 1,0, 6.320 tokens, 327.920 ms. Es **sintético y offline** (sin red, sin modelo, sin salas): mide el motor, no capacidad real de pentesting.

### 1.7 Módulos de seguridad ofensiva — [REAL]

Catálogo de 88 tools repartidas por efecto: recon (nmap, subfinder, httpx, ftp, nfs, dns, nikto, smb, netexec, bloodhound), web (nuclei, ffuf, sqlmap, dalfox, wp_bruteforce, http_request), credenciales (hydra, crack_hash), explotación (searchsploit, MSF search/auxiliary/exploit, noPac, changepasswd), post-explotación (ssh_exec, ssh_upload, enum_system, privesc_hints, dpapi, tftp, listener, ntlm_capture, pivot_*), AD (ad_acl, ad_user_enum, impacket_secretsdump/getuserspns/psexec), C2 (**9** tools Sliver, coincide con `README.md:405`), sesiones, pwn (analyze/ret2libc), workspace, knowledge, report.

- Riesgo: 26 `high` + 2 `destructive` (`impacket_psexec`, `sliver_deploy`); ambos destructivos siguen pidiendo aprobación incluso con `--trust-mode` (README §Trust mode; `kernel/policy.py`).
- Huecos declarados por el propio backlog: explotación web gobernada incompleta (V0-11), planificador multi-vector inexistente (V0-12), SARIF roto (V0-5), loot Windows parcial (V0-13), pivote solo HTTP y sin reutilización de sesión (V0-20).

### 1.8 Ejemplos de uso — [PARCIAL]

- Ejemplos en README: instalación, wizard, `--new-engagement`, `--doctor`, REPL, sesiones, Sliver, reportes. Coherentes con la CLI verificada.
- `bench/autonomy/` ejecutable y reproducible. `scripts/` contiene utilidades manuales (`install_msfrpcd_service.sh`, `msf_verify.py`, `audit_probes.py`, `ux_probes.py`).
- **No existe** `examples/` ni `demos/` con casos ejecutables independientes: los ejemplos son bloques de README, no artefactos versionados ejecutables.

---

## 2. Auditoría por dimensión (4.1 → 4.15)

### 4.1 UX / DX — Estado: [PARCIAL] · Nota: 7/10

Evidencia: `--help` completo y en español (verificado), `--doctor --json` válido, `--setup` con plan/aprobación, wizard condicionado a TTY, errores con códigos de salida documentados (`0/1/2/3/4/130` en la ayuda de `omni run`).

Hallazgos:

| ID | Severidad | Hallazgo | Evidencia | Impacto | Recomendación |
|---|---|---|---|---|---|
| F-10 | MEDIUM | Arranque lento para un CLI: 4,503 s `--help`, 2,859 s `--version` | `time .venv/bin/python omni.py --help` | Mala percepción en uso interactivo y en scripts; se paga en cada invocación | Mover imports pesados (`omni.py:main` importa config/bootstrap/wizard antes de parsear) a import perezoso; medir con `hyperfine` |
| F-22 | LOW | `pytest.ini` fija `log_cli = true`, lo que inunda la salida de test y dificulta leer fallos en CI | `nexus_core/tests/pytest.ini` | Diagnóstico más lento | `log_cli=false` por defecto, activarlo con `-o log_cli=true` |
| F-18 | MEDIUM | Métricas de tests obsoletas en la documentación (2.421/3.112/2.667 vs 4.852) | `BACKLOG.md`, secciones Fase 2/V0 | El lector no puede saber qué se midió ni cuándo | Sustituir cifras por la salida fechada del gate o enlazar el artefacto |

Recomendaciones: (1) perfilado de arranque y lazy imports; (2) unificar `--help` con ejemplos de una línea por comando; (3) actualizar cifras de tests con comando reproducible.

### 4.2 Diseño CLI / TUI — Estado: [REAL] · Nota: 8/10

Evidencia: TUI sobre `prompt_toolkit` con 19 módulos (`nexus_core/cli/tui/`: `layout.py`, `completion.py`, `markdown.py`, `panels.py`, `stream.py`, `status.py`, `history.py`, `fallback.py`), alt-screen con `--no-fullscreen`, fallback a readline, autocompletado de comandos/tools/argumentos/engagements, historial JSONL con permisos 600 y retención.

Hallazgos:

| ID | Severidad | Hallazgo | Evidencia | Impacto | Recomendación |
|---|---|---|---|---|---|
| F-01 | BLOCKER | Test PTY de integridad de la TUI falla | `nexus_core/tests/integration/test_tui_pty_integrity.py:109` (`assert []`), fallo en solitario | El gate `make test` no pasa; la garantía “una sola frontera de escritura” no está verificada en HEAD | Diagnosticar el router de logs en PTY; si es dependiente de entorno, aislarlo con marker `pty` **sin** debilitar el assert, y ejecutarlo en job dedicado |
| F-17 | LOW | Artefactos basura en el árbol: `partial` (16 B) y `docs/missions/audit-v1/evidence-index-baseline.txtclear` (0 B) | `ls -la`, `git status --porcelain` | Ruido y confusión sobre qué es evidencia | Borrar o mover a `docs/missions/audit-v1/` con nombre correcto |

Recomendaciones: (1) arreglar el test PTY; (2) prueba de humo de la TUI en CI con `--no-tui` y una PTY sintética; (3) documentar keybindings en `--help` (hoy solo en README).

### 4.3 Arquitectura backend — Estado: [PARCIAL] · Nota: 6/10

Evidencia: separación razonable `cli / agent / tools / kernel / scope / report`; gateway con orden de controles explícito; `control_store.py` (1.019 líneas) con SQLite/PostgreSQL; `ArtifactStore` content-addressed; hooks `pre_tool_use`/`post_tool_use`/`session_end`; journal durable.

Hallazgos:

| ID | Severidad | Hallazgo | Evidencia | Impacto | Recomendación |
|---|---|---|---|---|---|
| F-11 | HIGH | Clase dios: `react_coordinator.py` 6.150 líneas; `planner.py` 2.169; `fact_verification.py` 1.626 | `wc -l nexus_core/agent/react_coordinator.py` | Complejidad, riesgo de regresión y bus factor; difícil testear unidades | Extraer motor de turno, despacho de tools y completion gate a módulos con contratos y tests propios |
| F-16 | MEDIUM | Planificador de un solo vector: no encadena varios caminos a root (deuda V0-12 del backlog) | `BACKLOG.md` V0-12; `agent/planner.py` | Salas con múltiples vectores se resuelven a mano o se estancan | Cola de vectores con estados descubierto/probado/explotado/descartado |
| F-24 | INFO | `nexus.system.install_tool` es `high` y no exige scope (por diseño: instala local) | `tool_catalog()`; `pyproject.toml` | Correcto, pero el contrato no lo distingue de tools de objetivo | Documentar `scope_required=False` con justificación en el catálogo |

Recomendaciones: (1) dividir el coordinador; (2) tests de contrato por fase; (3) ADR del orden de controles del gateway (hoy está en comentarios de código).

### 4.4 Calidad de código Python — Estado: [PARCIAL] · Nota: 6/10

Evidencia: type hints extensos, Pydantic v2 en DTOs, `ruff.toml` (py312, 100 columnas), `mypy` configurado con `no_implicit_optional`, `warn_unused_ignores`, `warn_redundant_casts`; `make lint` limitado a `--select F,E9`; `make typecheck` incremental.

Hallazgos:

| ID | Severidad | Hallazgo | Evidencia | Impacto | Recomendación |
|---|---|---|---|---|---|
| F-02 | HIGH | Gate de lint rojo: 3 `F401` | `ruff check nexus_core omni.py nexus_worker.py --select F,E9` → exit 1; `nexus_core/tests/unit/test_background_wait.py:17,18` y el import de `_catalog` | CI rojo y señal de que el gate no se ejecuta antes de commitear | `ruff check --fix` + pre-commit real que bloquee |
| F-13 | MEDIUM | Mypy no está limpio: el backlog admite 23 errores preexistentes en `cli/tui/session.py`, y el gate es incremental | `BACKLOG.md` “Calidad · Tipado TUI”; `Makefile` (`typecheck` solo ficheros cambiados) | El tipado no cubre el repo; errores nuevos pueden esconderse tras la base | Fijar `mypy` sobre `nexus_core/cli/tui` con `# type: ignore` justificados uno a uno, y luego cerrar |
| F-12 | MEDIUM | 265 marcas TODO/FIXME/XXX/HACK en código no-test; 95 en `agent/engagement_plan.py` | `grep -rn -E 'TODO|FIXME' nexus_core` | Deuda no inventariada; el archivo con 95 marcas es el más cargado | Convertir cada TODO en issue o borrarlo; prohibir TODO sin ID |

Recomendaciones: (1) lint verde y pre-commit; (2) `ruff` con reglas adicionales (`B`, `SIM`, `ASYNC`) en modo no bloqueante y quemar hallazgos; (3) unificar `make lint` con CI.

### 4.5 Seguridad ofensiva (capacidades reales) — Estado: [REAL] · Nota: 8/10

Evidencia: catálogo por fases (recon → acceso → escalada → post-ex → lateral → C2 → reporte); 9 tools Sliver, 5 de AD, impacket, pwn, pivotes; reporte con CVSS/MITRE/CWE y chain of custody; `derive_assertions` promueve hallazgos solo desde parsers deterministas.

Hallazgos:

| ID | Severidad | Hallazgo | Evidencia | Impacto | Recomendación |
|---|---|---|---|---|---|
| F-14 | MEDIUM | SARIF prometido pero no escrito: `format:both` reporta `sarif_size_bytes > 0` y `report_path_sarif` vacío | `BACKLOG.md` V0-5 (reproducido en salas 8 y 9) | Un consumidor de SARIF recibe una ruta inexistente | Escribir el `.sarif` o no anunciar tamaño; test de artefacto existente |
| F-15 | MEDIUM | El blackboard no superpone hechos: duplica hipótesis y hallazgo acreditado | `BACKLOG.md` V0-33 | Reportes inflados y evidencia ambigua | Relación `supersede`/clave canónica con migración aditiva |
| F-16 | MEDIUM | Sin planificador multi-vector (repetido de 4.3) | V0-12 | Estancamiento en el primer hallazgo | Ver 4.3 |

Recomendaciones: (1) cerrar V0-5 y V0-33 con tests de tamaño/no duplicación; (2) parser de loot Windows (V0-13); (3) medir cobertura de kill chain con una sala de 3 rutas.

### 4.6 Seguridad operacional del propio OMNI — Estado: [PARCIAL] · Nota: 6/10

Evidencia: secretos en keyring (con detección del backend `fail`) o fichero `0600` (`config/secrets.py`), valores nunca impresos; redacción de credenciales en auditoría/resultados (`kernel/redaction.py`, `sanitize`); scope HMAC `governed` por defecto; `NEXUS_ENV=production` prohíbe `local`/`local_strict` (`SandboxPolicy.resolve`); gitleaks en CI.

Hallazgos:

| ID | Severidad | Hallazgo | Evidencia | Impacto | Recomendación |
|---|---|---|---|---|---|
| F-06 | HIGH | Aislamiento real ausente en modos locales y modo por defecto `local_strict` | `sandbox_modes.py` `GUARANTEES`: todo `False`; `_build_executor` → `LocalSandbox`; solo 7/88 tools con `sandbox_required` | El agente lee/escribe el host del operador; una inyección de prompt puede leer `~/.ssh` o `secrets.json` | Documentar el riesgo en el arranque (ya se hace) **y** ofrecer `oci` como default cuando Docker exista; medir cobertura de `sandbox_required` |
| F-07 | HIGH | Scope no cubre egress del shell universal (SEC-01); 27 tools sin `scope_required` | `SECURITY.md:74`; `tool_catalog()` (27 sin scope) | Tráfico fuera del engagement no bloqueado | Proxy de egress por engagement (SEC-01); revisar cada tool sin scope y justificarla en el catálogo |
| F-08 | MEDIUM | Plugins vía entry points `nexus.tools` sin allowlist ni firma (SEC-05) | `nexus_core/tools/registration.py:38`; `SECURITY.md:77` | Un paquete instalado puede registrar tools con `risk` arbitrario | Allowlist + firma/TOFU por hash, como ya se hizo con hooks (`hooks-trust.json`) |
| F-19 | MEDIUM | Auditoría de dependencias no ejecutable localmente y no bloqueante en CI; advisory abierto en paramiko | `No module named pip_audit`; `ci.yml` (`continue-on-error: true`, `PYSEC-2026-2858`) | CVE conocida en la cadena SSH que soporta post-explotación | Instalar `pip-audit` en el venv de desarrollo; fijar paramiko a una versión mitigada o sustituir el cliente |

Recomendaciones: (1) priorizar SEC-01 y SEC-05; (2) default seguro según disponibilidad de OCI; (3) `pip-audit` bloqueante tras resolver paramiko.

### 4.7 IA / Agentes / Orquestador — Estado: [REAL] · Nota: 7/10

Evidencia: 6 proveedores (5 + Fake offline); parser tolerante con validación Pydantic estricta (`agent/parser.py`); presupuesto por run y por árbol (`BudgetLedger`, `kernel_budget_reservations`); subagentes con `AgentSupervisor`; telemetría de turno (`turn_telemetry.py`, 591 líneas); journal de invocaciones.

Hallazgos:

| ID | Severidad | Hallazgo | Evidencia | Impacto | Recomendación |
|---|---|---|---|---|---|
| F-16 | MEDIUM | No hay orquestación multi-vector ni reutilización de credenciales entre ramas (V0-12) | `BACKLOG.md`; `agent/planner.py` | El “orquestador” es un bucle único con subagentes, no un planificador de vectores | Definir contrato de vector y cola de prioridad; tests con 3 rutas |
| F-21 | INFO | El banner muestra “2 providers” mientras el README lista 6 | `omni --about`; `nexus_core/cli/banner.py:242` | Ambigüedad: parece que faltan proveedores | Etiquetar “2 configurados” en el banner |
| — | — | Benchmark de autonomía solo sintético | `bench/autonomy/run.py`: 13/13, 4/4, 327,9 s | No demuestra autonomía en salas reales | Medir con las salas V2 ya planificadas y publicar tasa por sala |

Recomendaciones: (1) benchmark con salas reales y métrica de éxito por objetivo; (2) presupuesto y coste por fase visibles en `/status`; (3) contrato de vector (V0-12).

### 4.8 Extensibilidad — Estado: [PARCIAL] · Nota: 4/10

Evidencia: `@register_tool` y entry points `nexus.tools` (`tools/registration.py`); skills en `.agents/skills/`; hooks con confianza externa al repo (`omni hooks trust/list/revoke`); playbooks YAML con `jsonschema`.

Hallazgos:

| ID | Severidad | Hallazgo | Evidencia | Impacto | Recomendación |
|---|---|---|---|---|---|
| F-08 | MEDIUM | Sin sandbox/permisos/versionado para plugins (SEC-05) | `registration.py:38` | Cadena de suministro de tools sin control | Firma por hash + allowlist + versión mínima |
| — | — | API pública no documentada como estable; no hay guía de plugin con ejemplo ejecutable | `docs/` (no hay guía de plugins); `examples/` ausente | Terceros no pueden extender sin leer el kernel | `docs/PLUGINS.md` + plugin de ejemplo con test |
| — | — | Sin tests de compatibilidad de entry points más allá de `test_tool_registration.py` | `nexus_core/tests/unit/test_tool_registration.py` | Roturas silenciosas al cambiar el registro | Matriz de compatibilidad y test de carga de un plugin externo |

Recomendaciones: (1) seguridad de plugins; (2) guía + ejemplo; (3) versionado del contrato de tool (`schema_version` ya existe en el catálogo).

### 4.9 Errores, logging, observabilidad — Estado: [REAL] · Nota: 7/10

Evidencia: jerarquía propia (`kernel/errors.py`: `ApprovalRequired`, `ReplayApprovalRequired`, `ToolInputError`); auditoría encadenada por hash; `telemetry.span`/`metrics` en el gateway; `NEXUS_LOG_LEVEL`; `DeferredStreamHandler` y proxies de `sys.stdout/stderr` en TUI (README §Frontera única de escritura).

Hallazgos:

| ID | Severidad | Hallazgo | Evidencia | Impacto | Recomendación |
|---|---|---|---|---|---|
| F-01 | BLOCKER | La prueba de que los logs no rompen la TUI falla | `test_tui_pty_integrity.py:109` | La garantía de observabilidad no está verificada | Arreglar el test y el router |
| — | — | Rotación de logs no verificada | no hay evidencia leída de `RotatingFileHandler` | Crecimiento indefinido si se escribe a fichero | Verificar/añadir rotación y límite |
| — | — | Métricas sin exporter documentado | `metrics.increment` en gateway; no se auditó backend | Observabilidad local, no operacional | Documentar exporter o declararlo fuera de alcance |

Recomendaciones: (1) test PTY; (2) política de retención de logs; (3) trazas correlacionadas por `run_id` en `/timeline`.

### 4.10 Configuración — Estado: [REAL] · Nota: 7/10

Evidencia: XDG (`config/xdg.py`), TOML, `apply_environment` con `os.environ.setdefault` (entorno > `.env` > TOML > defaults, `config/loader.py:77-96`), `--config`, `--config-path`, `--reset-config` con backup, `tui.json` separado.

Hallazgos:

| ID | Severidad | Hallazgo | Evidencia | Impacto | Recomendación |
|---|---|---|---|---|---|
| — | MEDIUM | Las claves de proveedor se copian al entorno del proceso | `config/loader.py:87` (`os.environ[provider.upper()+"_API_KEY"] = key`) | Visibles para procesos hijos y volcados de entorno | Pasar el secreto por objeto de cliente, no por `os.environ` |
| — | LOW | Precedencia documentada pero dispersa entre loader, `llm_env.py` y bootstrap | `config/loader.py`, `cli/llm_env.py` | Difícil razonar sobre overrides | Un único resolvedor con test de matriz |
| — | LOW | Falta validación de esquema del TOML con Pydantic | `config/loader.py` (carga y defaults manuales) | Config corrupta se respalda, pero errores semánticos pasan | `ConfigModel` Pydantic con `extra="forbid"` |

Recomendaciones: (1) sacar secretos del entorno; (2) resolvedor único; (3) esquema validado.

### 4.11 Tests — Estado: [PARCIAL] · Nota: 7/10

Evidencia: 4.906 tests, 4.852 verdes, 53 skip, 1 rojo; 371 ficheros; markers `unit/integration/slow/pty`; CI con PostgreSQL real y gitleaks; tests de seguridad puntuales (redacción, scope, aprobaciones).

Hallazgos:

| ID | Severidad | Hallazgo | Evidencia | Impacto | Recomendación |
|---|---|---|---|---|---|
| F-01 | BLOCKER | 1 test rojo reproducible | ver 4.2 | Gate `make test` rojo | Arreglar |
| F-09 | MEDIUM | Sin cobertura medible ni umbral: `--cov` OOM (exit 137); CI no mide cobertura | dos ejecuciones `Killed`; `ci.yml` sin `--cov` | No se sabe qué % del motor está probado | Medir en runner con más RAM o por paquetes; publicar cifra y umbral |
| — | MEDIUM | Sin fuzzing ni tests de inyección sobre parser/schemas | no hay evidencia de fuzz en `nexus_core/tests` | Superficie de entrada del LLM poco estresada | `hypothesis` sobre `parse_react_response` y validadores de schema |
| — | LOW | Los E2E de red no corren en CI | `NEXUS_E2E=0` en `ci.yml` | Regresiones de integración real no detectadas | Job nocturno con binarios y un objetivo local |

Recomendaciones: (1) verde; (2) cobertura con umbral por paquete; (3) fuzzing del parser.

### 4.12 Documentación — Estado: [PARCIAL] · Nota: 6/10

Evidencia: README muy completo (1.127 líneas), `SECURITY.md` honesto, `BACKLOG.md` con deudas y criterios de cierre, 133 `.md`, auditorías previas.

Hallazgos:

| ID | Severidad | Hallazgo | Evidencia | Impacto | Recomendación |
|---|---|---|---|---|---|
| F-04 | HIGH | README niega licencia; `LICENSE` existe y restringe redistribución | `README.md:984` vs `LICENSE` | Riesgo legal y de confianza | Corregir README y enlazar `LICENSE` |
| F-05 | MEDIUM | CHANGELOG v2 describe FastAPI/JWT/RBAC/dashboard/Junior Agent inexistentes | `CHANGELOG.md:17-31`; `grep fastapi` en `nexus_core` vacío | Historia del producto engañosa | Marcar v1/v2 como linaje histórico de otro producto o eliminar |
| F-18 | MEDIUM | Cifras de tests obsoletas en backlog | `BACKLOG.md` | Métricas no reproducibles | Enlazar evidencia fechada |
| F-23 | MEDIUM | `oci_network`: docstring dice implementado, `SECURITY.md:76` dice no implementado | `sandbox_modes.py` vs `SECURITY.md:76` | El operador no sabe qué creer | Una sola fuente de verdad y estado explícito |

Recomendaciones: (1) licencia; (2) limpiar CHANGELOG; (3) revisar cifras; (4) resolver la contradicción de `oci_network`.

### 4.13 Performance — Estado: [PARCIAL] · Nota: 5/10

Evidencia: benchmark sintético 13/13 en 327,9 s; arranque CLI 2,9–4,5 s; `doctor` limita `parallel_tools` a 1 en hardware de 4 núcleos (`hardware` en `--doctor --json`).

Hallazgos:

| ID | Severidad | Hallazgo | Evidencia | Impacto | Recomendación |
|---|---|---|---|---|---|
| F-10 | MEDIUM | Arranque 4,5 s (`--help`) | medición `time` | UX y scripts | Lazy imports |
| F-09 | MEDIUM | La instrumentación de cobertura agota 3,8 GB y muere | exit 137 dos veces | No hay métrica de cobertura; indica picos de memoria del proceso de test | Medir con `--cov` por paquetes y runner de 8 GB; perfil de memoria |
| — | MEDIUM | `parallel_tools` efectivo = 1 en 4 núcleos | `omni --doctor --json` → `limits.parallel_tools=1` | Paralelismo conservador; runs largos | Revisar la regla de hardware y hacerla configurable con test |

Recomendaciones: (1) perfil de arranque; (2) medir memoria de la suite; (3) benchmark de latencia por tool (nmap/ffuf) con objetivo local.

### 4.14 Empaquetado / Distribución / Instalación — Estado: [PARCIAL] · Nota: 5/10

Evidencia: `pyproject.toml` limpio (setuptools, `py-modules`, `packages.find`, `package-data` para YAML/JSON), entry point `omni`, versión 3.0.0, lock reproducible, `install.sh` con `--dry-run`, `omni update`.

Hallazgos:

| ID | Severidad | Hallazgo | Evidencia | Impacto | Recomendación |
|---|---|---|---|---|---|
| F-03 | HIGH | 27 modificados + 7 sin trackear; lo auditado no está commiteado | `git status --porcelain` | Instalación y CI no reproducen el estado real | Commit o rama con PR; tag solo desde árbol limpio |
| — | MEDIUM | No publicado en PyPI (el propio README lo dice) y sin Dockerfile | `README.md` §Instalación; raíz sin `Dockerfile` | Distribución depende del repo git | Publicar wheel firmada o documentar canal único |
| — | LOW | `build/` presente en el árbol (no trackeado) | `ls`; `git ls-files build` = 0 | Ruido y riesgo de import accidental | Añadir a `.gitignore` y borrar |

Recomendaciones: (1) commit/tag del estado; (2) publicar o congelar canal; (3) limpiar `build/`.

### 4.15 Ética y uso responsable — Estado: [REAL] · Nota: 7/10

Evidencia: `LICENSE` de uso autorizado; `SECURITY.md` con modelo de privilegios sin adornos; scope HMAC obligatorio en `governed`; RoE con kill switch (`omni --roe`); `--trust-mode` no autoaprueba destructivas; aviso de que el scope no concede permiso legal (`LICENSE` §2).

Hallazgos:

| ID | Severidad | Hallazgo | Evidencia | Impacto | Recomendación |
|---|---|---|---|---|---|
| F-04 | HIGH | Licencia no OSI y contradictoria con README | `LICENSE`; `README.md:984` | Adopción y redistribución bloqueadas; confusión legal | Decidir licencia (propietaria coherente u OSI) y reflejarla |
| — | LOW | Sin fecha/versión de revisión legal ni contacto operativo en `LICENSE` | `LICENSE` | Gobernanza incompleta | Añadir versión y canal |

Recomendaciones: (1) resolver licencia; (2) añadir aviso de autorización en el primer arranque (el wizard ya lo sugiere); (3) registrar el consentimiento del engagement con timestamp.

---

## 3. Truth Check

**¿Estoy a nada de terminar o me estoy imaginando cosas?** Ninguna de las dos cosas, y conviene decirlo sin anestesia: el **cuerpo** (kernel, tools, gobernanza, TUI, reportes) está esencialmente construido y probado; el **cerebro/orquestación multi-vector** está a medias; y hay un conjunto pequeño pero real de **afirmaciones documentales que el código no respalda**.

### Qué está realmente terminado

- **Gateway único con gobernanza verificable.** `tool_gateway.py` aplica scope, RoE, policy, aprobación durable, hooks, journal, post-condición y auditoría en un solo punto. No es una promesa: es el camino obligatorio de toda tool.
- **Secretos.** Keyring con detección del backend `fail` y fallback a `0600` (`config/secrets.py`), valores nunca impresos, rotación por `omni auth login`.
- **Catálogo durable.** 88 tools reales, 61 con scope, 2 destructivas, con test de consistencia contra `docs/missions/audit-v1/catalog.json`.
- **Bucle ReAct durable.** Journal por paso, `step_key` del motor, deduplicación de efectos y respuesta explícita a repeticiones.
- **CLI/TUI.** `--doctor --json`, `--setup`, wizard, TUI `prompt_toolkit` con fallback, historial 600/JSONL, autocompletado.
- **Reportes.** Markdown/HTML/JSON con CVSS, MITRE, CWE y chain of custody; el HTML es autocontenido.
- **Suite.** 4.852 tests verdes (98,9% de los 4.906 recolectados). Es evidencia de ingeniería, no de marketing.

### Qué está a nada de terminar (90%, faltan cosas concretas)

1. **Verde de gates.** Falta arreglar 1 test PTY (`test_tui_pty_integrity.py:109`) y 3 imports sin usar (`test_background_wait.py`). Sin eso, CI no puede pasar. Es trabajo de horas, no de semanas.
2. **Licencia.** Una línea del README (`README.md:984`) contradice `LICENSE`. Decisión de negocio, no técnica.
3. **Métrica de cobertura.** No hay cifra ni umbral; la medición OOM en 3,8 GB. Falta un runner con memoria y un `--cov-fail-under` por paquete.
4. **SARIF (V0-5).** El reporte anuncia tamaño y no escribe el fichero; es un bug acotado con criterio de cierre ya escrito.
5. **Blackboard sin supersede (V0-33).** Duplica hallazgos; requiere migración aditiva y test de no duplicación.
6. **Documentación numérica.** Backlog con cifras de tests de hace varias fases (2.421/3.112/2.667 vs 4.852).

### Qué es humo, promesa o imaginario

- **CHANGELOG v2.0.0** (`CHANGELOG.md:17-31`): “Junior Agent con GPT-4o”, “JWT Auth”, “RBAC con middleware en FastAPI”, “Dashboard PRO de 15 páginas”, “FastAPI + SQLite con aiosqlite”. En `nexus_core` no hay una sola importación de `fastapi`, `aiosqlite` ni `jwt` (`grep -rln 'import fastapi|from fastapi|aiosqlite|jwt' nexus_core` → vacío). Es historia de **otro producto** (linaje NEXUS) presentada sin marca de histórico.
- **“Por definir” la licencia** (`README.md:984`) cuando `LICENSE` existe desde el inicio del repo. No es humo del autor sobre funcionalidad, pero sí una afirmación falsa en el documento que más se lee.
- **`oci_network`**: el docstring de `sandbox_modes.py` afirma que está implementado por `OCINetworkSandbox`; `SECURITY.md:76` dice que no está implementado y que en OCI el agente no alcanza el objetivo. Ambas cosas no pueden ser verdad a la vez; el código, además, lanza `SandboxModeNotImplemented` si faltan proxy y red.
- **SARIF**: se anuncia `sarif_size_bytes` sin escribir el `.sarif` (V0-5, reproducido en dos salas según el backlog).
- **“Orquestador multi-agente”**: existe un bucle ReAct único con subagentes y un planner determinista por fases; **no** existe el planificador de kill-chain multi-vector que el discurso de “orquestación” sugiere (V0-12, admitido en el backlog).

### Qué riesgos reales tiene llevar esto a producción

- **Seguridad:** el default `local_strict` no aísla lectura, escritura ni red; el agente corre con los privilegios del operador; el scope no cubre el egress del shell; los plugins no están firmados. En producción real, `NEXUS_ENV=production` obliga a `oci`, pero `oci` no tiene red y `oci_network` no está operativo sin proxy: el operador queda entre “no llego al objetivo” y “no estoy aislado”.
- **Legal:** licencia propietaria “Authorized Use Only” que restringe redistribución, con README que dice que no hay licencia. Cualquier uso comercial o distribución requiere una decisión explícita.
- **Mantenibilidad:** coordinador de 6.150 líneas, 265 TODO, un solo contribuidor (272 commits, 1 autor humano en el histórico), y gates de calidad que no se ejecutan o no pasan. Bus factor 1.
- **Cadena de suministro:** `paramiko` con advisory abierto (`PYSEC-2026-2858`) y `pip-audit` no bloqueante; `sliver-py`, `mcp` y `google-genai` amplían superficie.

### Veredicto honesto de madurez

**Alpha.** Tres evidencias que lo sostienen: (1) dos gates de calidad rojos en HEAD (test y lint), que impiden llamarlo Beta; (2) deudas P0/P1 abiertas y admitidas que afectan a la seguridad operacional (SEC-01, SEC-03, SEC-05) y al producto (V0-5, V0-12, V0-33); (3) ausencia de métrica de cobertura y de un estado commiteado reproducible (27+7 ficheros sin commit). Lo que sí es cierto: no es un prototipo; hay 88 tools, 4.852 tests verdes y una arquitectura de gobernanza que muchas herramientas comerciales no tienen.

---

## 4. Roadmap priorizado

### Quick wins (≤1 día)

1. `ruff check --fix nexus_core/tests/unit/test_background_wait.py` y ejecutar `make lint` hasta exit 0.
2. Arreglar `test_logs_stay_inside_the_router_on_a_real_pty`: reproducir con `pytest ... -s`, localizar el frame perdido en `cli/tui/output.py`/`stream.py`; si el fallo es del entorno PTY, aislarlo con `@pytest.mark.pty` y job dedicado **sin** quitar el assert.
3. Corregir `README.md:984` para que enlace `LICENSE` (o retirar `LICENSE` si la decisión es no licenciar; hoy la contradicción es el peor estado).
4. Borrar `partial` y `docs/missions/audit-v1/evidence-index-baseline.txtclear`; añadir `build/` a `.gitignore`.
5. Actualizar las cifras de `BACKLOG.md` con la salida fechada de `pytest -q` (4.852/4.906) y marcar `CHANGELOG.md` v1/v2 como linaje histórico.

### Mejoras estructurales (1–2 semanas)

1. **Cobertura medible:** ejecutar `pytest --cov=nexus_core --cov-report=xml` por paquetes en un runner de ≥8 GB, publicar la cifra y añadir `--cov-fail-under` (empezando por `kernel` y `tools`).
2. **Tipado:** cerrar los 23 errores de `cli/tui/session.py` y cambiar `make typecheck` a un conjunto fijo de paquetes (no solo ficheros cambiados).
3. **Seguridad de plugins (SEC-05):** allowlist + firma por hash al estilo de `hooks-trust.json`; test de carga de un plugin no confiable.
4. **Cerrar V0-5 y V0-33:** escribir el `.sarif` y añadir `supersede` al blackboard con migración aditiva y tests de no duplicación.
5. **Estado reproducible:** commit o PR de los 34 cambios pendientes; tag solo desde árbol limpio; CI que falle con árbol sucio.
6. **`pip-audit` bloqueante** tras mitigar `paramiko` (o sustituir el transporte SSH).

### Refactors mayores (>2 semanas, justificados)

1. **Partir `react_coordinator.py` (6.150 líneas)** en motor de turno, despacho de tools y completion gate, con tests de contrato por módulo. Justificación: es el mayor riesgo de regresión y el mayor coste de onboarding.
2. **Egress gobernado (SEC-01):** proxy por engagement para shell universal, con pruebas de rutas permitidas/denegadas, DNS rebinding e IPv4/IPv6 (criterio ya escrito en el backlog).
3. **`oci_network` real (SEC-03 / P1-B):** contenedor con red filtrada por scope y pruebas de que no degrada a local; hoy el operador elige entre aislar y alcanzar el objetivo.
4. **Planificador multi-vector (V0-12):** cola de vectores con estados y reutilización de credenciales/loot; medir con una máquina de 3 rutas.

### Riesgos a mitigar antes de release

- Gates verdes (test + lint) y cobertura con umbral.
- Licencia decidida y coherente.
- Modo por defecto con aislamiento real o advertencia bloqueante.
- SEC-01/SEC-05 cerrados o aceptados por escrito con el cliente.
- `paramiko` sin advisory abierto.
- Estado commiteado y tag verificable.

### Qué NO tocar todavía

- El **orden de controles del gateway** (`tool_gateway.py`): scope → RoE → policy → approval → journal. Cambiarlo sin tests de seguridad rompe la garantía central.
- La **atomicidad de `ApprovalService.consume`** (actualización condicional en SQLite/PostgreSQL): está probada y es la defensa contra replay.
- El **backend de secretos** (`config/secrets.py`): keyring + `0600` con detección de `fail` es correcto; no introducir un `.env` como fuente primaria.
- El **parser tolerante** (`agent/parser.py`): sus reparaciones (fences, batches, `wait`) están fijadas por tests y por runs medidos.
- La **frontera única de escritura de la TUI** (proxies de `stdout/stderr`, `DeferredStreamHandler`): el test PTY está rojo, pero el diseño es correcto; no reescribirlo para “arreglar” el test.

---

## 5. Anexos

### A. Tabla consolidada de hallazgos

| ID | Dimensión | Severidad | Descripción | Evidencia | Recomendación |
|---|---|---|---|---|---|
| F-01 | 4.2 / 4.11 | BLOCKER | Test PTY de la TUI falla de forma reproducible | `nexus_core/tests/integration/test_tui_pty_integrity.py:109` (`assert []`); falla solo en 2,63 s | Diagnosticar router de logs; aislar con marker `pty` sin debilitar el assert |
| F-02 | 4.4 | HIGH | Gate de lint rojo por 3 `F401` | `ruff check … --select F,E9` exit 1; `nexus_core/tests/unit/test_background_wait.py:17,18` + import `_catalog` | `ruff --fix` y pre-commit bloqueante |
| F-03 | 4.14 / 0 | HIGH | Árbol sucio: 27 modificados, 7 sin trackear (handlers/tests nuevos) | `git status --porcelain` | Commit/PR y tag desde árbol limpio |
| F-04 | 4.12 / 4.15 | HIGH | README dice que no hay licencia; `LICENSE` existe y restringe | `README.md:984`; `LICENSE` | Corregir README o retirar licencia; decisión explícita |
| F-05 | 4.12 | MEDIUM | CHANGELOG v2 describe FastAPI/JWT/RBAC/dashboard inexistentes | `CHANGELOG.md:17-31`; `grep` sin resultados en `nexus_core` | Marcar como histórico o eliminar |
| F-06 | 4.6 | HIGH | Modos locales sin aislamiento; default `local_strict`; 7/88 tools con sandbox | `sandbox_modes.py` `GUARANTEES`; `tool_catalog()` | Default a `oci` si Docker; documentar garantías en arranque |
| F-07 | 4.6 | HIGH | Scope no cubre egress del shell universal; 27 tools sin scope | `SECURITY.md:74`; `tool_catalog()` | Proxy de egress (SEC-01); justificar cada tool sin scope |
| F-08 | 4.6 / 4.8 | MEDIUM | Plugins `nexus.tools` sin allowlist ni firma | `nexus_core/tools/registration.py:38`; `SECURITY.md:77` | Firma por hash + allowlist |
| F-09 | 4.11 / 4.13 | MEDIUM | Cobertura no medible (OOM, exit 137) y sin umbral | dos ejecuciones `Killed`; `ci.yml` sin `--cov` | Medir por paquetes en runner con RAM; umbral |
| F-10 | 4.1 / 4.13 | MEDIUM | Arranque lento: 4,5 s `--help`, 2,9 s `--version` | `time .venv/bin/python omni.py --help` | Imports perezosos en `omni.py:main` |
| F-11 | 4.3 | HIGH | `react_coordinator.py` 6.150 líneas; planner 2.169 | `wc -l nexus_core/agent/react_coordinator.py` | Extraer módulos con tests de contrato |
| F-12 | 4.4 | MEDIUM | 265 TODO/FIXME en código no-test (95 en `engagement_plan.py`) | `grep -rn -E 'TODO|FIXME' nexus_core` | Issue por TODO o borrado |
| F-13 | 4.4 | MEDIUM | Mypy con 23 errores preexistentes; gate incremental | `BACKLOG.md`; `Makefile` (`typecheck`) | Cerrar errores y fijar paquetes del gate |
| F-14 | 4.5 | MEDIUM | SARIF anunciado y no escrito (V0-5) | `BACKLOG.md` V0-5 | Escribir `.sarif` o no anunciar tamaño; test de existencia |
| F-15 | 4.5 | MEDIUM | Blackboard no superpone hechos; duplica hallazgos (V0-33) | `BACKLOG.md` V0-33 | `supersede` + migración + test |
| F-16 | 4.3 / 4.5 / 4.7 | MEDIUM | Sin planificador multi-vector (V0-12) | `BACKLOG.md` V0-12; `agent/planner.py` | Cola de vectores con estados |
| F-17 | 4.2 | LOW | Basura en el árbol: `partial` (16 B), `…txtclear` (0 B), `build/` | `ls -la`; `git ls-files build` = 0 | Borrar y `.gitignore` |
| F-18 | 4.1 / 4.12 | MEDIUM | Cifras de tests obsoletas (2.421/3.112/2.667 vs 4.852) | `BACKLOG.md` | Evidencia fechada del gate |
| F-19 | 4.6 | MEDIUM | `pip-audit` ausente local y no bloqueante; `paramiko` con advisory | `No module named pip_audit`; `ci.yml` (`PYSEC-2026-2858`) | Instalar y bloquear tras mitigar |
| F-20 | 4.11 | LOW | E2E de red no ejecutados en esta auditoría ni en CI | `NEXUS_E2E=0` en `ci.yml` | Job nocturno con objetivo local |
| F-21 | 4.7 | INFO | Banner “2 providers” vs 6 clientes reales | `omni --about`; `banner.py:242` | Etiquetar “configurados” |
| F-22 | 4.1 | LOW | `log_cli=true` inunda la salida de pytest | `nexus_core/tests/pytest.ini` | Desactivar por defecto |
| F-23 | 4.12 | MEDIUM | `oci_network`: docstring “implementado” vs `SECURITY.md` “no implementado” | `sandbox_modes.py`; `SECURITY.md:76` | Fuente única de verdad |
| F-24 | 4.3 | INFO | `install_tool` es `high` sin scope (por diseño local) | `tool_catalog()` | Documentar la excepción en el catálogo |

### B. Métricas objetivas (comandos reproducibles)

| Métrica | Valor | Comando |
|---|---|---|
| Ficheros Python en `nexus_core` | 691 | `find nexus_core -name '*.py' \| wc -l` |
| LOC en `nexus_core` | 195.844 | `find nexus_core -name '*.py' -print0 \| xargs -0 wc -l \| tail -1` |
| Ficheros de test | 371 | `find nexus_core/tests -name 'test_*.py' \| wc -l` |
| Tests recolectados | 4.906 | `.venv/bin/python -m pytest nexus_core/tests --collect-only -q` |
| Tests ejecutados | 4.852 pasan, 1 falla, 53 skip, 249,75 s | `.venv/bin/python -m pytest nexus_core/tests -q -p no:cacheprovider` |
| Tools del catálogo | 88 (26 high, 26 medium, 20 read_only, 14 low, 2 destructive) | `.venv/bin/python -c "from nexus_core.tools.registry import tool_catalog; …"` |
| Tools con scope | 61 | ídem |
| Tools con sandbox declarado | 7 | ídem |
| Tools sin scope | 27 | ídem |
| Handlers | 89 ficheros | `ls nexus_core/tools/handlers \| wc -l` |
| Arranque `--help` | 4,503 s | `time .venv/bin/python omni.py --help` |
| Arranque `--version` | 2,859 s | `time .venv/bin/python omni.py --version` |
| Lint | exit 1, 3 hallazgos `F401` | `.venv/bin/ruff check nexus_core omni.py nexus_worker.py --select F,E9` |
| TODO/FIXME (no-test) | 265 | `grep -rn -E 'TODO\|FIXME' nexus_core \| grep -v tests \| wc -l` |
| `except:` desnudos | 0 | `grep -rn -E 'except\s*:' nexus_core \| wc -l` |
| Documentación | 133 `.md`; README 1.127 líneas | `find docs -name '*.md' \| wc -l`; `wc -l README.md` |
| Cobertura | No medida (OOM, exit 137); kernel 37% con 1 fichero de test | `pytest … --cov=nexus_core --cov-report=term` |
| Benchmark autonomía | 13/13 escenarios; 4/4 objetivos con evidencia; 6.320 tokens; 327.920 ms | `.venv/bin/python bench/autonomy/run.py --json /tmp/autonomy.json` |
| Dependencias runtime | 15 declaradas; lock dev con hashes | `pyproject.toml`; `requirements-dev.lock` |
| CVEs | [NO VERIFICABLE] localmente; advisory documentado `PYSEC-2026-2858` (paramiko) | `python -m pip_audit …` → módulo ausente; `ci.yml` |
| Git | 272 commits, 1 contribuidor; HEAD `61ae348`; árbol sucio (27 M + 7 ??) | `git log --oneline`; `git status --porcelain` |

### C. Discrepancias doc ↔ código

| Afirmación (README/docs) | Estado real | Evidencia |
|---|---|---|
| «Este repositorio no incluye todavía una licencia de distribución» | `LICENSE` existe (Authorized Use Only, restringe redistribución) | `README.md:984` vs `LICENSE` |
| CHANGELOG v2: «JWT Auth», «RBAC con middleware en FastAPI», «Dashboard PRO», «FastAPI + SQLite con aiosqlite» | No hay `fastapi`, `aiosqlite` ni `jwt` en `nexus_core` | `CHANGELOG.md:17-31`; `grep -rln 'import fastapi\|from fastapi\|aiosqlite\|jwt' nexus_core` → vacío |
| «`oci_network` implementado por `OCINetworkSandbox`» | `SECURITY.md` dice no implementado; el código lanza `SandboxModeNotImplemented` sin proxy/red | `sandbox_modes.py` vs `SECURITY.md:76` |
| SARIF disponible con `format:both` | `sarif_size_bytes > 0` y `report_path_sarif` vacío; no se escribe el fichero | `BACKLOG.md` V0-5 |
| Suite con «2.421 / 3.112 / 2.667 passed» | Hoy 4.852 pasan de 4.906 | `BACKLOG.md` vs ejecución actual |
| «Nueve tools» de Sliver | 9 en el catálogo | `README.md:405`; `tool_catalog()` |
| «Cinco tools» de AD | 5 (ad_acl, ad_user_enum, netexec, bloodhound, impacket) | `README.md:377`; `tool_catalog()` |
| «88 herramientas» | 88 exactas | `README.md:208`; `tool_catalog()` |
| Proveedores: Groq, OpenAI, Anthropic, Gemini, Ollama y Fake | 6 clientes implementados | `README.md:71`; `llm/abstraction.py`, `llm/anthropic_client.py` |

### D. Cosas que el autor cree que existen y no existen

1. **El producto web del CHANGELOG v2** (FastAPI, JWT, RBAC, dashboard de 15 páginas, Junior Agent con GPT-4o, `aiosqlite`). No hay una sola importación en `nexus_core`; es linaje histórico de NEXUS presentado como versión actual del changelog.
2. **`oci_network` operativo.** El docstring del módulo lo declara implementado; `SECURITY.md:76` lo declara no implementado; el constructor exige proxy SOCKS5 y red `--internal`, y sin ambos falla con `SandboxModeNotImplemented`. No hay evidencia de un contenedor OCI real ejecutado (el propio backlog P2-A/B lo admite).
3. **Salida SARIF.** El reporte calcula y publica `sarif_size_bytes`, pero no escribe el `.sarif` (V0-5). Un consumidor que confíe en el tamaño obtiene una ruta vacía.
4. **Planificador multi-vector / kill-chain.** El discurso de “orquestación” sugiere elección y encadenado de varios caminos; el planner determinista avanza una fase y un vector a la vez (V0-12).
5. **Licencia “por definir”.** El autor cree que no hay licencia; `LICENSE` existe y condiciona el uso y la redistribución.
6. **Métricas de test vigentes en el backlog.** Las cifras 2.421/3.112/2.667 no corresponden a la suite actual (4.852 verdes).
7. **Cobertura conocida.** No hay cifra ni umbral; la instrumentación completa agota la memoria y muere (exit 137). Cualquier afirmación de cobertura sería inventada.

---

_Fin de la auditoría. Todas las cifras de este documento se obtuvieron en el workspace auditado el 2026-11-06; los puntos marcados `[NO VERIFICABLE]` no se pudieron comprobar desde este entorno (GitHub Actions, CVEs locales, E2E de red, instalación `curl | bash`)._

---

## Addendum (2026-11-06, verificado contra el árbol)

Tres hallazgos de este informe quedaron obsoletos al contrastarlos con el código y
se corrigieron en `73efa17`:

1. `oci_network` / SEC-03 **sí está implementado**: `nexus_core/kernel/sandbox.py:578`
   (`OCINetworkSandbox`), `nexus_core/kernel/egress.py` (`Socks5EgressProxy`,
   `proxy_for_scope`) y 23 tests en `test_egress_proxy.py`. La fuente obsoleta era
   `SECURITY.md`, ya corregida.
2. `build/` ya estaba en `.gitignore:23` y `partial` en `.gitignore:95` (se
   regenera en cada ejecución): no eran basura pendiente de limpiar.
3. El test PTY no medía una fuga del router. `PROBE-INFO-LINE` llega una sola vez;
   el selector buscaba la cadena `--> hola` del render anterior.

El CHANGELOG ya etiquetaba v2 como "(lineage NEXUS)" y v1 como "(baseline)": lo que
faltaba no era el rótulo, sino no presentar v3 como publicada. Este informe se
cierra con el tag `v3.0.0b1`.
