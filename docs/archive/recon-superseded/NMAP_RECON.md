# NMAP_RECON — Reconocimiento para la primera herramienta ofensiva durable

Fecha: 2026-09-29
Rama: `feat/nmap-tool`
Baseline: `pytest nexus_core/tests/unit -q` → **76 passed** (71 + 5 wiring).

## 1. Sandbox (`nexus_core/kernel/sandbox.py`)

- `LocalSandbox(workspace_root, allowed_programs=("python3","git","rg"), max_output_bytes=1_000_000)`.
  - `allowed_programs` es un frozenset; `run(argv, *, cwd=".", timeout_seconds=30)`.
  - **argv es `list[str]`, sin shell** (`asyncio.create_subprocess_exec`), stdin DEVNULL,
    env mínimo (`PATH=/usr/local/bin:/usr/bin:/bin`, `NEXUS_SANDBOX=1`).
  - Si `argv[0] not in allowed_programs` → `PermissionError`.
  - stdout/stderr truncados y decodificados; timeout → mata el proceso y marca `timed_out`.
- `OCISandbox(workspace_root, allowed_images, runtime=...)`:
  - `build_argv(image, command)` exige `image in allowed_images`; incluye
    `--network none`, `--read-only`, `--cap-drop ALL`, `--user 65532:65532`.
  - `run(image, command, timeout_seconds=120)` — **firma distinta** a `LocalSandbox.run`.
- `sandbox_for_environment(workspace_root)`:
  - `NEXUS_ENV=production` → `OCISandbox` con imágenes de `NEXUS_SANDBOX_IMAGES`
    (default `python:3.12-alpine`).
  - resto → `LocalSandbox(workspace_root)` con la allowlist por defecto.

**Consecuencias para nmap**

- En dev hay que añadir `nmap` a `allowed_programs`: se pasa explícitamente
  `allowed_programs=("python3","git","rg","nmap")` desde el handler, y se extiende
  `sandbox_for_environment` con un parámetro opcional `allowed_programs`.
- En prod, `python:3.12-alpine` **no trae nmap**: hace falta una imagen con nmap
  (p.ej. `instrumentisto/nmap`) añadida a `NEXUS_SANDBOX_IMAGES`. Además, el
  `OCISandbox` actual fuerza `--network none`, que **impide cualquier escaneo de red**:
  el perfil OCI de nmap requerirá una variante con red (documentado como limitación).
- El handler nunca usa `subprocess`/`create_subprocess_exec` directo: sólo el sandbox.

## 2. ToolGateway (`nexus_core/kernel/tool_gateway.py`)

- `register(definition, handler)`: rechaza duplicados; en prod exige handler async.
- `invoke(tool_id, arguments, context: RunContext, permissions=(), approval_id=None)`:
  1. `validate(arguments, input_schema)`.
  2. Scope gating si `definition.scope_required or definition.scope_target_field`.
  3. `PolicyEngine.decide` con `Resource(tool_id, definition.tenant_id, "tool")`.
  4. Audit `tool.invoke`; exige approval si la decisión lo pide.
  5. `record_usage` (cuota), ejecuta handler, exige `ToolResult.success`
     (`verified and not timed_out and exit_code in accepted_exit_codes`),
     audita `tool.complete` / `tool.failed`.
- `ToolResult` lleva `output, verified, verification_method, evidence, exit_code,
  accepted_exit_codes, stdout, stderr, timed_out`.
- El handler recibe `(arguments: dict, context: RunContext)`.

## 3. Runtime (`nexus_core/kernel/runtime.py`)

- `execute_tool(payload, context: ExecutionContext)`:
  - construye `Identity`, carga scope con `load_engagement_scope` y arma `RunContext`.
  - contiene hoy un **dict `definitions` local** con `nexus.system.status` y
    `nexus.workspace.search` como closures (usan `context.store`, `context.worker_id`).
  - `gateway.register` sólo la tool invocada → hay que preservar eso.
- `execute_brain` invoca `execute_tool` por step y ya propaga `engagement_id`.

**Problema detectado**: los handlers del registro reciben sólo `RunContext`, pero
`system_status` necesita el `ControlStore` y el `worker_id`. Decisión: extender
`RunContext` con `store` (default None) y `worker_id` (default "") para preservar el
comportamiento exacto (mismo `ToolResult` y `evidence`) sin cambiar la firma del
handler. Se documenta.

## 4. Scope gating (`nexus_core/scope/`)

- `EngagementScope` firmado/ventana temporal; `EngagementStore(ControlStore)` CRUD.
- `ScopeValidator` + `make_scope_validator(secret)` → callable para el gateway.
- Para un dominio resuelve IPs y **todas** deben estar en `cidrs` y no excluidas.
- `scope_required=True` + `scope_target_field="target"` es exactamente lo que nmap necesita.

## 5. Entorno

- `nmap` **no está instalado** en este host; `rg` tampoco.
- La resolución DNS sí funciona:
  - `scanme.nmap.org` → `45.33.32.156` (A) y `2600:3c01::f03c:91ff:fe18:bb2f` (AAAA).
  - `example.com` → IPs de Cloudflare, fuera del scope de scanme.
- Por tanto el E2E real de nmap es opt-in (`NEXUS_E2E=1`) y además se auto-salta si
  falta el binario `nmap`. El E2E de denegación por scope sí puede correr (no usa nmap).

## 6. Decisiones de diseño

1. **`RunContext.store` / `RunContext.worker_id`**: añadir campos con default para que
   los handlers migrados conserven acceso al control store y al worker, sin cambiar la
   firma del handler que exige el gateway.
2. **Registro con tenant**: `durable_tool_definitions(tenant_id="system")` y las
   factorías `*_definition(tenant_id="system")` aceptan tenant para preservar el
   comportamiento multi-tenant previo (antes usaban `context.tenant_id`). El default
   mantiene `durable_tool_definitions()` invocable sin argumentos.
3. **Sandbox OCI**: se documenta que hace falta una imagen con nmap y que
   `--network none` bloquea el escaneo; el handler usa `NEXUS_NMAP_IMAGE`
   (default `instrumentisto/nmap`) como imagen objetivo.
4. **Allowlist**: `-oX -` se añade siempre por el handler y no está en la allowlist de
   usuario (si el LLM lo pasa, se rechaza por desconocido). El target va al final del argv.
