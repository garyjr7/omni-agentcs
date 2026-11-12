# Gestor de API Keys local — implementación

**Fecha:** 2026-10-28 · **Base:** `ca2f011` · **Alcance:** que el operador nunca
tenga que poner una clave en `.env` ni en el código, y que la CLI/TUI se lo pida
una sola vez de forma oculta.

**Punto de partida (auditoría previa):** `nexus_core/config/secrets.py` ya existía
y era sólido (keyring + JSON `0600` atómico, `/secrets set` en la TUI,
`import-env`). Lo que faltaba no era el almacén, sino **la puerta de entrada y la
prioridad de lectura**: no había `omni auth login`, el JSON se escribía en
`~/.config/omni/secrets.json` pero nadie lo verificaba en `doctor`, y los clientes
LLM leían **solo** `os.getenv(...)`, de modo que la clave guardada dependía del
`load_secrets_into_env()` del arranque y perdía contra cualquier valor exportado
en la shell o en `.env`.

---

## 1. Archivos modificados

| Archivo | Cambio |
|---|---|
| `nexus_core/config/secrets.py` | API por proveedor (`set_secret`/`get_secret`/`delete_secret`), `resolve_api_key` (store **antes** que entorno), `secrets_file_report` (ruta/permisos para `doctor`), `default_secrets_path`, y `_private_dir` que fuerza `0700` también cuando el directorio ya existía. `select_backend` deja de fiarse de que `keyring` esté instalado: comprueba que su backend no sea el `fail` (caja headless). `DEEPSEEK_API_KEY` añadida a `IMPORTABLE_KEYS`. |
| `nexus_core/cli/auth_cli.py` | **Nuevo.** `omni auth login [proveedor]`: menú de proveedores, lectura oculta con `getpass`, guardado en el store y mensaje sin valor. Admite inyección de lectores y store (los usa la TUI y los tests). |
| `nexus_core/cli/main.py` | `auth` como subcomando reconocido, despachado **antes** de abrir el control store: una clave es justo lo que se configura cuando el run no arranca, y no debe depender de una base de datos sana. |
| `nexus_core/cli/commands.py` | `/auth` en la tabla de comandos: mismo flujo, con `visible_input` para el menú y `secure_input` para la clave. |
| `nexus_core/cli/session.py` | `visible_input(prompt)`: lectura visible TUI-safe (la contraparte de `secure_input`), porque `input()` dentro de un meta comando pelea con prompt_toolkit. |
| `nexus_core/llm/abstraction.py` | `LLMFactory.create_from_env` resuelve las cinco claves con `resolve_api_key(...)` en lugar de `os.getenv(...)`; `DeepSeekClient` usa el mismo resolutor como último recurso. |
| `nexus_core/cli/doctor.py` | Sección **Secretos (gestor local)** con backend, ruta, existencia, permisos y número de secretos; aviso `WARNING` en `runtime_preconditions` cuando el fichero es legible por grupo/otros. |
| `.pre-commit-config.yaml` | **Nuevo.** Hook `gitleaks` (`git --pre-commit --redact --staged`) fijado a `v8.30.1`, antes de que el commit exista. |
| `nexus_core/tests/unit/test_api_key_manager.py` | **Nuevo**, 32 tests: ruta y permisos, API por proveedor, prioridad store/entorno, selección de backend, `omni auth login` (incluido end-to-end por `main()`), `/auth`, `visible_input` y la fábrica de LLM. |
| `nexus_core/tests/unit/test_doctor_secrets.py` | **Nuevo**, 4 tests: sección y aviso de permisos del doctor. |

No se añadieron dependencias: `keyring` y `getpass` ya estaban en el proyecto, y
el hook solo requiere `pip install pre-commit` (documentado en la cabecera del
YAML); no se toca `requirements-dev.txt` para no desincronizar
`requirements-dev.lock`, que es el que instala CI.

---

## 2. Flujo de uso para el operador

```bash
# 1. Guardar la clave (una vez por proveedor).
omni auth login
#   Proveedores disponibles:
#     1) openai     (OPENAI_API_KEY)
#     2) deepseek   (DEEPSEEK_API_KEY)
#     3) gemini     (GEMINI_API_KEY)
#     4) anthropic  (ANTHROPIC_API_KEY)
#   Proveedor (nombre o número): 1
#   API key de openai (no se mostrará):        <- getpass: no se ve al teclear
#   ✓ clave de openai guardada en el store (keyring)
#     variable: OPENAI_API_KEY · el valor no se imprime ni se escribe en el historial

# La forma directa, sin menú:
omni auth login deepseek

# 2. Desde la TUI, el equivalente:
#    /auth            (menú)      /auth anthropic    (directo)

# 3. Ver el estado (backend, ruta, permisos, cuántas claves hay):
omni --doctor
```

Detalles que importan:

- **Nada se imprime.** Ni el valor, ni un prefijo, ni una máscara con los últimos
  caracteres. La salida nombra el proveedor y la variable, nunca la clave, y el
  valor no entra en `readline`/`prompt_toolkit` history (`getpass` /
  `prompt_secret`).
- **Dónde se guarda.** Keyring del SO (`omni-agentcs` como servicio) y, si no hay
  un backend utilizable —SSH, contenedor, CI—, `~/.config/omni/secrets.json` con
  directorio `0700` y fichero `0600`, escrito de forma atómica
  (`mkstemp` + `fchmod` + `os.replace`). El JSON nunca se commitea: `.gitignore`
  cubre `.env` y `.env.*` desde el primer commit, y el store vive fuera del
  repositorio.
- **Borrar.** `/secrets delete openai` (la TUI no pide valor para borrar).
- **Migrar desde `.env`.** `omni auth login` no lee `.env`; para eso está
  `/secrets import-env`, que mueve `OPENAI_API_KEY`, `GEMINI_API_KEY`,
  `ANTHROPIC_API_KEY`, `GROQ_API_KEY`, `DEEPSEEK_API_KEY` y
  `NEXUS_SCOPE_SIGNING_SECRET` al store y deja que el operador borre las líneas.
- **Tras rotar una clave expuesta**, basta con volver a ejecutar
  `omni auth login <proveedor>`: el store gana sobre cualquier copia vieja.

---

## 3. Cómo consume las claves el router de modelos

`nexus_core/kernel/model_router.py` **no lee claves**: recibe clientes ya
construidos (`ModelRouter(clients, policies)`) y enruta por política, presupuesto,
circuito y fallback. El punto donde una clave se convierte en cliente es
`LLMFactory.create_from_env()` (`nexus_core/llm/abstraction.py`), que
`nexus_core/kernel/runtime.py` usa para montar el router.

Ese es el sitio que cambió:

```python
# antes: la clave solo podía venir del entorno
if os.getenv("OPENAI_API_KEY"):
    api_key=os.getenv("OPENAI_API_KEY")

# ahora: store primero, entorno después
keys = {name: resolve_api_key(name) for name in (...)}
if keys["openai"]:
    api_key=keys["openai"]
```

Consecuencias:

1. **Prioridad:** `resolve_api_key` consulta el store y, solo si no hay nada,
   `os.environ`. Una clave rotada con `omni auth login` gana sobre la línea vieja
   de `.env` o el `export` que quedó en la shell, sin tener que cazar la copia.
2. **Sin secretos en el entorno:** para construir un cliente ya no hace falta
   exportar nada. El proceso sigue funcionando si el operador nunca escribe
   `OPENAI_API_KEY` en la shell.
3. **Degradación segura:** si el backend está bloqueado o roto, la excepción se
   traga en `resolve_api_key` y se usa el entorno; y si no hay clave en ningún
   sitio, no se construye cliente para ese proveedor (el `fake` sigue
   disponible). No hay fallback silencioso a un proveedor distinto.
4. **Compatibilidad:** `load_secrets_into_env()` sigue existiendo para los
   consumidores que miran el entorno (`available_providers`, el banner) y solo
   rellena variables **no** definidas; `omni --doctor` sigue viendo la clave
   almacenada porque el arranque la publica ahí.

---

## 4. Veredicto del test de integración con `doctor`

**PASA.** Verificado con el CLI real y las XDG redirigidas a `/tmp` (ningún
fichero real del operador tocado):

| Comprobación | Resultado |
|---|---|
| `omni auth login openai` (stdin piped) | exit `0`, clave guardada, valor **no** impreso |
| Fichero creado | `~/.config/omni/secrets.json`, modo **`600`**, directorio `700` |
| Contenido | `["OPENAI_API_KEY"]`, valor correcto, JSON válido |
| Backend elegido | `file` — `keyring` está instalado pero resuelve al backend `fail`, así que el fallback se activa en vez de romper el comando |
| `omni --doctor` con `0600` | `Secretos (gestor local)`: backend `file`, `existe: sí`, `permisos: 0600 (OK)`, `secretos guardados: 1` — **sin aviso** |
| `omni --doctor --json` con `0600` | `secrets: {path, exists: true, mode: "0600", secure: true, backend: "file", names: 1}` y `config.api_keys.openai: true` (el arranque publica la clave del store en el entorno) |
| `chmod 644` + `omni --doctor` | `permisos: 0644 (INSEGUROS)` + `⚠ seguridad: … Ejecuta: chmod 600 <ruta>` |
| `chmod 644` + `omni --doctor --json` | entrada `runtime_preconditions`: `service=secretos`, `severity=warning`, `observed=mode=0644`, acción con el `chmod` exacto |
| ¿La clave aparece en la salida del doctor? | **No** (`"sk-e2e" in json.dumps(report) → False`) |

**Tests:** 36 nuevos (`test_api_key_manager.py` 32 + `test_doctor_secrets.py` 4),
todos en verde.

**Suite completa:** `4201 passed, 9 skipped, 2 failed` en 5m44s. Los dos fallos
son de `test_bench_runner.py` (`test_dry_run_lists_rooms_without_a_target`,
`test_probe_engagement_reads_back_what_it_created`) y **son previos a este
trabajo**: se reproducen igual en un worktree limpio en `HEAD`, porque el script
`bench/run_bench.py` exige un `~/.config/omni/config.toml` con
`scope.signing_secret` (es decir, un `omni --setup` hecho en la máquina del
operador). No los toca este cambio y no se han enmascarado.

**Límites declarados:**

- El hook `gitleaks` **no está activo por sí solo**: hay que ejecutar
  `pre-commit install` una vez por clon. Sin él, la protección sigue siendo la de
  CI, que llega después del push.
- `secrets_file_report` informa del fichero, no del keyring: si el backend elegido
  es el keyring, `existe: no` es correcto y la sección lo dice
  («sin fichero: keyring o sin claves»).
- `available_providers` sigue leyendo el entorno; la clave almacenada aparece ahí
  solo porque el arranque la publica. Un proceso que llame a la fábrica sin pasar
  por `bootstrap_secrets_and_config` obtiene igualmente la clave (vía
  `resolve_api_key`), pero el banner puede no listarla.
- El store no cifra en reposo cuando cae al fichero: son permisos `0600`, no
  criptografía. La alternativa cifrada sería el keyring del SO.
