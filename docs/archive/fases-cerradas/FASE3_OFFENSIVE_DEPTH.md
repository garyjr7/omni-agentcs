# Fase 3 — Profundidad Ofensiva, Subagentes y Ecosistema

Documento de misión (docs-as-code) de la Fase 3 sobre `feat/offensive-depth-phase-3`,
partiendo de `feat/integration-v3` (`a5b6786`, merge real de Fase 1 + Fase 2).

> **Este documento explica el PORQUÉ de cada decisión, no solo el QUÉ.** Las
> desviaciones respecto al prompt maestro están en la §7 y las limitaciones
> honestas (lo que **no** se pudo verificar) en la §8.

---

## 0. Estado de partida (verificado en esta sesión)

| Comprobación | Comando | Resultado |
| --- | --- | --- |
| Merge Fase 1+2 | `git log -1 --format='%H %P' a5b6786` | 2 padres (`bb9062b` Fase 2 + `5aaa5fa` Fase 1) |
| Ficheros del merge | `git diff --stat bb9062b a5b6786` | 23 files, +2145/−111 (Fase 1) |
| Ficheros del merge | `git diff --stat 5aaa5fa a5b6786` | 19 files, +1851/−6 (Fase 2) |
| Suite de integración | `pytest nexus_core/tests/unit -q` | **1 failed, 1797 passed, 1 skipped** |

El merge **sí** se había completado en una sesión anterior; el único fallo era el
preexistente de `test_installer.py` (ver §2).

---

## 1. Objetivo y alcance de esta entrega

La Fase 3 completa (3A–3F) es, con diferencia, la más grande del proyecto. El
prompt maestro autoriza explícitamente dividirla si no cabe con la calidad
exigida. Se entrega **la mitad 3A** completa y verificada, y se difiere la mitad
3B con su plan (ver §9). El criterio de corte es de **dependencia**, no de
comodidad: los subagentes (3A) son la base sobre la que MCP y Skills (3B) deben
colgar, porque todo canal no confiable debe terminar en el mismo bucle ReAct
gobernado.

```
Fase 3A (esta rama, entregada)
├── 3A. Subagentes especializados      nexus_core/agent/subagents.py
├── 3B. RoE como código                nexus_core/scope/roe.py
├── 3C. Auditoría con subagent_id      agent/react.py + kernel/audit.py (existente)
└── Bugs de alta prioridad             /secrets + test_installer

Fase 3B (diferida, plan en §9)
├── 3D. Ecosistema MCP + Skills + OMNI.md
├── 3E. CVSS 4.0, mapeos, SARIF, enriquecimiento CVE
└── 3F. Modo headless (--json / --stream-json)
```

**Gobernanza intacta.** No se ha modificado la semántica del scope firmado
(HMAC), la cadena de auditoría por hash, las aprobaciones durables ni la regla
de oro (post-condición determinista). Los cambios en `kernel/` son **aditivos**:
un parámetro opcional nuevo y una llamada extra fail-closed.

---

## 2. Bug `test_installer.py::test_update_shell_path_idempotent` (resuelto)

### El diagnóstico documentado era incorrecto

Fase 1 y Fase 2 documentaron que el test fallaba porque `update_shell_path` usaba
`Path.home()` **real** mientras el fixture simulaba otro home. Comprobado en esta
sesión, **eso no es lo que ocurre**:

- El fixture `onboarding_env` **ya** mockea `Path.home` → `monkeypatch.setattr(Path, "home", lambda: home)`.
- No hubo fuga al `~/.bashrc` real (`grep` → sin coincidencias).
- En `/tmp/pytest-of-…/home/` quedó un **`.zshrc`**, no un `.bashrc`.

### La causa real

`installer.py` elige el fichero rc según `$SHELL`:

```python
rc = Path.home() / (".zshrc" if Path(os.getenv("SHELL", "")).name == "zsh" else ".bashrc")
```

En esta máquina `SHELL=/usr/bin/zsh`, así que el código escribía `.zshrc`
(correcto) mientras el test afirmaba sobre `.bashrc` (frágil: dependía del shell
del host). El test era **no determinista**, no el código.

### La corrección

Se inyectan `home` **y** `shell` en `update_shell_path` (keyword-only, con
defaults que preservan el comportamiento de producción); los dos llamantes
(`cli/wizard.py`, `tools/handlers/system_install.py`) siguen pasando el
argumento posicional sin cambios.

```python
def update_shell_path(installs_to, *, home=None, shell=None) -> bool: ...
```

Test actualizado para fijar `home=` y `shell=` (determinista en cualquier host) y
**se añaden dos tests**: la rama zsh y el rechazo de caracteres de control en el
directorio. Suite: **1800 passed, 0 failed**.

---

## 3. 3A — Subagentes especializados

### 3.1 Diseño

`nexus_core/agent/subagents.py` define un `SubAgentDefinition` como **perfil de
capacidad** de una fase, nunca como frontera de ejecución:

| Campo | Función |
| --- | --- |
| `tools` | subconjunto de tools del catálogo durable |
| `token_budget` | presupuesto de tokens propio (carril de contabilidad aislado) |
| `max_iterations` | presupuesto de iteraciones dentro del subagente |
| `read_only` / `parallel_safe` | solo los perfiles de solo lectura se paralelizan |

**Por qué no es un límite de seguridad:** el subagente solo *encoge* lo que el
modelo puede proponer. La autoridad real (policy, scope firmado, aprobaciones,
sandbox, post-condición) sigue en el gateway. Un subagente no puede ampliar su
propio poder.

### 3.2 Los ocho perfiles y su subconjunto

| id | fase | tools propias (además de las comunes¹) | tokens | iters | modo |
| --- | --- | --- | --- | --- | --- |
| `recon` | recon | nmap, subfinder, httpx, ftp, gobuster, whatweb | 20000 | 8 | read-only |
| `web` | enumeration | httpx, gobuster, whatweb, nuclei, ffuf, dalfox | 20000 | 10 | read-only |
| `cred` | enumeration | bruteforce, netexec, ftp | 12000 | 6 | activo |
| `exploit` | exploitation | msf_search/auxiliary/exploit, searchsploit, netexec | 16000 | 8 | activo |
| `postexploit` | post_exploitation | ssh_exec, enum_system, session.*, sliver sessions/exec/loot | 16000 | 8 | activo |
| `privesc` | privilege_escalation | enum_system, privesc_hints, ssh_exec | 16000 | 10 | activo |
| `lateral` | lateral_movement | netexec, bloodhound, impacket×3, bruteforce, ssh_exec, session.*, sliver | 16000 | 8 | activo |
| `reporter` | reporting | report.generate | 8000 | 4 | read-only |

¹ **Comunes a todos** (`COMMON_TOOLS`, solo leen memoria/entorno local): 
`knowledge.record_fact`, `knowledge.query_facts`, `workspace.search`,
`system.status`, `system.check_env`, `orchestrator.playbook`.

Todo id listado es un id **real** del catálogo durable: un test lo comprueba
contra los 42 builtins (`validate_registry(catalog) == []`), de modo que un typo
o una tool retirada rompe la suite en vez de fallar en silencio.

### 3.3 Selección determinista (sin modelo en el bucle)

Igual que el planner, la selección es una tabla + un refinamiento guiado por el
blackboard:

```
recon→recon  enumeration→web  exploitation→exploit  privilege_escalation→privesc
post_exploitation→postexploit  lateral_movement→lateral  reporting→reporter

refinamiento (fase == enumeration):
  si hay hechos credential/user  → cred
  si hay endpoint/vulnerability  → web
  fase desconocida / None        → recon   (fail-closed: el perfil más restrictivo)
```

El modelo **nunca** elige su perfil. El operador puede fijarlo con
`payload["subagent"]`; un override desconocido **lanza** (no cae en silencio).

### 3.4 Aplicación fail-closed en el bucle

En `run_react_loop`, cada iteración:

1. Construye el plan y selecciona el subagente.
2. Emite un run event `orchestrator.subagent` (auditable, con `previous`).
3. Aplica los presupuestos: `max_iterations` por subagente (contador que se
   reinicia al cambiar de perfil) y `token_budget` por subagente.
4. Intersecta el catálogo: `allowed_catalog = filter_catalog(subagent, catalog)`.
   El prompt **solo ofrece** el subconjunto.
5. En la puerta de tools:
   - id **inexistente** en el catálogo → `unknown_tool` (regla de oro original);
   - id **existente pero fuera del subconjunto** → `subagent_tool_denied`,
     **fail-closed**, auditado con el `subagent_id` que lo rechazó.

La asimetría es deliberada: el catálogo completo decide *inventado*; el
subconjunto decide *no es mío*. Así el mensaje al modelo es accionable y la
auditoría distingue un fallo del modelo de un límite de política.

### 3.5 Contabilidad de tokens aislada

El gasto se contabiliza en dos carriles: el total del run (`react`) y el del
subagente (`react:<id>`). Así el presupuesto de una fase no consume el de otra, y
el límite global del run se sigue respetando.

### 3.6 Paralelismo solo read-only

`gather_readonly(calls, subagent=..., limit=...)`:

- **rechaza** (antes de programar nada) un perfil `parallel_safe=False`;
- limita la concurrencia (tope duro 4, `limit` clampeado);
- cancela *todas* las llamadas en vuelo al activar `cancel_event`;
- devuelve las excepciones en su posición (`gather(return_exceptions=True)`), de
  modo que una sonda rota no descarta la evidencia de sus hermanas.

**Por qué el bucle sigue siendo secuencial:** el contrato del parser es *una*
acción por turno (un `tool_call`). Paralelizar tools dentro de una iteración
exigiría cambiar el contrato del parser y la semántica de aprobación; se
documenta como decisión consciente, y el fan-out read-only cubre el caso de uso
real (varios objetivos/variedades de enumeración).

---

## 4. 3B — RoE como código

`nexus_core/scope/roe.py`. El scope firmado responde **dónde**; la RoE responde
**cuándo, con qué intensidad y hasta cuándo**:

| Capacidad | Implementación |
| --- | --- |
| Ventanas de tiempo | `TimeWindow(start, end, days)`, con soporte de cruce de medianoche |
| Rate | `max_actions_per_minute` con ventana deslizante de 60 s |
| Concurrencia | `max_concurrent_actions` vía `RoEEnforcer.slot()` (context manager) |
| Objetivos prohibidos | patrones exactos y `*.suffix` (además del scope) |
| Categorías prohibidas | `forbidden_categories` (case-insensitive) |
| Contacto de emergencia | `emergency_contact` (visible en `--roe`) |
| Kill switch | fichero-centinela **y** evento en proceso |

**Inmutabilidad:** `RulesOfEngagement` es `frozen` y firmable (HMAC-SHA256 sobre
la forma canónica, igual que el scope). El estado mutable (ventana deslizante,
contador de concurrencia, bandera de parada) vive en `RoEEnforcer`, de modo que
una RoE firmada **nunca muta** en runtime.

### 4.1 Enganche en el gateway (aditivo, fail-closed)

`ToolGateway` acepta un `roe_validator` opcional que corre **después** del scope
firmado y **antes** de la policy. Si deniega: audita `action="roe.denied"` con
`decision="deny"` y **relanza** la `RoEViolation` (el handler nunca se ejecuta).
La RoE solo puede *estrechar* el scope, jamás ampliarlo.

El kill switch es **absoluto**: se comprueba para toda tool. La ventana, el rate
y los prohibidos solo aplican a tools con objetivo (`scope_required` o
`scope_target_field`): un reporte o una escritura en el blackboard a las 02:00 no
es una "acción de engagement". Sin RoE configurada, el comportamiento es el de
siempre (la RoE es *opt-in*).

### 4.2 CLI y persistencia

- Ficheros: `$XDG_STATE_HOME/omni/roe/<engagement>.json` (0600, escritura atómica)
  y `<engagement>.kill` (centinela).
- `omni --roe [show|path|kill|arm]` y `/roe [show|kill|arm|path]`.
- La API `save_roe()` es la vía de configuración programática.

---

## 5. Bug `/secrets` + TUI (resuelto)

### Causa

El REPL corre el bucle principal en un hilo mientras la aplicación
`prompt_toolkit` vive en otro (`omni-tui`). `cmd_secrets` llamaba a
`getpass.getpass`, que escribe **directamente** en la terminal: mientras la TUI
posee el terminal, ambos compiten y `getpass` se queda bloqueado.

### Corrección

- `TuiSession.prompt_secret()` lee con el **buffer de la propia TUI**, con la
  entrada enmascarada mediante un `ConditionalProcessor(PasswordProcessor())`
  (en `prompt_toolkit` 3.0.53 no existe el kwarg `password` de `BufferControl`).
- Durante la lectura se sustituye el historial persistente por un
  `InMemoryHistory` vacío: el secreto **no** llega al fichero de historial, ni a
  readline, ni al transcript (solo se imprime `••••••`).
- `OmniSession.secure_input()` centraliza la ruta: `input_reader` inyectado
  (tests/embeds) → `TuiSession.prompt_secret` → `getpass` (último recurso, solo
  `--no-tui`). `cmd_secrets` ya no toca `getpass`.

### Confirmación visual

```
✓ Secreto GROQ_API_KEY rotado correctamente (file)
✓ Secreto GROQ_API_KEY guardado correctamente (file)
✗ no se pudo guardar GROQ_API_KEY: OSError: disk full
```

`set` dice *guardado*, `rotate` dice *rotado*, un valor vacío dice *no se
modificó* y un fallo del store se reporta sin tumbar el REPL. Nunca se imprime el
valor.

---

## 6. 3C — Auditoría con `subagent_id`

Cada entrada `react.step` lleva ahora el `subagent_id` activo (helper `audit_step`
en el bucle), y cada observación persistida incluye `metadata["subagent_id"]`. Un
test recorre `AuditWriter.export()` y comprueba que la denegación por subconjunto
queda registrada como `subagent_tool_denied` + `deny` + `subagent_id`, y que la
cadena de auditoría sigue siendo válida (`verify_chain() == (True, None)`).

**Regla de oro intacta:** un subagente sigue sin poder declarar éxito sin la
post-condición determinista del gateway.

---

## 7. Desviaciones conscientes respecto al prompt maestro

| # | El prompt pedía | Se hizo | Por qué |
| --- | --- | --- | --- |
| 1 | Fase 3 completa (3A–3F) | 3A + 3B/RoE + fixes; 3D/3E/3F diferidas (§9) | Autorizado explícitamente; el corte sigue dependencias, no comodidad |
| 2 | `omni roe` (subcomando) | `omni --roe [ACCION]` | El CLI es **argparse por flags** (`main.py`), sin subparsers; añadir un posicional rompería el diseño (`--objective`, selección de engagement). Se propone subcomando real en 3B |
| 3 | "Paralelismo solo read-only" dentro del bucle | `gather_readonly` para fan-out de objetivos read-only | El contrato del parser es 1 acción/turno; paralelizar tools intra-iteración cambiaría el contrato y la semántica de aprobación |
| 4 | "Configurar" la RoE por CLI | `show/path/kill/arm` + API `save_roe()` | Parser de ventanas/rate por CLI es un wizard; se difiere a 3B para no improvisar UX |
| 5 | Inyectar `home` en `update_shell_path` | Inyectar `home` **y** `shell` | El diagnóstico del prompt (home) era incorrecto: la causa real era `$SHELL` (§2) |

---

## 8. Limitaciones honestas (lo que NO se pudo verificar)

1. **Cobertura ≥90% no medida.** `pytest-cov` no está instalado en el venv y no
   se instalaron dependencias. No se afirma cobertura; sí se afirma que cada
   módulo nuevo tiene tests unitarios y que la suite completa pasa
   (**1871 passed, 1 skipped, 0 failed**).
2. **Sin informe de benchmark con/sin subagentes.** El prompt pedía "precisión y
   velocidad con/sin subagentes". Un número honesto requiere corpus de
   objetivos + proveedor LLM real (coste y no determinismo); no se ha fabricado.
   Propuesta de remediación en §9.3.
3. **`mypy` estricto no ejecutado** (no instalado, sin bloque `[tool.mypy]`).
   Verificación usada: `ruff --select F,E9` + `compileall` sobre los ficheros
   nuevos/modificados.
4. **`keyring` no instalado**: el backend de secretos cae a `FileBackend` (ya
   documentado en Fase 2) — no cambia con esta fase.
5. **El paralelismo read-only no está enganchado al flujo de sesión** todavía:
   la utilidad está implementada y testeada; su integración en la orquestación de
   objetivos es trabajo de 3B.

---

## 9. Traspaso a Fase 3B (diferido)

### 9.1 Ecosistema (3D)
- `nexus_core/integrations/mcp/` (stdio + HTTP) **siempre** detrás del gateway;
  todo output pasa por `injection.render_for_model`.
- `.agents/skills/<name>/SKILL.md` con firma HMAC opcional y previsualización;
  contenido también por `render_for_model`.
- `OMNI.md` concatenado al system prompt con procedencia y hash.
- Test clave: un Skill con payload malicioso **no** debe ser obedecido.

### 9.2 Reporte (3E) y headless (3F)
- CVSS 4.0 además de 3.1; mapeo PTES / OWASP WSTG / NIST SP 800-115 / D3FEND;
  export SARIF 2.1.0; enriquecimiento CVE offline-first (NVD/EPSS/KEV con caché);
  exponer la fuente de severidad (`tool`/`llm`/`heuristic`).
- `omni run "<objetivo>" --json` y `--stream-json` (NDJSON de los eventos ya
  existentes: `react.step`, `tool.complete`, `orchestrator.plan`,
  `orchestrator.subagent`).

### 9.3 Benchmark (remedia §8.2)
1. Corpus de N objetivos contra un lab local (dvwa/juice-shop).
2. Dos corridas: catálogo completo vs subagentes.
3. Métricas: tokens, iteraciones, tasa de éxito, tools fuera de fase intentadas.
   El carril `react:<subagent_id>` ya provee el desglose de tokens.

### 9.4 Deuda registrada
- `mypy` estricto y `pytest-cov` en el CI.
- `omni roe set` interactivo (wizard) y/o subcomando real `omni roe`.
- Enganchar `gather_readonly` a la orquestación de objetivos de sesión.

---

## 10. Verificación reproducible

```bash
# Suite completa
.venv/bin/python -m pytest nexus_core/tests/unit -q      # 1871 passed, 1 skipped

# Solo lo nuevo
.venv/bin/python -m pytest nexus_core/tests/unit/test_subagents.py \
    nexus_core/tests/unit/test_subagent_gating.py \
    nexus_core/tests/unit/test_roe.py \
    nexus_core/tests/unit/test_cli_secret_input.py -q

# Estática
.venv/bin/ruff check <ficheros nuevos/modificados> --select F,E9
.venv/bin/python -m compileall -q <ficheros nuevos/modificados>
```

**Fase 3A entregada y verificada. 3B/3D/3E/3F quedan planificadas en §9.**
