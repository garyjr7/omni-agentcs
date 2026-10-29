# STABILITY_FIXES_V2 — run Hijack V1 (2026-10-29)

Cuatro arreglos de código, sin bloqueos por fase y sin tocar la gobernanza. Cada
uno ataca un *dead end* medido en el run `run_199aa986a3b24d89aa15f60cb56bc70f`
(38 iteraciones, 498 k de 1,5 M tokens, `exit_code=4`).

El diagnóstico externo pedía "enjaular al LLM" con una máquina de estados. El
run no murió por falta de metodología: murió porque **una aprobación recién
creada fue rechazada**, porque **un 200 con el formulario de login se reportó
como navegación exitosa** y porque **un `mount` fallido se reportó como éxito**.
El agente ya tenía la metodología; lo que mentía era el código.

---

## 1 · Trust mode: la aprobación se registraba para otra acción

**Qué pasaba.** `nexus.system.install_tool` no se aprueba como
`execute:tool:<id>` sino **por plan exacto**:
`execute:tool:nexus.system.install_tool:<sha256>` (`kernel/tool_gateway.py`,
`provisioner/installer.py:approval_action`). La rama interactiva de
`cli/approval.py` reescribía la acción; la rama `trust_mode` **retornaba antes**
(`_trust_authorization`), así que la fila durable quedaba con la acción corta.

Resultado medido: iteración 38, `approval_79e2f686…` creada y decidida en la
misma llamada, consumida una línea después → `PermissionError: approval is
invalid or already used`. No era reutilización: era la **primera** invocación.

**Arreglo.** `_exact_action()` en `cli/approval.py` calcula la acción que el
gateway va a consumir, y **ambas** ramas la usan (la interactiva, además,
imprime el plan). La aprobación sigue siendo de un solo uso: el arreglo es la
cadena de acción, no un permiso reutilizable (`test_trust_mode_does_not_weaken_the_single_use_rule`).

## 2 · Un `governance_denial` ya no cierra el run

**Qué pasaba.** En `agent/react_coordinator.py`, la ruta de llamada suelta
trataba cualquier `PermissionError` como terminal: `status="governance_denial"`
y `Transition.STOP`. En la ruta de *batch* el mismo error era local a la llamada
y el batch continuaba. Esa asimetría convirtió un desajuste de aprobación en el
final de un run con credencial verificada en el tablero, 82 iteraciones y 1 M
tokens sin usar.

**Arreglo.** `ApprovalRequired` sigue parando (nadie puede aprobar en
unattended → `blocked`). Cualquier otra denegación del gateway:

- se registra como **observación del turno** (`_record_governance_denial`) con
  guía explícita ("no la repitas: elige otra acción, otros argumentos o
  pivota");
- cuenta como fallo y marca `FrictionFlag.GOVERNANCE_DENIAL`;
- el run sigue (`Transition.READY`) y solo se cierra si el modelo **insiste**
  `MAX_CONSECUTIVE_GOVERNANCE_DENIALS = 3` veces seguidas. El `exit_code=4`
  sigue existiendo para el caso real de insistencia.

## 3 · `nexus.web.request`: la sesión que no autentica

**Qué pasaba.** `_store_session` guardaba la cookie de **cualquier** respuesta
2xx y el resultado se marcaba `verified=True` con
`verification_method="http_response_received"`. Un `200` con `login.php` era,
para el agente, un panel. Iteraciones 18-35: los mismos 3 843 bytes leídos como
"estoy dentro", con `session_ref` rotando (`vault:c981…` → `vault:751e…`) y
siete turnos de SQLi manual después de tener la credencial.

**Arreglo.** Si la petición llevó `session_ref` y el cuerpo sigue teniendo
`<input type="password">`, el resultado es:

- `outcome="partial"`, `verified=False`,
  `verification_method="http_session_not_authenticated"`;
- `output["session_state"] = "not_authenticated"` + guía que dice qué hacer
  (repetir el login, `csrf_mode=true`, y si sigue igual, cambiar de vector);
- **no se guarda** la cookie de ese login fallido (no envenena el vault).

La comprobación es sobre *nuestra* sesión: pedir `/login.php` sin `session_ref`
sigue siendo una respuesta normal (`test_a_login_page_without_a_session_stays_a_normal_response`).

## 4 · `mount -t nfs` sin root: fallo de entorno, no éxito

**Qué pasaba.** El comando medido era
`mkdir … && (mount -t nfs … 2>&1 || mount …); ls -laR /tmp/nfsmnt` — el estado
de salida lo daba `ls`, así que el handler devolvía `outcome="success"` con el
`failed to apply fstab options` escondido en la salida. El agente reintentó el
montaje cuatro veces y luego pidió `nfs-common`, que no da privilegios.
`nexus.recon.nfs` **ya no monta nada** (`showmount`/`nfs-ls`/`nfs-cat`): el
problema era que rodear la tool salía gratis.

**Arreglo.** `mount_requires_root()` en `tools/handlers/shell_exec_local.py`,
con el mismo patrón que `apt_install_permission_denied`:

- dispara solo si un segmento **local** del comando es `mount`/`mount.<fs>` y
  menciona `nfs`, y la salida trae una marca de privilegios
  (`failed to apply fstab options`, `must be superuser`, `permission denied`…);
- devuelve `outcome="unavailable"`, `verification_method="mount_requires_root"`
  y una guía que nombra la alternativa sin root (`nexus.recon.nfs`) y prohíbe
  reinstalar `nfs-common`;
- un `mount` remoto por `ssh` o de otro sistema de ficheros conserva su
  resultado normal (el clasificador está atado al comando, no a la frase).

## 5 · Sincronización del prompt

`agent/prompts.py` afirmaba dos cosas que el motor ya no hace:

- **"SUBAGENTE ACTIVO: … solo puedes invocar tools de ESE subconjunto"** se
  enviaba también con el perfil `omni` (`unrestricted: true`, 83 tools). Ahora
  la regla se elige por perfil: `UNRESTRICTED_SCOPE_RULE_PROMPT` dice que todo
  el catálogo está disponible y que el gateway sigue gobernando cada llamada.
  El texto restringido se mantiene para `NEXUS_LEGACY_PROFILES=1`.
- **"si falta el BINARIO, instálalo"** empujaba a `install_tool` justo cuando el
  muro era de privilegios. Ahora: primero alternativa dentro del catálogo,
  instalación solo como último recurso, y "un fallo por falta de privilegios no
  se arregla instalando". La regla solo se renderiza si el catálogo ofrece
  `nexus.system.install_tool`.

---

## Por qué esto basta sin *tool gating*

El gating por fase existió y se retiró en WP2 (`subagents.py:legacy_profiles`,
`test_wp2_loop_v2.py::test_legacy_flag_restores_the_phase_tool_gate`): cerraba
fases, producía `premature_completion` y negaba tools que la fase siguiente
necesitaba. Además habría bloqueado `nexus.cred.bruteforce` en enumeración,
que es exactamente lo que `LOGIN_RULE_PROMPT` **obliga** a usar en un login web,
y habría denegado la credencial que ganó en la iteración 17 de este run.

El patrón que sí funciona ya está en el motor y se ha reutilizado:

| Mecanismo | Dónde | Qué hace aquí |
|---|---|---|
| Withholding | `LOGIN_PROBE_WITHHELD_TOOLS`, `react_coordinator._refresh_login_hint` | retira tools ruidosas mientras falta una sonda |
| Observación correctiva | `_record_governance_denial`, `_correct_repeated_action` | el modelo lee *qué* falló y elige otra cosa |
| Clasificador de entorno | `apt_install_permission_denied`, `mount_requires_root` | un muro del sandbox se nombra una vez, no se reintenta |
| Preflight | `agent/preflight.py` | retira tools sin binario/módulo al arrancar |
| Degradación por estancamiento | `stuck_detected`, `branch_closed`, `coverage_pivot` | pivota la rama, no el run |

Con esto el LLM conserva el libre albedrío táctico (puede saltar de fase, usar
SSH cuando el web falla) y el backend deja de mentirle con `success` donde hubo
un rechazo.

## Verificación

- 13 tests nuevos en `nexus_core/tests/unit/test_stability_v2_fixes.py`
  (uno por contrato: plan exacto en trust mode, denegación no terminal,
  denegación insistida terminal, sesión no autenticada, no envenenar el vault,
  login sin sesión intacto, mount NFS sin root, `mount` no-NFS/remoto intacto,
  prompt unrestricted/restricted, regla de instalación ausente sin la tool).
- Suites afectadas: `test_approval_consumed`, `test_system_install_handler`,
  `test_http_request_handler`, `test_shell_exec_local`,
  `test_subagent_gating`, `test_deny_and_failure_causes`,
  `test_react_degradation`, `test_wp2_loop_v2`, `test_headless_exit_codes`,
  `test_headless_ndjson` → **207 passed**.
- Suite unitaria completa: **4 323 passed, 9 skipped, 2 failed**. Los 2 fallos
  son los de siempre de `test_bench_runner` (`config.toml` sin
  `scope.signing_secret`; fallan igual sin estos cambios). Las cuatro
  aserciones de tamaño de `test_prompt_optimization` se recalibraron con la
  medida real (33 821 / 34 448 / 8 272 / 10 624) y su comentario, como hace el
  resto del fichero: el límite sigue acotando el crecimiento, solo que ahora
  incluye las dos órdenes nuevas.
- `ruff --select F,E9` limpio en todo `nexus_core` y `mypy` limpio en los seis
  ficheros tocados.

## Qué NO se ha tocado

- `kernel/approvals.py` y el consumo atómico: la aprobación sigue siendo de un
  solo uso (propiedad de seguridad con tests propios).
- `tools/handlers/nfs.py`: ya no monta; su contrato (`exports`/`list`/`read`) es
  el que el arreglo 4 recomienda.
- El modelo de fases y `NEXUS_LEGACY_PROFILES`.
- `_payload_key` del planner (la sonda de login que compara la contraseña
  literal) sigue pendiente: es un dead end distinto, ya documentado en la
  auditoría.
