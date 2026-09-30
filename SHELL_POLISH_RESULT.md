# SHELL_POLISH_RESULT — Banner + spinner + prompt polish

Rama `feat/shell-polish-core`. Todo aditivo dentro de `nexus_core/cli/` (+ tests
y README). Kernel, scope, agent, tools e integrations **no modificados**.

## Criterios de éxito

| Criterio | Estado | Evidencia |
|---|---|---|
| 6 imports OK | ✅ | `banner`, `spinner`, `session`, `render`, `main`, `omni` |
| 721 tests previos siguen pasando | ✅ | 721 → **790 passed** (69 nuevos, 0 rotos) |
| ≥12 tests del banner | ✅ | `test_cli_banner.py` → **15** |
| ≥10 tests del spinner | ✅ | `test_cli_spinner.py` → **13** |
| ≥8 tests del prompt polish | ✅ | `test_cli_prompt_polish.py` → **10** |
| ≥8 tests de integración REPL | ✅ | `test_cli_banner_integration.py` → **13** |
| ≥6 tests de helpers | ✅ | `test_cli_helpers.py` → **18** |
| ruff clean, cero TODOs | ✅ | `ruff check --select F,E9` → *All checks passed!* |
| Banner solo en modo REPL | ✅ | `_show_banner()` se invoca únicamente en `run_repl()` |
| Banner no en `--help/--version/--doctor/--list-engagements/--objective` | ✅ | 5 casos parametrizados: `run_repl` nunca se llama |
| Banner no con `NEXUS_NO_BANNER=1` | ✅ | 3 variantes (`1`, `true`, `yes`) |
| Banner no si stdout no es TTY | ✅ | demo con stdout redirigido: banner ausente |
| Spinner escribe a stderr, stdout limpio | ✅ | `test_spinner_writes_to_stderr_not_stdout` + demo nmap real |
| Spinner se detiene limpiamente (sin huérfanos) | ✅ | `test_spinner_start_stop_thread_lifecycle` + `test_spinner_handles_keyboard_interrupt` |
| Ctrl+C interrumpe el spinner y propaga | ✅ | `pytest.raises(KeyboardInterrupt)` con `✗` en stderr |
| Prompt con los 4 estados | ✅ | normal / trust / session / ambos |
| `--no-color` desactiva ANSI | ✅ | banner en ASCII, `"\\033[" not in output` |
| Cero subprocess en banner/spinner | ✅ | grep sin coincidencias |
| Ningún handler del kernel modificado | ✅ | `git status` solo toca `nexus_core/cli/`, tests, README |

## Ficheros

| Fichero | Líneas | Contenido |
|---|---|---|
| `nexus_core/cli/banner.py` | 184 | `BANNER_ASCII`, `TIPS` (12), `pick_tip`, `build_banner`, `render_banner` |
| `nexus_core/cli/spinner.py` | 144 | `Spinner`, `spinner_enabled`, frames Unicode/ASCII |
| `nexus_core/cli/session.py` | +~170 | `_show_banner`, `_llm_stats`, `_verify_audit_chain`, `_supports_unicode`, `_describe_tool_call`, `_spinner_enabled`, `_detect_msfrpcd_version`, prompt con color |
| `nexus_core/cli/main.py` | +1 | propaga `--no-color` a `OmniSession(no_color=...)` |
| `nexus_core/tests/unit/test_cli_{banner,spinner,prompt_polish,banner_integration,helpers}.py` | 5 ficheros | 69 tests |
| `README.md` | +~60 | sección **Presentación** |

## Captura real del banner (terminal, `--no-color`)

Generado contra la DB XDG real, engagement `eng-scanme`, msfrpcd vivo:

```text
 ██████╗ ███╗   ███╗███╗   ██╗██╗
██╔═══██╗████╗ ████║████╗  ██║██║
██║   ██║██╔████╔██║██╔██╗ ██║██║
██║   ██║██║╚██╔╝██║██║╚██╗██║██║
╚██████╔╝██║ ╚═╝ ██║██║ ╚████║██║
 ╚═════╝ ╚═╝     ╚═╝╚═╝  ╚═══╝╚═╝
   A G E N T C S   ·   C L I

       =[ OmniAgentCS v3.0.0                                              ]
 + -- --=[ 16 tools · 1 providers · engagement: scanme-lab                ]
 + -- --=[ audit-chain ok · msfrpcd 6.5.3-dev- · groq/openai/gpt-oss-120b ]

 Tip: Use /tools to list all available durable tools.
```

Con color (bytes reales de la línea de auditoría, `ESC[` visible):

```text
 + -- --=[ audit-chain \x1b[32m✓\x1b[0m · msfrpcd 6.5.3-dev- · \x1b[1mgroq/openai/gpt-oss-120b\x1b[0m ]
```

Terminal < 80 columnas (ancho 60): solo el bloque de stats, sin art:

```text
       =[ OmniAgentCS v3.0.0                                      ]
 + -- --=[ 16 tools · 7 providers · engagement: none              ]
 + -- --=[ audit-chain INVALID · msfrpcd n/a · fake/nexus-fake-v1 ]
```

## Captura del spinner durante un nmap real contra scanme

`invoke_tool("nexus.recon.nmap", {"target": "scanme.nmap.org", "flags": ["-Pn","-T4","-p","80,443"]})`
gobernado, con `trust_mode` (auto-aprobación auditada) y TTY simulado.
Wall time 4.2 s, `success=True`, `verification_method=nmap_xml_parsed`,
`raw_xml_sha256=09d45261…45303`.

**stderr** (43 líneas, `cat -v`; `\r\033[K` limpia la línea antes de cada frame):

```text
^M^[[K⠋ Ejecutando nmap contra scanme.nmap.org  [0s]
^M^[[K⠙ Ejecutando nmap contra scanme.nmap.org  [0s]
^M^[[K⠹ Ejecutando nmap contra scanme.nmap.org  [0s]
   …  (40 frames, el contador sube a [4s])
^M^[[K⠋ Ejecutando nmap contra scanme.nmap.org  [4s]
^M^[[K✓ Ejecutando nmap contra scanme.nmap.org  [4s]
```

En un terminal se ve (frames sobreescritos en la misma línea):

```text
⠋ Ejecutando nmap contra scanme.nmap.org  [2s]
✓ Ejecutando nmap contra scanme.nmap.org  [4s]
```

**stdout** en esa misma ejecución: cero frames del spinner. Verificado también
por `test_spinner_writes_to_stderr_not_stdout` (captura separada de `capsys`).

## Prompt: los 4 estados

```text
normal   -> '┌──(OmniAgentCS)─[scanme-lab]\n└─$ '
trust    -> '┌──(OmniAgentCS)─[scanme-lab]─[TRUST MODE]\n└─$ '
session  -> '┌──(OmniAgentCS)─[scanme-lab]─[session a1b2c3d4/meterpreter]\n└─$ '
ambos    -> '┌──(OmniAgentCS)─[scanme-lab]─[TRUST MODE]─[session a1b2c3d4/meterpreter]─[report lab-20260929-143012]\n└─$ '
```

Con color, los códigos van *alrededor* de cada token, de modo que el texto plano
es idéntico al de antes (compatibilidad con los tests de la misión anterior):

```text
'┌──(\x1b[36mOmniAgentCS\x1b[0m)─[\x1b[33mscanme-lab\x1b[0m]\n└─$ '
```

## Demos de no-banner

```console
$ .venv/bin/python omni.py --version
omni 3.0.0                       # sin banner

$ .venv/bin/python omni.py --list-engagements
  eng-scanme               scanme-lab                   cliente=NEXUS  hasta 2030-01-01T00:00:00+00:00
                                 # sin banner

$ printf '/exit\n' | omni.py --engagement eng-scanme --no-wizard
• omni listo · tenant=system · engagement=eng-scanme · /help para comandos
┌──(OmniAgentCS)─[scanme-lab]
└─$ Cerrando sesión omni. La auditoría durable permanece.
                                 # stdout redirigido → sin banner

$ NEXUS_NO_BANNER=1 omni.py --engagement eng-scanme
                                 # sin banner (TTY simulado)
```

## Bugs reales corregidos durante la misión

1. **`render.paint` ignoraba el argumento `no_color`.** `build_banner(no_color=True)`
   devolvía el texto sin códigos, pero `render_banner` los habría reintroducido
   al pasar por `paint` con el estado global en color. Se añadió un envoltorio
   `_paint(..., colored=...)` local al módulo, de modo que el argumento manda
   sobre el estado global.
2. **`LLMFactory.create_from_env()` ensuciaba stdout.** `get_logger("LLMFactory")`
   añade un `StreamHandler(sys.stdout)` y hace `setLevel(INFO)` en cada llamada,
   así que silenciar el logger no sirve. El banner imprimía una línea INFO por
   proveedor antes del art. `_llm_stats()` ahora resuelve por entorno, sin
   construir clientes (0 logs, 0 red, 0 claves usadas).
3. **Doble resolución de proveedores.** `_count_providers()` y `_llm_summary()`
   llamaban cada una a `create_from_env()`. Ahora hay una única pasada
   (`_llm_stats() -> (summary, count)`).

## Decisiones de diseño no cubiertas por el prompt de la misión

1. **El banner no decide en `omni.py`.** El prompt sugería calcular
   `is_repl_mode` en `omni.py`, pero allí no existe ni el engagement ni el LLM
   ni el store. Se implementó en `OmniSession.run_repl()` y se hizo *estructural*:
   los modos no-REPL nunca llegan a ese método, así que no hay bandera que
   mantener sincronizada. `omni.py` no se tocó.
2. **Gate del banner = `stdout.isatty()`, no `stderr`.** Para el banner la
   pregunta es "¿alguien va a ver esto en pantalla?", y el banner va por stdout.
   Para el spinner la pregunta es "¿puedo animar sin ensuciar la salida?", y por
   eso `spinner_enabled()` exige **ambos** TTY (stdout y stderr).
3. **`_stdout_is_tty()` es un helper de módulo, no un método.** Así los tests lo
   mockean con `mock.patch.object(session_module, "_stdout_is_tty", ...)` sin
   instanciar nada y sin depender del terminal real de CI.
4. **El color del prompt va alrededor del token, nunca dentro.** Insertar ANSI
   entre `[` y `TRUST` habría roto los tests existentes
   (`"[TRUST MODE]" in prompt`). Se mantiene el contrato: el token es greppable
   en un transcript pegado.
5. **Truncado del nombre de engagement a 30 caracteres.** El prompt es una línea
   y un nombre largo hacía wrap. El valor anterior no truncaba, pero ningún test
   dependía de ello.
6. **`use_ascii` por `sys.stdout.encoding`.** No se usa `locale` ni
   `PYTHONIOENCODING`: basta con comprobar que el encoding contiene `utf`.
7. **`_describe_tool_call` conoce 4 tools y cae a genérico.** Añadir los 16
   mensajes a mano habría acoplado el CLI al catálogo; las tools con espera real
   (nmap, msf_exploit, session.interact, report.generate) son las que importan.
8. **`--no-color` se propaga a `OmniSession`,** en vez de consultar el estado
   global de `render` desde el banner. El banner sigue funcionando aunque se
   construya antes de `configure_color`, y el flag `--no-color` es explícito.
9. **El spinner también envuelve `run_objective`,** no solo `invoke_tool`: un
   exploit puede consumir 30-120 s en el bucle ReAct completo, que era
   exactamente el caso de uso citado en la misión.
10. **El spinner no se muestra si `--no-color`.** `spinner_enabled()` consulta
    `render.color_enabled()`; los frames `⠋` y el `\033[K` son ANSI, así que en
    modo plano no se emite nada. `NEXUS_NO_SPINNER=1` lo desactiva
    independientemente.
11. **`NEXUS_NO_BANNER` se trata como booleano de presencia** (`os.getenv(...)`
    truthy), igual que `NEXUS_NO_SPINNER`; no se parsea "0"/"false" como falso.

## Verificación ejecutada

```console
$ .venv/bin/python -m pytest nexus_core/tests/unit -q
790 passed in 21.64s

$ .venv/bin/ruff check nexus_core/cli omni.py \
    nexus_core/tests/unit/test_cli_banner.py nexus_core/tests/unit/test_cli_spinner.py \
    nexus_core/tests/unit/test_cli_prompt_polish.py nexus_core/tests/unit/test_cli_banner_integration.py \
    nexus_core/tests/unit/test_cli_helpers.py --select F,E9
All checks passed!

$ grep -rnE "TODO|FIXME|XXX|HACK|raise NotImplementedError" nexus_core/cli/banner.py nexus_core/cli/spinner.py
(ninguna coincidencia)

$ grep -rnE "subprocess|Popen|os\.system|shell=True" nexus_core/cli/banner.py nexus_core/cli/spinner.py
(ninguna coincidencia)
```

## Nota de honestidad sobre las demos interactivas

La misión pedía ejecutar `.venv/bin/python omni.py --engagement eng-scanme` a
mano. **Este entorno no tiene TTY** (`sys.stdout.isatty()` es `False`), así que
ejecutarlo directamente produce salida plana sin banner por diseño — que es
justamente el comportamiento requerido para pipelines. Para capturar el banner y
el spinner reales se mockeó únicamente `_stdout_is_tty` / `spinner_enabled`
(el equivalente a estar en un terminal), manteniendo el resto de la ruta real:
DB XDG, engagement real, `core.version` real de msfrpcd, cadena de auditoría real
y una tool call real de nmap contra `scanme.nmap.org`. Los tests de integración
usan la misma técnica (`mock.patch.object(sys, "stdout", _Tty())`), tal como pedía
el punto 9 de las reglas estrictas.