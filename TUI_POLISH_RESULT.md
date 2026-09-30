# Resultado B2 — polish de la TUI

Rama: `feat/tui-polish`. Base: `5630acc`. Sin push.

## Implementado

- Coste desconocido: `$—` desde el arranque y tras consumir tokens sin tarifas.
  Las estimaciones configuradas se conservan; no se añadió una tabla de precios.
- `OmniCompleter`: comandos con ayuda, tools y argumentos del catálogo real,
  engagements `@`, rutas y rutas entre comillas. Tab completa una coincidencia;
  si hay varias, abre el menú y permite recorrerlo. El menú flota sobre el panel
  completo para evitar recortes junto al prompt inferior.
- Markdown en `/ask` y vista previa de `/report` en TUI, sin dependencias nuevas:
  encabezados, énfasis, listas, enlaces, código y tablas ASCII.
- Alt+Enter inserta una línea; Enter envía. Altura dinámica y continuación `·`.
- Lexer de comandos, tools, argumentos, cadenas y rutas; respeta `--no-color`.
- `/exploit view-live UUID` (alias `watch`): vista independiente de estado y
  resultados MSF, con polling cada dos segundos. Prioridad tmux, después terminal
  gráfico; sin terminal secundario presenta una instantánea. Valida UUID,
  engagement y consulta antes de lanzar procesos. Usa argv, nunca shell=True.
- README y `.env.example` actualizados. Fallback readline conserva su entrada
  y presentación; incorpora el nuevo comando sin abrir ventanas desde pipes.

No se modificaron kernel, scope, agent, tools, integrations ni provisioner.

## Verificación final

```text
NO_COLOR=1 .venv/bin/python -m pytest nexus_core/tests -q
990 passed, 18 skipped in 79.27s (0:01:19)

env -u NO_COLOR .venv/bin/python -m pytest nexus_core/tests -q
990 passed, 18 skipped in 83.77s (0:01:23)

Tests nuevos: 65 passed in 3.25s
Ruff --select F,E9: All checks passed!
git diff --check: limpio
TODO/FIXME/XXX/HACK/NotImplementedError en tui y live_jobs: sin coincidencias
```

Los 925 casos anteriores siguen pasando en ambas configuraciones. Dos asserts
existentes se adaptaron al placeholder `$—` y al contenedor raíz del menú.
Los 18 casos omitidos no se contabilizan como éxitos.

| Archivo nuevo | Casos que pasan |
| --- | ---: |
| test_tui_completion.py | 19 |
| test_tui_markdown.py | 14 |
| test_tui_multiline.py | 4 |
| test_cli_view_live.py | 18 |
| test_tui_lexer.py | 7 |
| test_tui_cost.py | 3 |

Se usan `create_pipe_input()` y `DummyOutput` en los flujos de interfaz, con
sincronización mediante eventos. RPC y procesos de view-live se simulan:
prioridad tmux, terminal gráfico, fallback, denegación, job ausente, formato
inválido, consulta de solo lectura y finalización del watcher.

Seis imports verificados: `nexus_core.cli.tui.completion`, `.markdown`, `.lexer`,
`nexus_core.cli.commands`, `nexus_core.cli.session` y `omni`.

## Comprobación visual en PTY

Se ejecutó la CLI real dentro de tmux a 120×35, con `TERM=xterm-256color`,
`NEXUS_LOG_LEVEL=warning` y sin `NO_COLOR`. Capturas textuales mediante
`tmux capture-pane`, además del registro ANSI de `script`.

Observado: banner una vez, sin logs INFO antes del banner, prompt inferior,
barra con modelo y `$—`, `/he<TAB>` convertido en `/help`. El menú de tools
muestra las tres entradas completas sobre el prompt:

```text
                 nexus.recon.httpx
                 nexus.recon.nmap
                 nexus.recon.subfinder
┌──(OmniAgentCS)─[scanme-lab]
└─$ nexus.recon.
scanme-lab · groq/openai/gpt-oss-120b · 0 tok · $— · 6m50s
```

Alt+Enter, sin ejecutar el objetivo:

```text
┌──(OmniAgentCS)─[scanme-lab]
└─$ primera linea
  · segunda linea
scanme-lab · groq/openai/gpt-oss-120b · 0 tok · $— · 2m18s
```

Markdown se comprobó en otra PTY con una respuesta local simulada, sin llamar
a un proveedor ni ejecutar herramientas. Se visualizaron encabezado, énfasis,
bullets, tabla con bordes y bloque de código sobre el prompt fijo:

```text
  Respuesta de demostración
  Negrita y cursiva, código.
    • Primer elemento
    • Segundo elemento
  +------+------------+
  | Tool | Estado     |
  +------+------------+
  | nmap | disponible |
  +------+------------+
    ----------------------------------------
    print("Hola")
    ----------------------------------------
```

Las capturas de texto no preservan el color; los estilos ANSI y su desactivación
se verifican en tests. No se comprobó un job MSF real ni una ventana gráfica:
los lanzamientos y respuestas RPC se verificaron con dobles deterministas.
Para la validación operativa restante: con un job autorizado existente,
ejecutar `/exploit view-live <uuid>` dentro de tmux; comprobar actualización,
independencia del panel del agente y cierre con Ctrl+C.

Evidencias locales: `/tmp/tui-polish-final-completion.txt`,
`/tmp/tui-polish-final-tools.txt`, `/tmp/tui-polish-multiline.txt`,
`/tmp/tui-polish-markdown.txt`, `/tmp/tui-polish-final-terminal.raw`.
Logs completos de tests: `/tmp/tui-polish-color-tests.txt`,
`/tmp/tui-polish-no-color-tests.txt`, `/tmp/tui-polish-new.txt`.

## Demo fallback

```bash
printf '/help\n/status\n/exit\n' | env NEXUS_LOG_LEVEL=warning NO_COLOR=1 \
  .venv/bin/python omni.py --engagement eng-scanme --no-wizard
```

Salida comprobada, extracto (el log completo enumera todos los comandos):

```text
• omni listo · tenant=system · engagement=eng-scanme · /help para comandos
┌──(OmniAgentCS)─[scanme-lab]
└─$ Comandos disponibles:
  /exploit     /exploit view-live <job_uuid>: vista de estado MSF en otra terminal (solo lectura).
  /help        Muestra esta ayuda.
  /status      /status [on|off|show]: muestra u oculta la barra (preferencia persistente).
┌──(OmniAgentCS)─[scanme-lab]
└─$ status bar: ON (fallback readline)
┌──(OmniAgentCS)─[scanme-lab]
└─$ Cerrando sesión omni. La auditoría durable permanece.
• sesión terminada
```

Sin banner, sin ANSI, salida normal. Log: `/tmp/tui-polish-fallback.txt`.
Una prueba adicional rechazó `invalid;uuid` sin lanzar procesos.

## Decisiones y límites

- Renderer de subconjunto Markdown propio, sin Rich ni CommonMark completo.
  La vista de reportes se limita a 65 536 caracteres; el artefacto queda intacto.
- View-live usa `module.results`, no stdout/stderr crudos: la API existente no
  expone un stream de consola por job. No se alteran handlers ni se generan logs
  artificiales. La opción de watcher de estado estaba autorizada en la misión.
- El historial mantiene el formato readline: saltos de línea se guardan como
  espacios. La entrada enviada al agente conserva los saltos originales.
- Completar `nexus.*` o `@nombre` solo inserta texto; no cambia el despacho de
  objetivos ni el engagement. No se añadió detección conversacional automática.
- Una primera corrida quedó interrumpida por disco lleno (Errno 28), no fue
  considerada válida. Con autorización se vació solo la caché regenerable Go
  (~2,2 GB); las dos corridas finales se completaron después sin fallos.

El commit de esta entrega se identifica con `git log --oneline -3`; el hash
final se reporta en la respuesta para evitar autorreferencia dentro del commit.
