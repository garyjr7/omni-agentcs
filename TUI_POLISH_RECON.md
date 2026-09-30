# Reconocimiento B2

Base: `5630acc`. Rama: `feat/tui-polish`. Árbol limpio al comenzar.

- `tui/session.py` mantiene PromptSession y su Application en un hilo; un
  panel superior recibe las salidas y la entrada/barra quedan abajo.
  El completer actual es WordCompleter de nombres de comandos, sin metadatos.
  El input es single-line y la altura del contenedor es fija.
- `commands.COMMANDS` y `durable_tool_definitions(tenant)` permiten construir
  un catálogo local de completado, sin ejecutar herramientas. Las propiedades
  del input_schema dan los argumentos reales. `main` ya lista engagements.
- `render.render_answer` presenta texto sin Markdown. `/report` genera los
  artefactos mediante el gateway y muestra un resumen; la CLI puede leer el
  Markdown generado para previsualizarlo sin cambiar report ni tools.
- Coste: el código usa `~$0.0000` o `$n/d`, no el literal `$0/0`. El estado
  inicial se marca conocido antes de tener consumo. Se cambiará a `$—` cuando
  sea desconocido, incluido el arranque; se conservarán estimaciones válidas.
- `MetasploitClient.get_module_results(uuid)` consulta `module.results` y
  devuelve un dict con status. No hay un stream de stdout del job en esta
  API. Los handlers no imprimen un log de consola que pueda duplicarse.
  Se elige una vista de estado/resultado JSON con polling, sin crear jobs,
  ejecutar módulos, intervenir sesiones ni modificar integraciones.
- `/exploit view-live UUID` comprobará formato, engagement y respuesta RPC
  antes de abrir un proceso; tmux tiene prioridad, después terminal gráfico,
  y finalmente snapshot. El watcher no recibe secretos por argumentos.
- Los cambios visuales de Markdown se limitan a TUI: fallback conserva la
  presentación previa. El renderer implementará un subconjunto documentado
  sin dependencias nuevas: títulos, énfasis, links, listas, código y tablas.
- Alt+Enter añadirá newline; Enter enviará. La altura crecerá con el contenido
  hasta un límite para no ocultar el panel. No se cambia la interpretación
  de objetivos ni se redirige conversación automáticamente hacia `/ask`.

Pruebas: completer y lexer contra Documents deterministas; flujos reales con
create_pipe_input/DummyOutput; RPC/procesos secundarios simulados, sin
explotación ni red externa. Mantener los 925 casos previos en ambos entornos.

Referencias primarias consultadas:
[prompt_toolkit](https://python-prompt-toolkit.readthedocs.io/en/stable/pages/asking_for_input.html),
[Rich Markdown](https://rich.readthedocs.io/en/stable/markdown.html).
