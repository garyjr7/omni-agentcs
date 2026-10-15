# Auditoría visual de Omni — 2026-09-30

## Alcance

Investigación solicitada antes de continuar B3: ejecutar `omni`, enviar
`/ask que puedes hacer`, reproducir la corrupción visual y comparar criterios
de UX con Freebuff, Claude Code y Codex. No se ha modificado código de producción.
Rama examinada: `feat/tui-live-stream`, commit `824dbc7`.

## Pruebas realizadas

Se ejecutó el launcher instalado `omni` en un pseudoterminal de tmux de
110 columnas por 35 filas, capturado mediante `script`. El launcher apunta a
este repositorio y a su `.venv`; no se estaba ejecutando una instalación vieja.
Se hicieron dos consultas reales `/ask que puedes hacer`. No se ejecutaron
herramientas de reconocimiento ni explotación.

| Prueba | Resultado observado |
| --- | --- |
| `omni`, configuración habitual | Tres logs INFO: creación del cliente, inicio y fin de la consulta. Texto mezclado con el prompt y restos de caracteres en pantalla. |
| `NEXUS_LOG_LEVEL=warning omni` | Cero logs INFO; prompt y status alineados en la captura posterior a la respuesta. Persisten problemas de longitud y Markdown. |
| 70 mensajes sintéticos, logger creado antes de capturar stdout | Cinco filas difieren entre la pantalla que el renderer cree haber dibujado y las celdas reales de tmux. |
| Misma prueba, logger dirigido al stream capturado | Cero filas diferentes: las 35 filas coinciden. |

Las pruebas sintéticas adicionales con texto largo, preámbulo y emojis no
reprodujeron esa corrupción por sí solas. Una comparación tuvo únicamente una
diferencia de un segundo en el reloj entre las dos capturas.

Evidencia local temporal:

- `/tmp/omni-ux-ask.ansi` y `/tmp/omni-ux-ask.timing`: reproducción habitual.
- `/tmp/omni-ux-corrupted.txt`: pantalla dañada.
- `/tmp/omni-ux-warning.ansi`, `/tmp/omni-ux-warning.timing` y
  `/tmp/omni-ux-warning-clean.txt`: control con nivel warning.
- `/tmp/omni_ux_probe.py`: prueba sintética reproducible.
- `/tmp/omni-ux-logger-{actual,expected}.txt` y
  `/tmp/omni-ux-logger-routed-{actual,expected}.txt`: comparación de celdas.

Estos archivos de `/tmp` no son artefactos permanentes del repositorio.
La comprobación es sobre un PTY de tmux, no una inspección del emulador gráfico
del operador. No demuestra compatibilidad con todos los terminales.

## Causa confirmada de la corrupción

`NexusLogger` conserva un `logging.StreamHandler(sys.stdout)` creado antes de
entrar en el REPL (`nexus_core/utils/logger.py:84`).
`capture_output()` sustituye `sys.stdout` y `sys.stderr`
(`nexus_core/cli/tui/output.py:64`), pero no sustituye las referencias ya
almacenadas en esos handlers. Sus logs siguen escribiendo al terminal físico.
Esto mueve el cursor sin actualizar el estado del renderer de prompt_toolkit:
el siguiente dibujo diferencial parte de coordenadas incorrectas.

El `.env` del proyecto contiene `NEXUS_LOG_LEVEL=info`. `omni.py` configura
logging antes y después de cargar ese archivo, por lo que el INFO de arranque
no se explica simplemente por llamar tarde a `configure_logging()`.
La validación anterior con nivel warning no cubría esta configuración real.

El control sintético confirma el mecanismo: cambiar únicamente el destino
del handler elimina las discrepancias. Cambiar colores, borrar la pantalla o
reducir redibujados no resuelve ese bypass.

Mitigación comprobada: `NEXUS_LOG_LEVEL=warning omni`. No es una reparación
completa: un warning/error emitido por el mismo handler también puede saltarse
la TUI.

## Otros problemas observados

1. **Contexto de producto insuficiente.** `ASK_SYSTEM_PROMPT` en
   `nexus_core/cli/commands.py:25` describe un asesor de ciberseguridad genérico.
   No incorpora el catálogo efectivo de comandos y capacidades de esta CLI.
   Una pregunta de bienvenida produjo una explicación extensa, en vez de una
   ayuda breve para usar Omni. Esto es independiente del fallo del renderer.
2. **Markdown incompleto.** El renderer implementa un subconjunto mediante
   expresiones regulares. La segunda respuesta mostró `<br>` literal dentro
   de tablas, muchas filas y párrafos cortados por el ancho del terminal.
3. **Jerarquía visual.** Banner grande, respuestas largas y resultados ocupan
   el mismo flujo. Conviene diferenciar turnos, actividad, resultados y errores,
   con detalles expandibles y una cabecera compacta.
4. **Validación visual insuficiente.** `DummyOutput` no reproduce las celdas y
   el movimiento del cursor de un terminal. Reducir bytes ANSI o redibujados
   tampoco demuestra que el contenido final esté correctamente colocado.
5. **Aspectos que requieren medición adicional.** El intervalo mínimo global
   de redibujo de 250 ms puede afectar la sensación al escribir; no se midió
   latencia de teclado. El historial se mantiene en varias representaciones
   en memoria y requiere pruebas de conversaciones largas.

## Comparación con fuentes primarias

- **Freebuff:** su [manifiesto oficial](https://github.com/CodebuffAI/freebuff/blob/main/cli/package.json)
  declara OpenTUI/React, remark-parse/remark-gfm, string-width, yoga-layout y una
  prueba tmux. Esto acredita componentes y herramientas para layout, Markdown,
  ancho visual y pruebas; no demuestra por sí solo ausencia de fallos visuales.
- **Claude Code:** su [documentación de fullscreen](https://code.claude.com/docs/en/fullscreen)
  describe una vía de renderizado en pantalla alternativa, mensajes visibles
  en el árbol de render, input fijo, resultados expandibles y navegación del
  transcript. Está documentada como research preview y convive con el renderer
  clásico. No existe una regla universal de usar siempre modo inline.
- **Codex:** la [documentación de la CLI](https://learn.chatgpt.com/docs/codex/cli)
  y de [personalización](https://learn.chatgpt.com/docs/cli-customization)
  documenta interacción, comandos, temas, resaltado de bloques de código/diffs
  y editor externo para prompts largos. El `codex --help` instalado también
  describe `--no-alt-screen` como modo inline que conserva el scrollback.

Se investigaron código/manifiestos y documentación oficial. No se realizó
una prueba interactiva comparativa completa de los tres productos.

## Trabajo recomendado, en orden

1. **Integridad del terminal:** un único propietario de la pantalla. Integrar
   handlers existentes y nuevos con el router, o dirigir diagnósticos a un
   archivo; restaurar handlers al cerrar. Mantener warnings/errores visibles
   mediante la interfaz, sin escrituras fuera del renderer. Puede hacerse
   desde la capa CLI sin cambiar kernel o integraciones.
2. **Regresión real en PTY:** probar INFO/WARNING/ERROR antes y durante `/ask`,
   mensajes desde hilos, respuesta larga, resize, colores y fallback.
   Comparar celdas reales con el resultado esperado, además de medir redibujados.
3. **Ayuda ajustada al producto:** generar contexto a partir de comandos y tools
   registrados; bienvenida breve, ejemplos ejecutables y distinción clara
   entre `/ask` informativo y objetivos que pueden ejecutar herramientas.
4. **Presentación:** ancho de lectura, Markdown estructurado, tablas adaptables,
   mensajes diferenciados y resultados plegables. Elegir explícitamente cómo
   deben funcionar scroll, selección y copia antes de cambiar el modo de pantalla.
5. **Fluidez:** separar frecuencia de actualización de logs/busy de la respuesta
   al teclado; medir latencia y memoria. Renderizar la porción visible del
   historial y persistir el transcript según lo requieran esas mediciones.

Mantener prompt_toolkit es una opción viable; estos hallazgos no justifican
por sí solos una migración de lenguaje o framework. Primero debe corregirse y
verificarse la frontera de escritura del terminal.

## Estado de entrega

Diagnóstico y comparación completados. Código funcional sin cambios, sesiones
de prueba cerradas. No se ejecutó nuevamente la suite completa porque no se
modificó implementación; los resultados de la misión anterior no se presentan
como validación nueva. No se creó commit ni se hizo push en esta investigación.
