# B3 — regiones, indicador de trabajo y stream compacto

Rama `feat/tui-live-stream`, base `ac844a9`. Sin nuevas dependencias.
No se modificaron kernel, scope, agent, tools, integrations ni provisioner.

## Arquitectura entregada

`TuiSession` mantiene su fachada síncrona y un hilo de interfaz, pero construye
directamente una Application y un Layout con cuatro regiones independientes:

1. Buffer de salida de solo lectura, sin límite de líneas en memoria.
2. Working de una línea, colapsado en reposo.
3. Input con historial, lexer, autocompletado y hasta cinco líneas editables.
4. Status de una línea al fondo, ocultable con `/status off`.

`full_screen=False`; no hay cambio a la pantalla alternativa ni borrado de
pantalla al entrar al REPL. El banner tiene un único destino. El menú de
completado sigue flotando sobre las regiones. PageUp/PageDown recorren el
buffer y pausan/reanudan el seguimiento automático.

Las escrituras, también desde el daemon, se agrupan durante 50 ms y se
despachan al loop de la UI. BufferControl observa los cambios del documento:
no se invalida explícitamente por cada write ni se suspende el renderizador.
El buffer almacena texto plano; los estilos se interpretan al añadir cada
lote y se conservan por línea. El renderizador aplica las diferencias entre
frames. Un límite de 250 ms agrupa redibujados durante la actividad.

El refresco rápido de Working usa 250 ms; en reposo se desactiva y queda un
tick de 2 s para el reloj de sesión. Se sustituye la captura anterior de
stdout/stderr por un adaptador que alimenta el buffer, sin salida externa.

Esc comunica una señal al loop de trabajo; este registra una sola solicitud
`react.cancel_requested` por operación. ReAct conserva su cancelación
cooperativa existente: las tools en curso pueden terminar antes de alcanzar
el punto seguro. `/ask` e invocaciones directas cancelan su tarea asyncio.
Ctrl+C conserva la semántica previa; Ctrl+D sale con el prompt vacío.

## Medición antes/después

Método idéntico: PTY tmux 120×35, `script -T ... -O ...`, contadores con
timestamps monotonic y 60 llamadas a print separadas por 100 ms. Se mantienen
todos los writes; la reducción no consiste en descartar output.

| Métrica de carga controlada | Antes | Después verificado | Cambio |
| --- | ---: | ---: | ---: |
| Writes | 60 | 60 | iguales |
| Invalidaciones explícitas de TuiSession | 122 | 2 | −98,4 % |
| Solicitudes Application.invalidate | 186 | 146 | −21,5 % |
| Frames renderizados | 127 | 27 | −78,7 % |
| Pico frames por segundo | 22 | 5 | −77,3 % |
| Bytes del registro ANSI | 81212 | 11775 | −85,5 % |
| Movimientos de cursor arriba | 219 | 34 | −84,5 % |
| ESC[2J / ESC[H | 0 / 0 | 0 / 0 | sin borrados |

El pico de 5 incluye transición inicial/final; la actividad regular se limita
a cuatro frames/s. Las solicitudes internas de invalidación no equivalen a
frames: los eventos del Buffer y del reloj se agrupan por la Application.
No se afirma que solo se evalúe una región: PTK compara el layout y emite las
diferencias. Se eliminó la suspensión/restauración de pantalla por cada write.
La captura ANSI mide ese mecanismo y su reducción; no es una evaluación
perceptual en todos los emuladores de terminal.

Registros comparables: `/tmp/tui-b3-bench-before.{json,timing,ansi}` y
`/tmp/tui-b3-bench-verified.{json,timing,ansi}`. Se confirmó también con una
corrida intermedia: 27 renders y 11775 bytes. Duraciones totales de captura
9,30 s y 11,17 s, incluyendo arranque y salida; el trabajo emitido es el mismo.
Instrumentación temporal: `/tmp/tui_b3_bench.py`; análisis por segundo:
`/tmp/tui_b3_analyze.py`. El reconocimiento previo está en `TUI_B3_RECON.md`.

El run real final tiene 21 prints (pico 11/s), 13 invalidaciones explícitas
(pico 5/s), 892 solicitudes internas (pico 586/s, incluye la entrada pegada),
0 ESC[2J, 0 ESC[H, 315 movimientos arriba (pico 6/s) y 26621 bytes durante
195,77 s de captura. La duración incluye espera ociosa; por eso la comparación
cuantitativa principal usa la carga fija, no dos respuestas LLM distintas.

## Captura textual: nmap real durante el run

Se ejecutó el objetivo autorizado de reconocimiento TCP connect a
`scanme.nmap.org`, solo puertos 22,80,443, sin scripts NSE. Gateway, scope y
auditoría permanecieron activos. Run final:
`run_994efb4daf85489bba0f914e7753c586`, completed, dos iteraciones.

Extracto de `/tmp/tui-b3-working-nmap.txt`, capturado automáticamente en tmux
mientras el modelo preparaba el resumen después de la ejecución real de nmap:

```text
⚙️   [Recon-NMAP] nmap -sT -p 22,80,443 -oX - scanme.nmap.org
   -> Host up: 45.33.32.156
   ...
   -> Puerto 443/tcp filtered: https
   -> Nmap done: 1 host(s) up · 1.85s
   ✓ 2 puertos abiertos · 1 hosts up · noise: high · 1.85s

 ⠹ Working... (29s · esc to interrupt)
┌──(OmniAgentCS)─[scanme-lab]
└─$
scanme-lab · groq/openai/gpt-oss-120b · 6.3k tok · $— · 37s
```

Al terminar se oculta Working y la barra registra 13,3k tokens. El banner
apareció una vez, sin logs INFO previos. ANSI y timestamps del run completo:
`/tmp/tui-b3-final.{ansi,timing,json}`; captura final:
`/tmp/tui-b3-final-result.txt`. No se simuló el resultado de nmap.

## Verificación

```text
NO_COLOR=1 .venv/bin/python -m pytest nexus_core/tests -q -o faulthandler_timeout=20
1041 passed, 18 skipped in 44.25s

env -u NO_COLOR .venv/bin/python -m pytest nexus_core/tests -q -o faulthandler_timeout=20
1041 passed, 18 skipped in 43.99s

Tests nuevos solicitados (-v): 51 passed in 5.75s
Ruff --select F,E9: All checks passed!
git diff --check: limpio
```

Los 990 casos anteriores y los 51 nuevos pasan en ambos modos; los 18 omitidos
no se cuentan como aprobados. `faulthandler_timeout` solo añade diagnóstico
de hilos si un test tarda más de 20 s; no altera los asserts ni omite tests.
Logs completos: `/tmp/tui-b3-color.txt`, `/tmp/tui-b3-no-color.txt` y
`/tmp/tui-b3-new.txt`.

Cinco imports comprobados: `nexus_core.cli.tui.session`, `.stream`, `.layout`,
`nexus_core.cli.session` y `omni`. Ruff F/E9 y git diff --check limpios.
Cero referencias a la primitiva de suspensión de terminal en el código CLI;
cero TODO/FIXME/XXX/HACK/NotImplementedError en los módulos TUI.

Cobertura nueva: truncado (11), prefijos (6), stream (10), busy (11),
regresión de redibujado (5), layout (8): 51 casos. Incluye pipes y DummyOutput,
historia de más de 2000 líneas, 1000 writes en ráfaga, límites de frames,
captura del daemon, cancelación mediante Escape y conservación de typeahead.

Los asserts antiguos sobre pantalla completa, estructura del contenedor,
ruta de escritura y orden del borrado inicial se adaptaron a los requisitos B3;
se conservan sus comprobaciones de salida, orden del banner y funcionamiento.
Una corrida intermedia pasó 1037 tests. Las corridas posteriores detectaron
una carrera entre typeahead y la siguiente llamada a prompt, y un assert de
tiempo demasiado estricto sobre el final de cada frame. Se corrigieron antes
de la verificación final: typeahead se conserva en reposo y se mide el inicio
del frame, que es donde PTK aplica el límite. No se cuentan corridas fallidas
ni interrumpidas como aprobadas.

Demo fallback, salida completa en `/tmp/tui-b3-fallback.txt`:

```text
• omni listo · tenant=system · engagement=eng-scanme · /help para comandos
└─$ Comandos disponibles:
  /help        Muestra esta ayuda.
  /status      /status [on|off|show]: muestra u oculta la barra (preferencia persistente).
  ... (resto del catálogo)
└─$ status bar: ON (fallback readline)
└─$ Cerrando sesión omni. La auditoría durable permanece.
• sesión terminada
```

El pipe `/help`, `/status`, `/exit` termina normalmente, sin banner ni ANSI.
No cambia la representación de eventos en fallback.

## Decisiones y límites

- El prompt proponía eventos tool.complete; el repositorio entrega los datos
  reales mediante mensajes durables react.action/observation. Se renderizan
  estos mensajes una vez. También se admiten eventos completos para clientes
  que ya entreguen argumentos y resultados en sus payloads.
- Truncado: hasta tres líneas de datos, más un solo marcador de omisión;
  respeta primera + últimas dos, como piden los ejemplos/test cases.
- Nmap: se muestran datos normalizados de su scan, no stdout inventado.
  El argv incluye `-oX -`, que añade el handler existente. Otras tools muestran
  su solicitud durable cuando no se puede reconstruir su comando exacto.
- No se añadió streaming de tokens ni lectura del stdout en ejecución: el
  contrato actual entrega resultados al terminar cada herramienta.
- Se conserva toda la salida mostrada en el buffer, navegable con PageUp y
  PageDown. full_screen=False preserva la pantalla principal, pero no duplica
  la historia completa de ese buffer en el scrollback nativo del terminal.
- `/timeline` es auditoría y `/ask` no ejecuta comandos; el README corrige esa
  indicación del ejemplo solicitado.
- Las comprobaciones de Escape y cancelación son deterministas con pipe input
  y operaciones controladas. No se interrumpió una explotación real.
- La nueva Application mantiene una fachada interna `_session` para los
  renderers existentes; ya no construye un PromptSession.

El hash del commit y `git log --oneline -3` se reportan en la respuesta final.
No se realiza push.
