# B3: medición antes del cambio

Base `ac844a9`; rama `feat/tui-live-stream`. Instrumentación temporal fuera
del repositorio: `/tmp/tui_b3_probe.py`, `/tmp/tui_b3_bench.py`,
`/tmp/tui_b3_analyze.py`. Sin cambios en kernel, agente o herramientas.

Se envolvieron `TuiSession.print`, `TuiSession.invalidate` y
`Application.invalidate` con contadores y monotonic timestamps. La carga
reproducible contó también `Application.after_render`. PTY tmux 120×35,
`script -q -T archivo.timing -O archivo.ansi -c ...`, con colores activos.
El analizador asigna cada bloque de bytes al segundo de su timestamp.

| Medición | Nmap real | Carga fija: 60 writes, 10/s |
| --- | ---: | ---: |
| Duración captura (incluye arranque/espera/salida) | 136,15 s | 9,30 s |
| print total / pico por segundo | 24 / 11 | 60 / 10 |
| TuiSession.invalidate total / pico | 62 / 14 | 122 / 21 |
| Application.invalidate total / pico | 1485 / 1287 | 186 / 32 |
| Renders / pico | no instrumentado | 127 / 22 |
| ESC[2J total / pico | 1 / 1 | 0 / 0 |
| ESC[H total | 0 | 0 |
| Cursor arriba total / pico | 125 / 18 | 219 / 41 |
| Bytes ANSI | 67555 | 81212 |

El pico de Application.invalidate del run real incluye la entrada pegada
mediante send-keys; no representa writes de output. La carga fija sin teclado
es la comparación controlada para B3. Ninguna de las dos cargas genera tokens
LLM en streaming: el proveedor entrega respuestas completas actualmente.

Objetivo real: TCP connect a `scanme.nmap.org`, solo puertos 22,80,443, sin NSE.
Run `run_c022d30fe1a4476995f489ee01859d39`, estado completed, dos iteraciones,
1 host up, 2 puertos abiertos, noise high. El gateway y el scope permanecieron
activos. Registro: `/tmp/tui-b3-before.{json,timing,ansi}`. Carga fija:
`/tmp/tui-b3-bench-before.{json,timing,ansi}`.

Hallazgos:

- Cada print suspende la Application mediante la primitiva de salida externa,
  modifica el panel, invalida dentro del append e invalida otra vez al salir.
  Se restaura la pantalla aunque no se escribió nada físicamente fuera de ella.
- La carga genera ~dos renders por write; los borrados ESC[2J no son un buen
  indicador aislado. Contar renders, bytes y movimientos de cursor muestra el
  coste que sí está presente.
- patch_stdout no repite el banner en este run, pero también puede suspender
  la Application para writes ajenos al router. Se reemplazará por un adaptador
  que añade stdout/stderr al mismo buffer.
- El polling de 0,5 s entrega lotes de mensajes; no invalida si no hay salida.
- react.action como evento tiene tool_id pero no argumentos. Los argumentos
  y resultados completos están en mensajes durables react.action/observation.
  El renderer usará esos mensajes para evitar invenciones y duplicados.
- Las observaciones recortan stdout; nmap entrega scan estructurado, evidencia
  y XML. Se mostrarán datos reales disponibles, sin fingir líneas de consola.
- El ejemplo del truncado es contradictorio: se adopta primera + últimas dos
  líneas de datos, más un único marcador de omisión (hasta cuatro líneas visuales).
- full_screen=False evita la pantalla alternativa, pero por sí solo no hace
  que el terminal archive el contenido de un Window desplazable. Se verificará
  la historia con navegación explícita por el buffer y se documentará el límite.
