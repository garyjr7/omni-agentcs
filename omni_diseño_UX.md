# Auditoría de diseño UX — TUI y CLI de OMNI

| Dato | Valor |
|---|---|
| Fecha | 2026-11-06 |
| HEAD auditado | `433ddd0` — *chore(gates): cobertura medida, tipos medidos y auditoría bloqueante* |
| Versión | `3.0.0b1` |
| Alcance | `nexus_core/cli/` (capa de presentación). **No** se audita el kernel, la gobernanza ni los handlers. |
| Superficie | `nexus_core/cli/tui/`: 20 ficheros, **5.384 líneas** (`wc -l nexus_core/cli/tui/*.py`); más `theme.py`, `render.py`, `banner.py`, `spinner.py`, `tool_result.py` (1.235 líneas). |
| Medición ejecutada | 362 tests TUI: **362 passed en 13,03 s**; test PTY aislado: **1 passed en 2,48 s**; renders deterministas de las funciones reales (Anexo A). |
| Regla de este informe | Toda afirmación lleva `ruta:línea` o comando reproducible. Lo que no se pudo medir se marca como límite en §1.3. |

---

## 0. Resumen ejecutivo

**Veredicto: la capa visual no es un script de universidad, y tampoco está a medio construir.** Es una interfaz de producto con jerarquía, un solo escritor de terminal, tarjetas plegables, overlay de razonamiento, panel de plan, menú de aprobación de dos pasos y barra de estado con prioridad de caída. El plan que se pegó para esta ronda asume que esa capa hay que crearla; **ya existe y tiene 362 tests**.

**Nota global: 7,1/10** (media de las cinco reglas del plan).

| Regla del plan | Nota | Estado real |
|---|---|---|
| 1. Jerarquía visual, sin muro de texto | 9,0 | Implementada: rail de operador, razonamiento atenuado, llamada de una línea, veredicto con `✓`/`×`, cuerpo plegado. |
| 2. Resumen vs. detalle | 8,0 | Implementada: `fold_lines` + «Ver N líneas más» + clic/`ctrl+o` + JSON diferido. **Un defecto de ancho** (D1). |
| 3. Bordes y contenedores | 7,0 | Decisión deliberada y coherente: sin cajas por tarjeta; panel solo para el resultado final. No es deuda, es criterio. |
| 4. Paleta semántica | 6,5 | Existe `THEME`, pero **2 de 4 módulos se saltan la paleta** (D4), el color es 24-bit forzado (D6) y no hay tema claro. |
| 5. Barra de estado | 5,0 | La maquinaria existe, pero **en una sesión real solo muestra alertas** (D3); `/status show` duplica tokens (D2). |

### Lo que está genuinamente bien

1. **Un solo escritor de terminal.** `TuiOutput.write` → `TuiSession.print` (`nexus_core/cli/tui/output.py:54-62`); `rich.live.Live` está deliberadamente ausente (`nexus_core/cli/tui/frame.py:10-15`). El test PTY demuestra que un log INFO no se escribe por detrás de la TUI (`nexus_core/tests/integration/test_tui_pty_integrity.py:51-58`).
2. **Cuatro regiones, no cinco.** `ui._regions = [scrollback, input]` (`layout.py:354`) con overlays que no consumen layout; el menú de aprobación crece *dentro* del dock (`layout.py:385-401`).
3. **La jerarquía es código, no una guía.** `user_message` (`presentation.py:153`), `thinking` (`presentation.py:344`), `tool_call_line` (`presentation.py:658`), `tool_result_line` (`presentation.py:704`). El pensamiento colapsado cuesta exactamente una fila (`presentation.py:356-359`).
4. **Degradación honesta.** `--no-color` / `NO_COLOR` atraviesan TUI y renderers (`session.py:88`), y `render_markdown` elimina secuencias SGR del contenido del modelo antes de pintarlo (`markdown.py:129-131`).
5. **Refresco adaptativo.** 0,1 s mientras trabaja, sin refresco periódico en reposo (`session.py:1599-1601`); 1.000 invalidaciones en ráfaga se acotan a ≤4 repintados (`test_tui_flicker_regression.py:19-31`).

### Lo que impide llamarlo terminado

Doce defectos medidos (§5). Los tres que afectan a lo que el operador ve **en cada turno**:

- **D1**: la línea de resultado se pasa del ancho y **corta la lista de puertos por la mitad** (120 celdas en un ancho de 100; 2 filas donde el contrato dice 1).
- **D2**: `/status show` imprime los tokens dos veces y el coste con dos etiquetas.
- **D3**: en una sesión con workspace —es decir, siempre— la barra solo pinta `TRUST`/`session`; tokens, coste, contexto, alcance y sandbox no están en ninguna fila persistente (el modelo y el cwd sí están, en el footer del input).

Nada de esto exige rediseñar. Son correcciones de 0,5–3 h cada una (§8).

---

## 1. Método, alcance y límites

### 1.1 Leído

Inventario completo de `nexus_core/cli/tui/` y de los módulos de presentación de `nexus_core/cli/`: `layout.py` (466), `presentation.py` (729), `session.py` (1.623), `stream.py` (495), `status.py` (299), `panels.py` (261), `frame.py` (193), `markdown.py` (177), `strings.py` (59), `tasks.py` (218), `usage.py` (101), `pricing.py` (90), `theme.py` (166), `render.py` (502), `banner.py` (378), `spinner.py` (148). También `nexus_core/cli/session.py` en los puntos donde la TUI recibe datos (envío de tool calls, tarjetas, estado).

### 1.2 Ejecutado

```bash
.venv/bin/python -m pytest nexus_core/tests/unit/test_tui_*.py -q -p no:cacheprovider
# 362 passed, 1 warning in 13.03s

.venv/bin/python -m pytest nexus_core/tests/integration/test_tui_pty_integrity.py -q -p no:cacheprovider
# 1 passed in 2.48s
```

Renders deterministas con las funciones reales de producción (`render_tool_result`, `format_tool_invocation`, `detailed_tool_invocation`, `render_status_plain`, `render_status_bar`), sin terminal interactiva. Salidas literales en el Anexo A.

### 1.3 No ejecutado / límites

- **No hay capturas de pantalla.** El entorno de auditoría no tiene TTY interactivo. La verificación visual es textual (renders reales) más el test PTY que comprueba integridad de cursor y orden de escritura. Una revisión estética final —proporciones, contraste percibido, sensación de velocidad— requiere una sesión humana en un terminal real.
- **No se ha modificado código.** Todos los parches de §7 son propuestas, marcadas como no aplicadas.
- **No se mide latencia de tecleo ni FPS reales.** Se cita la configuración de refresco, no una medición de percepción.

---

## 2. Arquitectura de la capa visual

### 2.1 Mapa de módulos

| Módulo | Responsabilidad | Evidencia |
|---|---|---|
| `layout.py` | Composición de regiones, overlays, captura de ratón, arranque de la `Application`. | `layout.py:1-21`, `:404-460` |
| `session.py` | Estado del transcript, segmentos, tarjetas, typewriter, scroll, aprobación, hilo único de escritura. | `session.py:100-170`, `:980-1035` |
| `presentation.py` | Renderizables Rich puros: banner, turno de usuario, razonamiento, tarjeta, líneas conversacionales, spinner. | `presentation.py:1-120` |
| `stream.py` | Traducción de `tool_result` durable a tarjeta: resumen, cuerpo, diff, guardrail, JSON diferido. | `stream.py:324-465` |
| `status.py` | Estado de la barra, prioridad de caída, preferencias XDG, línea del footer. | `status.py:49-270` |
| `frame.py` | Cabecera, pulso de trabajo, línea «completado en», menú de permiso. | `frame.py:61-140` |
| `panels.py` | Panel lateral (Float) y menú de aprobación. | `panels.py:51-251` |
| `markdown.py` | Markdown sin dependencias: encabezados, listas, tablas, fences. | `markdown.py:120-177` |
| `theme.py` | Paleta semántica única. | `theme.py:25-145` |
| `output.py` | Frontera única de escritura (`TuiOutput`, `StderrOutput`, `PlainOutput`). | `output.py:15-60` |

### 2.2 Flujo real: del agente a la pantalla

```text
ReAct action (tool_call)
   └─ cli/session.py:969-972  format_tool_invocation(...)  → append_execution_block
                                 "> Ejecutando nmap en <target>..."
   └─ cli/session.py:651      _busy(descripción) → fila fija del dock (set_busy)
   └─ ejecución (gateway: policy, scope, aprobación, journal, auditoría)
   └─ observation (react.observation)
         ├─ TUI: append_card(observation)        (session.py:1652)
         └─ render_tool_result(...)              (stream.py:421)
               ├─ summarize_tool_result          (stream.py:324)
               ├─ tool_result_line               (presentation.py:704)  → 1 línea
               └─ expandida: trace_block         (presentation.py:457)  → cuerpo plegado
```

La tarjeta no inventa datos: el resumen sale de `evidence`, `output`, `message`/`reason` del propio resultado (`stream.py:324-366`). Un resultado negativo verificado conserva sus palabras y su color de éxito (`stream.py:303-322`; test `test_a_negative_but_verified_result_keeps_its_own_words`).

### 2.3 La invariante que sostiene todo

`rich.live.Live` no se usa: la sesión posee el terminal con una única `prompt_toolkit.Application`, y una segunda escritura pelearía por el cursor (`frame.py:10-15`). El transcript es un `Buffer` de solo lectura con un lexer que **no re-parsea estilos por frame** (`layout.py:124-134`). Cualquier propuesta de UX que añada un spinner por tarjeta o una caja animada rompe esa invariante; ver §9.

---

## 3. Las cinco reglas, una por una

### 3.1 Jerarquía visual estricta (el «no muro de texto»)

**Lo que pide el plan:** usuario claro, pensamiento atenuado, tool call delimitada con resumen (nunca JSON crudo), spinner mientras corre, check/X con tiempo, truncado con `Ctrl+O`.

**Lo que hay:**

| Elemento | Implementación | Evidencia |
|---|---|---|
| Turno del operador | Rail `▌` rojo, hora de 12 h, cuerpo envuelto al ancho | `presentation.py:153-171` |
| Razonamiento | Colapsado: exactamente `▸ Razonamiento`; expandido: `▾` + nota en gris itálica | `presentation.py:344-368` |
| Razonamiento en vivo | Máximo 5 filas, última con `…`; nunca una línea horizontal | `presentation.py:370-415` |
| Tool call por defecto | `> Ejecutando nmap en scanme.nmap.org...` (una fila) | `presentation.py:658-677` |
| Tool call detallada | `$ nmap -sV -p- -oX - <target>` solo al expandir | `stream.py:186-231` |
| Veredicto | `✓` verde / `×` rojo, con el nombre de la tool | `presentation.py:704-729` |
| Cuerpo | Líneas bajo `└`, sin color de veredicto | `presentation.py:513-536` |
| Guardrail | `⚠` ámbar, guía completa, sin marca de fallo | `presentation.py:470-483` |
| Spinner | Fila fija del dock, braille de 10 frames, `esc` como keycap | `frame.py:33`, `presentation.py:540-576` |
| Línea de cierre | `completado en 3m 12s • 04:35 PM` en la misma fila | `frame.py:131-138` |
| Diff | `rich.syntax` con tema `ansi_dark` | `presentation.py:417-420` |

**Veredicto: 9,0 — implementada.** La única deuda de esta regla es D1 (ancho del veredicto) y D8 (tiempo por tool, que hoy solo reportan 12 de 88 handlers).

### 3.2 Resumen vs. detalle

**Lo que pide el plan:** una línea de resumen y el detalle detrás de una affordance explícita; nada de 500 líneas de salida.

**Lo que hay:** `fold_lines` parte el cuerpo en 3 líneas de cabeza + 1 de cola (nunca la media aritmética antigua) y devuelve el número exacto de líneas ocultas (`presentation.py:120-135`). El pie `Ver N líneas más` es clicable por línea de transcript (`layout.py:47-67`, `session.py:1294-1304`) y `ctrl+o` pliega/expande la última tarjeta (`session.py:655-669`). Un payload estructurado no se vuelca: se difiere con su recuento (`presentation.py:493-505`), y el JSON no aparece en la tarjeta colapsada (tests `test_report_result_summarizes_the_path_and_keeps_the_json_in_the_detail`, `test_unknown_structured_output_is_summarized_in_one_line`).

Además, el transcript está **acotado**: se descartan los bloques visuales más antiguos al superar `TRANSCRIPT_MAX_SEGMENTS`/`TRANSCRIPT_MAX_LINES`, sin tocar el registro durable (`session.py:1324-1357`). El miedo del plan a que «la TUI se congele» con 3 MB de XML no se sostiene: `output_text` mapea el `scan` ya parseado a filas (`stream.py:246-258`).

**Veredicto: 8,0 — implementada, con un defecto de ancho (D1).** La tabla limpia de puertos **solo** existe en el resumen final, construida desde los hechos del blackboard (`presentation.py:179-210`); la tarjeta viva muestra líneas `└ Puerto 443/tcp open: https`. Es una oportunidad (P2), no un fallo de corrección.

### 3.3 Bordes y contenedores

**Lo que pide el plan:** `Panel` con bordes redondeados para encapsular.

**Lo que hay:** una decisión opuesta y documentada. En la transcripción **no hay caja por tarjeta**: el borde y el cuerpo dejan de coincidir a 200 columnas y fragmentan el bloque (`presentation.py:214-222`). Las cajas se reservan para el resultado final, que sí es un `Panel` cuadrado con `surface_alt` (`presentation.py:259-276`, usado en `cli/session.py:1385`). El input es un panel gris con **una sola barra vertical roja**, sin reglas horizontales (`layout.py:321-331`), y el menú de permiso crece desde ese mismo dock (`layout.py:385-401`).

**Veredicto: 7,0 — no es deuda, es criterio.** Adoptar «bordes redondeados en todo» sería una regresión medida contra el propio código. Lo que sí falta es que esa decisión esté en un ADR o en `docs/`; hoy solo vive en docstrings.

### 3.4 Paleta semántica y oscura

**Lo que pide el plan:** roles, no colores sueltos; agente en un color distintivo; legibilidad por encima del neón.

**Lo que hay:** `Theme` con roles y valores únicos (`theme.py:25-60`), alias ANSI derivados (`theme.py:130-145`) y la regla «un renderer nombra un rol, nunca un hex» (`presentation.py:23-35`). El razonamiento es gris itálica, el éxito verde, el fallo rojo, el aviso ámbar, el operador rojo (`theme.py:29`, `:43-49`).

**Pero:** `panels.py` y `status.py` se saltan la paleta.

- `panels.py:126-133` y `:241-251` llevan hex literales: `#0d1117`, `#ffc950`, `#56e696`, `#ff4054`, `#6a6f76`, `#1a0d11`, `#9aa0a6`. En total, 28 literales en 14 reglas de estilo (`grep -o "#[0-9a-fA-F]\{6\}" nexus_core/cli/tui/panels.py | wc -l` → 28). Cambiar `THEME.primary` no cambia la fila seleccionada del menú de permiso (`#ff0055` fijo en `panels.py:248`).
- `status.py:108-170` usa nombres ANSI (`ansicyan`, `ansigreen`, `ansired`, `ansimagenta`), que son los del terminal, no los de OMNI: el «Alcance» de la barra no es el aqua `#00e5ff` del tema.
- El test que protege la regla solo inspecciona **dos** módulos (`test_tui_theme.py:7-14`: `presentation`, `layout`), así que la fuga pasa verde.

**Veredicto: 6,5 — parcial.** Es el hallazgo de consistencia más claro del informe (D4).

### 3.5 Barra de estado

**Lo que pide el plan:** modelo, tokens, coste, scope y sandbox en una línea fija tipo `htop`.

**Lo que hay:** `StatusState` con todos esos campos (`status.py:49-84`), una tabla de prioridad de caída (`status.py:25-42`), segmentos protegidos (`status.py:45-47`), truncado por celdas (`status.py:207-235`) y preferencia persistente en `tui.json` (`status.py:252-270`). La barra se enciende con `/status on|off` y muestra el estado completo con `/status show` (`commands.py:1343-1368`).

**El problema:** en una sesión real `workspace_path` **siempre** está definido (`cli/session.py:753`), y esa rama descarta todo salvo las alertas:

```python
if state.workspace_path:
    items = [part for part in _parts(state) if part[0] == PRIORITY["alert"]]
```

(`status.py:218-221`). Medido: con un estado completo a 120 columnas, la barra devuelve **solo** `session ab12cd/ssh` (Anexo A). Durante un run no hay forma de leer tokens, coste, contexto ni alcance sin ejecutar `/status show`. Y el sandbox no tiene campo en `StatusState`: solo se pinta en el banner de arranque (`banner.py:243`).

Peor: los tests de la barra usan `StatusState()` **sin** `workspace_path` —por ejemplo `test_status_truncates_to_width` afirma `"Estado: INA"` a 11 columnas (`test_tui_status.py:56-61`)—, es decir, validan la rama que producción no ejecuta. `grep workspace_path nexus_core/tests/unit/test_tui_status.py` no devuelve nada.

**Veredicto: 5,0 — la maquinaria es buena; el cableado la anula.** Es D3, el defecto de mayor impacto visible después de D1.

---

## 4. Tabla de brecha: plan pegado vs. realidad

| Petición del plan | Estado | Evidencia / hueco |
|---|---|---|
| Jerarquía usuario/pensamiento/tool/resultado | **Existe** | `presentation.py:153`, `:344`, `:658`, `:704` |
| Tool call con resumen, nunca JSON crudo | **Existe** | `presentation.py:658-677`; `stream.py:421-465` |
| Spinner animado mientras corre | **Existe** (fila global) | `frame.py:33`, `:87-92`; refresco 0,1 s en `session.py:1600` |
| Check/X con el tiempo que tardó | **Parcial** | `✓/×` sí (`presentation.py:704`); duración solo si el handler la reporta: 12 de 88 ficheros de handler mencionan `elapsed_seconds` |
| Truncar con «N líneas omitidas + Ctrl+O» | **Existe** | `presentation.py:120-135`; `ctrl+o` en `session.py:655`; clic en `layout.py:47` |
| Panel/box por bloque | **No, por diseño** | `presentation.py:214-222`; caja solo en el resultado final (`:259`) |
| Paleta semántica central | **Parcial** | `theme.py:29-49`; fugas en `panels.py:126-133`, `:241-251`, `status.py:108-170` |
| Barra con modelo/tokens/coste/scope/sandbox | **Parcial** | `status.py:218-221` (solo alertas); sandbox solo en `banner.py:243` |
| Tabla limpia de puertos en la tarjeta | **No** (sí en el resumen final) | `stream.py:246-258` vs. `presentation.py:179-210` |
| Estado reactivo sin mezclar logs e input | **Existe** | `output.py:54-62`; PTY test `test_tui_pty_integrity.py:51` |
| Capturas para revisar el aspecto | **No disponible** | Sin TTY interactivo (§1.3); renders en Anexo A |

---

## 5. Defectos medidos

| ID | Sev. | Síntoma | Evidencia |
|---|---|---|---|
| D1 | P1 | El resultado colapsado excede el ancho y corta la lista de puertos a mitad de número | `presentation.py:704-729` + `stream.py:431-445` |
| D2 | P1 | `/status show` imprime los tokens dos veces; coste y presupuesto sin etiquetas distinguibles | `status.py:125`, `:142-150`, `:127`, `:152-157` |
| D3 | P1 | La barra en sesión real solo muestra alertas; tests validan la rama muerta | `status.py:218-221`; `test_tui_status.py:56-61` |
| D4 | P2 | `panels.py`/`status.py` no usan `THEME`; el test de paleta solo cubre 2 módulos | `panels.py:126-133`, `:241-251`; `test_tui_theme.py:10-14` |
| D5 | P2 | El panel lateral y el menú de permiso miden por `len()`, no por celdas | `panels.py:30-49`, `:198-200` |
| D6 | P2 | 24-bit forzado sin consultar la capacidad del terminal | `layout.py:456`; `presentation.py:91`, `:101` |
| D7 | P3 | `nexus.report.generate` se llama «generate» en la tarjeta | `presentation.py:614-621`; render en Anexo A |
| D8 | P2 | Sin duración por tool en 76 de 88 handlers | `stream.py:345-346`; `grep -l elapsed_seconds nexus_core/tools/handlers` |
| D9 | P3 | `PREFIXES`/`tool_prefix` sin uso en producción (solo tests); `SHOW_FULL_REASONING` muerto | `stream.py:11-26`; `strings.py:27` |
| D10 | P3 | `ctx ~?%` se pinta como si fuera una métrica cuando el contexto es desconocido | `status.py:137-138` |
| D11 | P2 | El modo sandbox no está en ningún estado persistente; solo en el banner | `StatusState` (`status.py:49-84`); `banner.py:243` |
| D12 | P3 | Ratón capturado; seleccionar texto exige `Shift` y no hay opt-out | `layout.py:450-451` |

### D1 — La línea de resultado rompe el contrato de una fila

Reproducción (Anexo B):

```text
✓ nmap: 15 puertos abiertos (21, 22, 25, 80, 110, 143, 443, 993, 995, 3306, 5432, 6379, 8080,
8443,… · Ver 13 líneas más
```

- `cell_len(línea) = 120` con `width=100`; el transcript la envuelve en **2 filas**.
- La lista de puertos se corta en `8080,` y luego en `8443,` (número incompleto), se pierde el paréntesis de cierre y el pie queda colgando en la segunda fila.
- Causa: `tool_result_line` ajusta la línea a `width` (`presentation.py:725-729`) y **después** `render_tool_result` le concatena ` · Ver N líneas más` (`stream.py:434-444`). El pie nunca reserva su espacio.
- Por qué ningún test lo cazó: `test_collapsed_card_is_a_single_plain_line` solo comprueba el número de filas con un resumen corto (`test_tui_stream_render.py:117-124`); no hay aserción de ancho.

Efecto real: el operador lee «8443,…» como si el puerto estuviera truncado o el escaneo incompleto. En una herramienta de reconocimiento, una cifra cortada es peor que una omitida.

### D2 — Tokens duplicados en `/status show`

Salida medida:

```text
... | Tokens: 49,500 | Presupuesto: $5.00 | ... | run 49.5k tok | ~$0.9100 | ...
```

`_parts` añade el segmento `Tokens:` (`status.py:125`) y vuelve a añadir los mismos tokens como `run N tok` (`status.py:142-150`), ambos con `PRIORITY["tokens"]`. El coste ocurre igual: `Presupuesto` (`:127`) y `~$coste` (`:152-157`) son métricas distintas pero llegan sin etiqueta que las distinga. La barra no workspace oculta el duplicado con un filtro textual (`and not part[2].startswith("run ")`, `:222`), lo que confirma que el duplicado se conoce y se tapa en un sitio en vez de corregirse en el origen.

### D3 — La barra priorizada solo vive en tests

Con `workspace_path` siempre poblado (`cli/session.py:753`), `render_status_bar` cae en `status.py:218-221` y descarta todo salvo `PRIORITY["alert"]`. La tabla de prioridades, el truncado por celdas y los segmentos protegidos quedan sin uso en producción. Medición: estado completo, ancho 120 →

```text
FormattedText([('ansimagenta', 'session ab12cd/ssh')])
```

No es un bug de pintado: es una decisión de producto (modelo y cwd viven en el footer, la fase en el panel) cuyo coste no está declarado: **tokens, coste, contexto, alcance y sandbox no son visibles durante el run**. Y su test unitario prueba la otra rama.

### D4 — Fuga de paleta en dos módulos

`test_tui_theme.py` afirma «renderers must not carry hex literals» pero solo importa `presentation` y `layout` (`:7-14`). `panels.py` tiene 28 literales hex en 14 reglas (`:126-133`, `:241-251`); `status.py` usa ANSI del terminal (`:108-170`). Consecuencia verificable: `THEME.primary` es `#ff0055` y la fila seleccionada del menú de permiso también, pero está escrita a mano; cambiar el rol deja el menú en rojo viejo. Lo mismo con `ok`, `warn`, `error`, `subtle` y `surface_alt`.

### D5 — Ancho por caracteres, no por celdas

`panels.py:_wrap` y `_clip_line` usan `len()` (`:30-49`, `:198-200`), mientras `status.py` usa `get_cwidth` (`:211`) y `presentation.py` usa `cell_len`/`chop_cells` (`presentation.py:632-657`). Un nombre de fase o un argumento con CJK o emoji desborda el panel lateral y el menú de permiso en celdas, y la fila se corta donde no toca. El menú de permiso es el sitio donde el operador firma una acción: un argumento mal cortado ahí no es cosmético.

### D6 — Truecolor forzado

`ColorDepth.DEPTH_24_BIT` se pasa siempre que hay color (`layout.py:456`), y `render_rich`/`wrap_terminal_text` fijan `color_system='truecolor'` (`presentation.py:88-103`). `README.md:618` documenta la paleta como truecolor, así que es una decisión declarada; el coste es que en terminales de 8/256 colores no hay detección ni degradación controlada. `prompt_toolkit` ya expone `output.get_default_color_depth()` (verificado en el entorno), que devolvería la profundidad real.

### D7 — «generate» en vez de «report»

`_TOOL_SHORT_NAMES` (`presentation.py:614-621`) no incluye `nexus.report.generate`, así que el nombre corto sale del último segmento: `✓ generate: …`. Para el operador, la tool de informe se llama «generate». Se corrige con una entrada en el mapa; el resto del sistema ya la llama `report.generate`.

### D8 — El «tiempo que tardó» solo existe en 12 de 88 handlers

El plan pide «check verde con el tiempo que tardó». Hoy la duración aparece en el resumen solo si `evidence.elapsed_seconds` existe (`stream.py:345-346`); `grep -l elapsed_seconds nexus_core/tools/handlers/*.py` devuelve 12 de 88 ficheros. El gateway **sí** mide la duración para su métrica (`tool_gateway.py:708-712`: `nexus_tool_duration_ms_total`), pero no la devuelve en el resultado, así que la TUI no puede mostrarla sin un cambio de contrato. Alternativa sin tocar el kernel: medir en el punto de llamada de la CLI y pasarla a la tarjeta (ver §7.7).

### D9 — Código muerto que se mantiene con tests

`PREFIXES` y `tool_prefix` (`stream.py:11-29`) no se usan en producción: las 8 referencias son de `test_tui_stream_prefix.py`. `SHOW_FULL_REASONING` (`strings.py:27`) tiene 0 usos fuera de su definición y de `__all__`. No rompe nada; engorda la superficie y da la falsa impresión de que existe una etiqueta `[Recon-NMAP]` en la interfaz.

### D10 — `ctx ~?%` como métrica falsa

Cuando `context_window` es desconocido, la barra pinta `ctx ~?%` en dim (`status.py:137-138`). Es honesto (no inventa un número), pero ocupa espacio y se lee como un porcentaje roto. En `/status show` aparece siempre. Mejor: omitir el segmento cuando no hay dato, o decir `ctx sin dato`.

### D11 — El sandbox no tiene estado persistente

`StatusState` no tiene campo de sandbox (`status.py:49-84`); el modo se pinta una vez en el banner (`banner.py:243`) y desaparece al primer scroll. En una herramienta que promete gobernanza, el modo de aislamiento vigente debería ser legible en cualquier momento. Es una fila del footer o un segmento protegido, no un rediseño.

### D12 — Ratón sin opt-out

`mouse_support=True` (`layout.py:450`) es necesario para la rueda en alt-screen, pero obliga a `Shift` para seleccionar texto (comentario en `layout.py:448-449`). En una TUI que produce comandos y hashes que el operador quiere copiar, no hay ajuste para desactivar la captura. No es urgente; es fricción diaria.

---

## 6. Sistema de diseño (lo que ya es norma y debe quedarse)

### 6.1 Paleta: rol → valor → uso

| Rol | Valor | Uso | Definición |
|---|---|---|---|
| `primary` | `#ff0055` | Rail del operador, badge, fila seleccionada, marca | `theme.py:29` |
| `surface` | `#2a2a2a` | Panel de entrada | `theme.py:31` |
| `surface_alt` | `#1a0d11` | Menú de permiso y resultado final | `theme.py:33` |
| `text` | `#ffffff` | Títulos, pregunta de permiso | `theme.py:35` |
| `white` | `#f0f4f8` | Salida de comandos | `theme.py:37` |
| `muted` | `#787e86` | Metadatos, razonamiento, timestamps | `theme.py:39` |
| `subtle` | `#6a6f76` | Placeholder, pendiente | `theme.py:41` |
| `thinking` | `#787e86` | Razonamiento en vivo | `theme.py:43` |
| `ok` | `#56e696` | Verificado | `theme.py:45` |
| `error` | `#ff4054` | Fallo real | `theme.py:47` |
| `warn` | `#ffc950` | Guardrail, riesgo, fase actual | `theme.py:49` |
| `aqua` | `#00e5ff` | Acento legacy | `theme.py:54` |

Regla: **un renderer nombra un rol**. Las excepciones actuales son D4.

### 6.2 Jerarquía tipográfica

| Nivel | Peso | Color | Ejemplo |
|---|---|---|---|
| Operador | normal | texto + rail `primary` | `▌ [04:12 PM] objetivo…` |
| Razonamiento | itálica | `muted` | `▸ Razonamiento` |
| Acción | normal | texto | `> Ejecutando nmap en …` |
| Veredicto | bold | `ok` / `error` / `warn` | `✓ nmap: 3 puertos abiertos` |
| Detalle | normal | terminal | `└ Puerto 443/tcp open: https` |
| Affordance | dim underline | `link_style` | `Ver 13 líneas más` |

### 6.3 Espaciado e indentación

| Medida | Valor | Evidencia |
|---|---|---|
| Inset del transcript | 2 celdas | `layout.py:117-124` (`ConsoleInset`) |
| Rail del operador | `▌ ` (2 celdas) | `presentation.py:164` |
| Rama de salida | `└ ` (2 celdas), continuación 4 | `presentation.py:522-529` |
| Continuación de invocación | `  ↳ ` | `stream.py:114` |
| Padding del panel de resultado | `(1, 2)` | `presentation.py:273` |
| Separación del dock | 2 columnas + barra de 1 | `layout.py:321-331` |
| Ancho útil | `columns - 2` | `session.py:1466-1474` |

### 6.4 Iconografía

| Glifo | Significado | Evidencia |
|---|---|---|
| `▌` | turno del operador | `presentation.py:164` |
| `▸` / `▾` | razonamiento colapsado / expandido | `presentation.py:357` |
| `└` | cuerpo del resultado | `presentation.py:45` |
| `✓` / `×` | éxito / fallo | `presentation.py:446`, `:725` |
| `⚠` | corrección del orquestador | `presentation.py:470` |
| `⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏` | pulso de trabajo | `frame.py:33` |
| `│` | barra del input | `layout.py:321` |
| `▶` `⏳` `✓` `·` `✗` | estados del plan | `panels.py:66`, `:88` |
| `▲` | transcript pausado | `session.py:477` |
| `$` | argv real | `stream.py:221` |

### 6.5 Máquina de estados de una tarjeta

```text
creada ──success──▶ ✓ ok ──clic/ctrl+o──▶ cuerpo completo
   │                 │
   ├──failure──▶ × error ──clic──▶ error + detalle
   │
   └──guardrail──▶ ⚠ warn (sin marca de fallo, sin footer)
```

| Transición | Condición | Evidencia |
|---|---|---|
| creada | `append_card` | `session.py:1191-1228` |
| plegable | `_has_toggle` | `session.py:1272-1291` |
| expandir/colapsar | clic en pie o `ctrl+o` | `session.py:1294-1304`, `:655-669` |
| guardrail | `is_guardrail` | `stream.py:403-419` |

### 6.6 Reglas de ancho (las que hay que respetar y hoy D1 incumple)

1. Medir en **celdas**, no en caracteres (D5 es la excepción).
2. Reservar el pie **antes** de ajustar la línea: ver D1.
3. El texto del cuerpo nunca se recorta (se envuelve); solo la línea de veredicto se ajusta, y los fallos **nunca** se recortan (`presentation.py:725-729`).
4. El transcript se envuelve antes de entregarlo a `prompt_toolkit` (`wrap_terminal_text`, `presentation.py:97-110`).

### 6.7 Terminales y accesibilidad

| Tema | Estado | Evidencia |
|---|---|---|
| `NO_COLOR` / `--no-color` | Soportado en TUI y renderers | `session.py:88`; `layout.py:456` |
| Truecolor | Forzado (documentado) | `README.md:618`; D6 |
| Tema claro | No existe: superficies oscuras fijas | `theme.py:31-33` |
| Movimiento reducido | `NEXUS_TUI_TYPEWRITER=0` (solo por entorno) | `session.py:1066-1077` |
| Ratón | Capturado, sin opt-out | D12 |
| ASCII en spinner no-TUI | `SPINNER_FRAMES_ASCII` | `spinner.py:16` |

---

## 7. Código: lo que ya existe y los parches propuestos

> **Estado (2026-11-07):** D1–D4 y el banner de arranque se aplicaron después de esta auditoría. Los parches de §7.3–§7.6 se conservan como registro de la propuesta, no como deuda pendiente; D1 se cerró además con un fallback que omite la lista de puertos cuando no cabe, en vez de cortar un número.

### 7.1 Tool call (ya implementado)

```python
# nexus_core/cli/tui/presentation.py:658-674 (literal, docstring abreviada)
def tool_call_line(tool_id: str, arguments: Any, *, width: int | None = None) -> str:
    from ..render import display_arguments

    safe = display_arguments(arguments if isinstance(arguments, dict) else {})
    tool = str(tool_id or '')
    action = _TOOL_ACTIONS.get(tool)
    if action is None:
        action = f'Ejecutando {_short_tool_name(tool)}'
    target = _action_target(safe)
    return _fit_line(f'> {action}' + (f' en {target}' if target else '') + '...', width)
```

Detalle real al expandir: `$ nmap -sV -p- -oX - scanme.nmap.org` (`stream.py:186-231`). Los secretos pasan siempre por `display_arguments`.

### 7.2 Spinner (ya implementado)

El frame es un glifo braille muestreado por el bucle de refresco (`frame.py:87-93`); la fila es fija, nunca una línea del transcript (`layout.py:287-292`). No añadir un segundo spinner por tarjeta: reintroduce el segundo escritor que `frame.py:10-15` rechaza.

### 7.3 Parche D1 — reservar el pie antes de ajustar

```python
# nexus_core/cli/tui/stream.py, dentro de render_tool_result
if not expanded and not guardrail:
    summary = summarize_tool_result(result)
    hidden = hidden_detail_lines(result, max_lines=max_lines)
    footer = f" · Ver {hidden} líneas más" if hidden else ""
    line = tool_result_line(
        result, summary=summary,
        width=max(20, width - len(footer)),   # el pie ya tiene su sitio
    )
    return line + footer
```

Test que lo fija:

```python
from rich.cells import cell_len

def test_collapsed_line_never_exceeds_the_width():
    line = render_tool_result(scan_with_15_ports(), width=100, no_color=True)
    assert cell_len(line) <= 100
    assert line.count("(") == line.count(")")
```

### 7.4 Parche D2 — un solo segmento de tokens y coste etiquetado

```python
# nexus_core/cli/tui/status.py
# 1) eliminar el bloque "run N tok" (:142-150): los tokens ya están en :125
# 2) sustituir el append de coste (:152-157) por este, que lo etiqueta:
parts.append((PRIORITY["cost"], "ansigreen",
              f"coste ~${state.cost_usd:.4f}" if state.cost_known else "coste $—"))
```

### 7.5 Parche D3 — métricas en la única fila siempre visible

En lugar de reactivar una segunda barra que duplique el transcript, añadir al footer del input (`status.py:186-204`, `workspace_line`):

```text
deepseek/v4 · ~/omni-agentcs · ctx 62% · ~$0.91
```

La fase sigue en el panel de plan y las alertas en la barra. Es una fila, no una región nueva.

### 7.6 Parche D4 — llevar `panels.py` y `status.py` al tema

```python
# nexus_core/cli/theme.py
@property
def overlay_surface(self) -> str:
    return "#0d1117"          # panel lateral; hoy literal en panels.py:126
```

y sustituir en `panels.py` `#ffc950 → THEME.warn`, `#56e696 → THEME.ok`, `#ff4054 → THEME.error`, `#6a6f76 → THEME.subtle`, `#d0d4da → THEME.offwhite`, `#ffffff → THEME.text`, `#1a0d11 → THEME.surface_alt`, `#ff0055 → THEME.primary`. Extender el test:

```python
for module in (presentation, layout, panels, status):
    assert not hex_literal.search(inspect.getsource(module))
```

### 7.7 Parche D8 — duración en el punto de llamada

Sin tocar el kernel: envolver la llamada de `invoke_tool` (`cli/session.py:969-980`) y pasar `duration_seconds` a la tarjeta; en el bucle ReAct, hacer lo mismo en el punto donde se construye la observación (`cli/session.py:1652`). La tarjeta lo añade al resumen solo si está presente.

---

## 8. Prioridad

| Orden | IDs | Trabajo | Esfuerzo |
|---|---|---|---|
| **P0 (antes de RC)** | D1, D2 | Ancho del veredicto; quitar el duplicado de `/status show` | 1,5 h |
| **P0 (decisión)** | D3 | O footer con métricas, o declarar en `docs/` que la barra es solo de alertas y quitar los tests de la rama muerta | 0,5 h decidir · 2,5 h implementar |
| **P1** | D4, D5, D8, D11 | Paleta en 4 módulos; celdas en `panels.py`; duración; sandbox en el estado | 6–8 h |
| **P2** | D6, D7, D9, D10, D12 | Profundidad de color, nombre de `report`, código muerto, `ctx`, opt-out del ratón | 3 h |
| **Oportunidad** | — | Tabla de puertos en la tarjeta viva (no en el resumen final) | 3–4 h |

---

## 9. Evaluación crítica del plan pegado

### 9.1 Correcto y ya aplicado

1. **La jerarquía visual es el eje.** Cierto, y es exactamente cómo está construida la capa (`presentation.py:41-45`).
2. **Resumen vs. detalle.** Cierto; `fold_lines` + affordance clicable ya lo implementan.
3. **Paleta semántica, no `print()` con colores.** Cierto; `Theme` es la fuente única (con la deuda D4).
4. **Barra de estado priorizada.** Cierto como idea; el cableado la anula (D3).
5. **`rich` ya está en el proyecto.** Cierto: `Panel`, `Syntax`, `Text`, `Group`, `box.SQUARE`.

### 9.2 Incorrecto, desactualizado o redundante

1. **«Necesito ver cómo está la TUI ahora mismo».** El plan está escrito a ciegas: la capa tiene 5.384 líneas y 362 tests. La auditoría no debía empezar por «qué construir» sino por «qué medir».
2. **«Implementar esto es cuestión de capa de presentación».** Es cierto, y ya está implementado en su mayoría. El trabajo restante son 12 defectos, no un módulo nuevo.
3. **«Claude Code y Freebuff usan React (OpenTUI) o `prompt_toolkit` con estado reactivo».** OMNI usa `prompt_toolkit` con una `Application` persistente e `invalidate`; no hay React. La comparación no aporta un requisito: aporta una aspiración.
4. **«Paneles con bordes redondeados».** Contradice una decisión medida: a 200 columnas el borde y el cuerpo dejan de coincidir y fragmentan el bloque (`presentation.py:214-222`). Adoptarlo sería una regresión, no una mejora.
5. **«Un spinner por ejecución de tool».** Ya existe uno global en la fila fija, con refresco a 0,1 s (`session.py:1600`). Añadir otro por tarjeta introduce un segundo escritor y el flicker que el diseño evita (`frame.py:10-15`; `test_tui_flicker_regression.py`).
6. **«Nmap devuelve 3 MB de XML y la TUI se congela».** No ocurre: el resultado llega parseado (`stream.py:246-258`) y el transcript está acotado (`session.py:1324-1357`). El problema real es otro: la tarjeta viva no convierte ese `scan` en tabla (§3.2).
7. **«Ctrl+O para expandir».** Ya es `ctrl+o` **y** clic en el pie de la tarjeta.
8. **«Barra con sandbox».** El plan no sabe que el sandbox no tiene campo en `StatusState` y solo se pinta en el banner. Es un cambio de estado, no un `print` más.
9. **«Coste aproximado».** Existe (`usage.py:88-101`, `pricing.py`), pero está oculto por la rama de workspace. El plan pide lo que ya está calculado y no se muestra.

### 9.3 Lo que el plan acierta a señalar sin saberlo

La frase «el agente/IA en un color distintivo» choca con la decisión actual: el agente **no** tiene color propio; el acento rojo pertenece al operador y al marco. Es una elección defendible (el agente es el transcript, no un personaje), pero conviene dejarla escrita antes de que alguien la «corrija» añadiendo un cyan para la IA.

---

## 10. Anexo A — renders reales (salida literal)

Generados con las funciones de producción, `no_color=True`, ancho 100.

### A.1 Tool call conversacional y detallada

```text
> Ejecutando nmap en scanme.nmap.org...
$ nmap -sV -p- -oX - scanme.nmap.org
```

### A.2 Tarjeta colapsada (nmap, 15 puertos) — **D1**

```text
✓ nmap: 15 puertos abiertos (21, 22, 25, 80, 110, 143, 443, 993, 995, 3306, 5432, 6379, 8080,
8443,… · Ver 13 líneas más
```

`cell_len = 120`; 2 filas al envolver a 98 columnas.

### A.3 Tarjeta expandida (primeras 12 de 19 filas)

```text
  ✓ 15 puertos abiertos · 1 hosts up · 12.4s
  └ Host up: 45.33.32.156
  └ Puerto 21/tcp open: ftp
  └ Puerto 22/tcp open: ssh
  └ Puerto 25/tcp open: smtp
  └ Puerto 80/tcp open: http
  └ Puerto 110/tcp open: pop3
  └ Puerto 143/tcp open: imap
  └ Puerto 443/tcp open: https
  └ Puerto 993/tcp open: imaps
  └ Puerto 995/tcp open: pop3s
  └ Puerto 3306/tcp open: mysql
```

### A.4 Payload estructurado (40 campos) — D7

```text
✓ generate: resultado estructurado · 40 campo(s) · Ver 42 líneas más
```

### A.5 `/status show` — D2

```text
session ab12cd/ssh | ▸ Enumeration 3/7 | BAJIOWARE · OMNI-AGENTCS | Alcance: 7 objetivos |
Modelo: deepseek/v4 | Tokens: 49,500 | Presupuesto: $5.00 | Estado: INACTIVO | ctx ~?% |
run 49.5k tok | ~$0.9100 | 0s | 42 datos | AcmeCorp
```

(los saltos de línea son del informe; `render_status_plain` devuelve una sola línea).

### A.6 Barra dentro de workspace — D3

```python
FormattedText([('ansimagenta', 'session ab12cd/ssh')])
```

---

## 11. Anexo B — comandos reproducibles

```bash
# Suite TUI completa
.venv/bin/python -m pytest nexus_core/tests/unit/test_tui_*.py -q -p no:cacheprovider

# Integridad en PTY real (frontera única de escritura)
.venv/bin/python -m pytest nexus_core/tests/integration/test_tui_pty_integrity.py -q -p no:cacheprovider

# Renders del informe
.venv/bin/python - <<'PY'
from rich.cells import cell_len
from nexus_core.cli.tui.stream import render_tool_result, format_tool_invocation
from nexus_core.cli.tui.status import StatusState, render_status_plain, render_status_bar

ports = [{'port': p, 'protocol': 'tcp', 'state': 'open', 'service': s} for p, s in
         [(21,'ftp'),(22,'ssh'),(25,'smtp'),(80,'http'),(110,'pop3'),(143,'imap'),(443,'https'),
          (993,'imaps'),(995,'pop3s'),(3306,'mysql'),(5432,'postgresql'),(6379,'redis'),
          (8080,'http-proxy'),(8443,'https-alt'),(9200,'elasticsearch')]]
scan = {'hosts': [{'state':'up','ip':'45.33.32.156','ports':ports}], 'hosts_up':1, 'elapsed_seconds':12.4}
r = {'success': True, 'tool_id':'nexus.recon.nmap',
     'evidence':{'ports_open_total':15,'hosts_up':1,'elapsed_seconds':12.4},
     'output':{'scan':scan}}
line = render_tool_result(r, width=100, no_color=True)
print(line); print('celdas:', cell_len(line))

st = StatusState(workspace_path='/tmp', session_uuid='ab12cd', session_type='ssh',
                 provider_model='deepseek/v4', tokens_input=41200, tokens_output=8300,
                 cost_usd=0.91, scope_targets=7, budget_usd=5.0, facts_count=42,
                 plan_phase='Enumeration', plan_progress='3/7')
print(render_status_plain(st))
print(render_status_bar(st, width=120))
PY
```

---

## 12. Anexo C — qué cubre y qué no cubre la suite visual

| Fichero | Qué fija | Hueco |
|---|---|---|
| `test_tui_stream_render.py` | Una fila colapsada, JSON diferido, diff, guardrail | No hay aserción de ancho (D1) |
| `test_tui_status.py` | Prioridad, caída, truncado por celdas | Ningún test fija `workspace_path`: la rama real queda sin probar (D3) |
| `test_tui_theme.py` | Sin hex en `presentation`/`layout`; roles | No cubre `panels`/`status` (D4) |
| `test_tui_typewriter.py` | La revelación es aditiva; `NEXUS_TUI_TYPEWRITER=0` se prueba en una sesión en vivo (`:149-155`) | — |
| `test_tui_flicker_regression.py` | Sin `erase_screen` durante una tool; ≤4 repintados por ráfaga | — |
| `test_tui_pty_integrity.py` | Integridad de cursor y logs dentro del router | Un solo escenario (INFO line) |
| `test_tui_retention.py` | Acotado del transcript | — |
| `test_tui_panels.py` | Panel lateral | Ancho por celdas no probado (D5) |

**Cierre.** La capa visual de OMNI está por delante de cómo la describe el plan que se pegó. Lo que falta no es una «cara»: es coherencia (D4), honestidad de métricas (D2, D3, D10), medición de ancho (D1, D5) y duración por tool (D8). Con D1–D3 resueltos, la capa visual deja de tener defectos que el operador vea en cada turno; el resto es pulido priorizable.
