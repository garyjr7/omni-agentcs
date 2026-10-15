# FASE1_UX_UI_BRANDING.md — Fase 1: UX/UI y Branding de la TUI

Estado: completa y auditada · Fecha: 2026-10-06 · Rama de trabajo: `feat/sliver-bridge`
(working tree, sin commit) · Autor: BAJIOWARE

> Documento *docs-as-code*: registra el **porqué** de cada decisión de la Fase 1,
> no solo el **qué**. Es la fuente de verdad para quien retome el proyecto.

---

## 1. Resumen ejecutivo

### 1.1 De dónde viene

La Fase 1 ataca los hallazgos de presentación de `AUD_OMNI_BW.md` y de
`TUI_UX_AUDIT.md`:

| Hallazgo | Descripción | Resolución en Fase 1 |
| --- | --- | --- |
| **H4** | Redundancia en la TUI: el engagement (y el modelo) aparecían a la vez en la cabecera, el prompt y la barra de estado. | Cabecera compacta como **única** fuente; prompt minimalista con *chips*; engagement degradado a segmento de menor prioridad. |
| **H9** | Markdown parcial y un único tema; jerarquía visual pobre. | Jerarquía explícita del transcript por glifos y colores; tarjetas colapsables con respiro. |
| **H14** | Marca antigua (NEXUS) e i18n incoherente. | Branding **BAJIOWARE · Team Red**, `LICENSE`, `CHANGELOG` y avisos legales en español. |

### 1.2 Qué cambió (una frase por área)

1. **Cabecera** (`cli/banner.py`): de un bloque ASCII gigante a una **cabecera de
   3 líneas** con marca, scope/validez y sandbox+auditoría; el arte ASCII se
   conserva bajo demanda (`--about` / `--banner`).
2. **Redundancia** (`cli/session.py`, `cli/tui/status.py`): el engagement y el
   modelo salen del prompt y del centro de la barra; el prompt pasa a `└─$ ` con
   *chips* contextuales solo cuando aplican.
3. **Barra de estado** (`cli/tui/status.py`): pasa de "truncar por la derecha" a
   **descartar por prioridad**, con `alert` y `phase` **protegidos**.
4. **Transcript** (`cli/tui/stream.py`, `cli/tui/session.py`): glifo `⚙` para
   invocaciones y `\n\n` de respiro entre tarjetas.
5. **Marca y legales**: `LICENSE`, `CHANGELOG.md`, `README.md`, aviso en el
   wizard y flags `--about`/`--banner`.

### 1.3 Invariante de diseño (lo que la Fase 1 **no** tocó)

La Fase 1 es **presentación pura**. No modifica ninguna ruta de gobernanza: el
scope firmado (`nexus_core/scope/`), la cadena de auditoría
(`kernel/audit.py`), las aprobaciones durables (`kernel/approvals.py`) y la regla
de oro "un modelo propone, nunca afirma éxito" (post-condición determinista en
`kernel/tool_gateway.py`) siguen intactos. La cabecera y la barra **solo leen**
estado ya existente; nunca escriben en el registro durable.

---

## 2. Cabecera compacta (`nexus_core/cli/banner.py`)

### 2.1 Antes / después

- **Antes**: arte ASCII de 7 líneas + bloque de stats `=[ ... ]` en cada arranque.
  Ocupa ~10 líneas de scrollback antes de que el operador vea el prompt.
- **Ahora** (`build_header`, por defecto): 3 líneas de caja + 1 tip, con los
  valores que importan al arrancar.

```
╭─ BAJIOWARE · OMNIAGENTCS ── Team Red ◈ ── scanme-lab ───────────────╮
│ scope  1 CIDR · 1 dominio · 0 URLs          hasta 2026-10-07T14:00Z │
│ sandbox local_strict (sin aislamiento de red)            audit ✓ ok │
╰──────────────────────────────────────────────────────────────────────╯
 Tip: Use /report to generate a client-ready report with CVSS and MITRE.
```

### 2.2 Piezas nuevas

- `BRAND = "BAJIOWARE"` y `TEAM_RED = "Team Red ◈"`: identidad del producto y del
  equipo (Team Red) en la línea superior, en `AQUA`/`RED` + `BOLD`.
- `SANDBOX_NOTES: dict[str, str]`: traduce el modo de sandbox a una **garantía
  legible** (`local_strict → "sin aislamiento de red"`, `oci → "container aislado
  · sin red"`, …). Nunca se afirma más aislamiento del que existe.
- `describe_scope(scope)`: produce `"1 CIDR · 1 dominio · 0 URLs"` (y
  `"N exclusión/es"` si hay exclusiones). Devuelve `""` cuando no hay engagement,
  para no duplicar el texto `sin engagement` de la cabecera.
- `build_header(...)`: filas `╭─ … ╮ / │ … │ / │ … │ / ╰─ … ╯` mediante
  `_top`, `_row`, `_bottom`, `_fit`. La columna derecha alinea `hasta <valid_until>`
  y `audit ✓ ok | ✗ INVALID`.
- `build_banner(..., compact=True, scope_summary=..., valid_until=...)`: fachada
  única. `compact=False` delega en `_build_art_banner(...)`.

### 2.3 Preservación del arte ASCII

El arte legacy (`BANNER_ASCII`, ~7 líneas con el tagline `A G E N T C S · C L I`)
se movió a `_build_art_banner(...)` y solo se construye con `compact=False`, es
decir:

- `omni --about`: `_render_about(...)` en `cli/main.py` imprime arte + stats y
  sale.
- `omni --banner`: pasa `show_art_banner=True` a `OmniSession`, que llama a
  `build_banner(..., compact=not self.show_art_banner)`.

El arte se omite por debajo de `MIN_WIDTH_FOR_ART = 80` columnas; el bloque de
stats sobrevive (degradación útil en terminales pequeñas).

### 2.4 Modo sin color

`no_color` propaga a `_paint`/`_highlight`: en modo plano no se emite ningún
`ANSI`, y los marcadores no-ASCII se sustituyen por texto
(`audit ok` / `audit INVALID` en lugar de `✓` / `✗`). Esto mantiene el banner
copiable-pegaable y compatible con `NO_COLOR`.

---

## 3. Eliminación de redundancia (`cli/session.py`, `cli/tui/status.py`)

### 3.1 El problema

Antes, el nombre del engagement se repetía en **tres** sitios simultáneos:
cabecera, cadena del prompt y barra de estado. Además el prompt truncaba el
nombre con `MAX_PROMPT_ENGAGEMENT_NAME`, lo que generaba ambigüedad cuando el
engagement cambiaba (`/engagement …`) y el truncado difería entre sitios.

### 3.2 Prompt minimalista con *chips* (`OmniSession.prompt`)

```python
trust   = "─" + paint("[TRUST MODE]", RED, BOLD)          if self.trust_mode else ""
session = "─" + paint("[session <uuid>/<kind>]", MAGENTA)  # o [sliver:<id>/<kind>]
report  = "─" + paint("[report <dir>]", BLUE)              if self.last_report_directory
chips   = f"{trust}{session}{report}".lstrip("─")
return f"{chips}\n└─$ " if chips else "└─$ "
```

Reglas:

- El prompt base es **siempre** `└─$ ` (barato, estable, greppable).
- Los *chips* solo aparecen cuando el estado **transitorio** está activo: trust
  mode, sesión adjunta y último reporte. No repiten nada de la cabecera.
- El color se aplica **alrededor** de cada token, nunca dentro, de modo que los
  substrings planos `[TRUST MODE]` y `[session <uuid>/<type>]` permanecen
  intactos y siguen siendo localizables en logs.
- Se **eliminó** la constante `MAX_PROMPT_ENGAGEMENT_NAME`: ya no hay nombre que
  truncar en el prompt.

### 3.3 La barra deja de ser la fuente del engagement

El engagement pasa a ser el segmento de **mínima prioridad** (`PRIORITY["engagement"] = 0`)
en la barra: si no cabe, cae primero, porque la cabecera ya lo muestra. Esto es
intencional (ver §8, Notas de desviación).

### 3.4 Línea del objetivo en la TUI

`run_objective` dejó de escribir `🤖 [OmniAgent]: {objective}` y ahora escribe:

```python
self._output.write("\n" + render.paint(f"❯ {objective}", render.WHITE))
```

El glifo `❯` (blanco) marca "esto lo pidió el operador", y contrasta con `💭`
(razonamiento del modelo, rojo) y `⚙` (invocación de herramienta, aqua). El
emoji de robot competía visualmente con el propio agente.

---

## 4. Barra de estado con prioridad (`nexus_core/cli/tui/status.py`)

### 4.1 Prioridades

```python
PRIORITY = {
    "alert": 7,       # TRUST MODE / sesión adjunta  → nunca se descarta
    "phase": 6,       # fase del kill-chain + progreso → nunca se descarta
    "provider": 5,
    "tokens": 4,
    "cost": 3,
    "time": 2,
    "facts": 1,
    "engagement": 0,  # ya está en la cabecera → cae primero
}

#: Segmentos que deben sobrevivir a cualquier ancho (se truncan como último
#: recurso, nunca se eliminan).
PROTECTED_PRIORITIES = frozenset({PRIORITY["alert"], PRIORITY["phase"]})
```

Cada segmento se construye como `(priority, style, text)` y se ordena de
izquierda a derecha por importancia: `alert · phase · provider · tokens · cost ·
time · facts · engagement` (más el spinner `busy`, prioridad 8, cuando trabaja).

### 4.2 Lógica de descarte (pseudocódigo real)

```
render_status_bar(state, width):
    items = _parts(state)                       # lista de (prioridad, estilo, texto)
    mientras len(items) > 1 y ancho(items) > width:
        descartables = [i for i in items si items[i].prioridad ∉ PROTECTED]
        si descartables está vacío: break       # solo quedan protegidos → truncar
        items.pop(índice de menor prioridad en descartables)

    # Segundo pase: truncado por celda, nunca por carácter (respeta CJK/emoji).
    remaining = width
    por cada carácter: si get_cwidth(char) > remaining → devolver lo acumulado
    devolver FormattedText(fragmentos)
```

Propiedades garantizadas:

1. **`alert` y `phase` nunca se descartan**; como mucho se truncan por celda
   cuando ya no queda nada más que tirar.
2. El ancho renderizado **nunca excede `width`** (truncado por `get_cwidth`, no
   por `len`, por lo que `界` cuenta 2 celdas).
3. El segmento con prioridad 0 (`engagement`) es el primero en caer.
4. `render_status_plain(state)` conserva **todos** los segmentos en orden (lo usa
   `/status show`): la versión de una línea para copiar/pegar.

---

## 5. Jerarquía del transcript (`cli/tui/stream.py`, `cli/tui/session.py`)

### 5.1 Tabla de glifos

| Glifo | Significado | Emisor | Color |
| --- | --- | --- | --- |
| `❯` | Objetivo / eco del operador | `session.run_objective` | `WHITE` |
| `💭` | Razonamiento del modelo (una iteración ReAct) | `stream.render_thought` | `RED` |
| `⚙` | Invocación de herramienta | `stream.format_tool_invocation` | `AQUA` |
| `->` | Línea de datos del resultado | `stream.render_tool_result` | `OFFWHITE` |
| `✓` | Post-condición **verificada** | `stream.render_tool_result` | `GREEN` |
| `✗` | Fallo / post-condición no cumplida | `stream.render_tool_result` | `RED` |
| `⚠` | Aprobación humana / trust mode / kill | `tui/panels.py`, `render.py` | `YELLOW` |
| `▼` / `▲` | Expandir / colapsar tarjeta | `stream.render_tool_result` | `AQUA` |
| `▶` / `✓` / `·` | Fase del plan (actual/hecha/pendiente) | `tui/panels.py` | — |

Lectura vertical del transcript: **intención** (`💭`, rojo) → **acción**
(`⚙`, aqua) → **evidencia** (`->` + `✓`/`✗`). El humano ve el *porqué* antes del
*qué*, y la evidencia determina el color del veredicto.

### 5.2 Reglas de espaciado

- El bloque de pensamiento se emite **antes** de la invocación que justifica.
- La invocación de herramienta usa `⚙` en aqua + tag dim (`[Recon-NMAP]`) + línea
  de comando aqua: el glifo ancla la vista, el tag es contexto secundario.
- Las tarjetas de resultado (`render_tool_result`) cierran con un pie clicable
  (`▼ mostrar N línea(s) más` / `▲ mostrar menos`); el resumen y el marcador de
  éxito **siempre** se muestran, incluso colapsados.
- `TuiSession._card_text` añade `"\n\n"` al final de cada tarjeta: **un respiro**
  entre resultados consecutivos evita el efecto "bloque de texto".

---

## 6. Marca y legales

- **`LICENSE`** (nuevo): licencia propietaria *"Authorized Use Only"* de
  BAJIOWARE. Sección 1 (uso autorizado) y sección 2 (usos prohibidos) dejan por
  escrito que la herramienta es solo para pentest/red-team **con permiso escrito**.
- **`CHANGELOG.md`**: renombrado a OmniAgentCS; `v3.0.0` describe el rename y la
  cabecera BAJIOWARE/Team Red; `v2.0.0` se conserva etiquetado como
  *"lineage NEXUS"* para no perder la historia.
- **`nexus_core/cli/wizard.py`**: tras la bienvenida se imprime el bloque
  `AVISO · USO AUTORIZADO ÚNICAMENTE` (solo sobre objetivos con permiso escrito;
  el usuario es responsable).
- **`README.md`**: cabecera, prompt `└─$ `, barra de estado por prioridad, tabla
  de glifos y flags `--about` / `--banner`.
- **`cli/main.py`**: flags nuevos `--about` (arte ASCII + stats y salir) y
  `--banner` (arte ASCII al arrancar el REPL). `_render_about(...)` resuelve el
  engagement igual que el REPL.

---

## 7. Evidencia de verificación

### 7.1 Suite completa

```
$ .venv/bin/python -m pytest nexus_core/tests/unit -q
1 failed, 1747 passed, 1 skipped, 1 warning in 33.48s
```

Cifra de referencia al abrir la Fase 1: **1742 passed**. Tras la auto-auditoría
(§9) sube a **1747** por 5 tests nuevos.

### 7.2 El fallo preexistente (`test_installer.py`) es **ajeno** a esta fase

```
FAILED nexus_core/tests/unit/test_installer.py::test_update_shell_path_idempotent
E  FileNotFoundError: '/tmp/pytest-of-kali/.../home/.bashrc'
```

Motivo: el test lee `(managers.home / ".bashrc")` pero
`provisioner/installer.py::update_shell_path` resuelve `Path.home()` real, que
bajo pytest no coincide con el home simulado del *fixture*. `installer.py` **no
está en el diff** de la Fase 1 (`git diff --stat` §7.4) y el fallo se reproduce en
`HEAD` sin cambios locales. Se deja fuera del alcance de la Fase 1 a propósito.

### 7.3 Ruff y compilación

```
$ .venv/bin/ruff check <7 archivos tocados> --select F,E9
All checks passed!

$ .venv/bin/python -m compileall -q nexus_core/cli
(OK)
```

Sobre el conjunto **completo** de reglas, la comprobación se hizo archivo por
archivo contra `HEAD` con `git show HEAD:<file> | ruff check --stdin-filename <file> -`:
el número de hallazgos es **idéntico antes y después** en cada archivo tocado
(p. ej. `session.py` 11 → 11, `tui/session.py` 3 → 3, `banner.py` 0 → 0). Es
decir, la Fase 1 **no introduce deuda de lint nueva**; el ruido restante es el
baseline preexistente del repo (583 hallazgos en total, en su mayoría estilo
`UP`/`I`).

### 7.4 Superficie del cambio

```
$ git diff --stat
 CHANGELOG.md                                       |  15 +-
 README.md                                          |  65 +++----
 nexus_core/cli/banner.py                           | 215 +++++++++++++++++++--
 nexus_core/cli/main.py                             |  44 +++++
 nexus_core/cli/session.py                          |  31 +--
 nexus_core/cli/tui/session.py                      |   4 +-
 nexus_core/cli/tui/status.py                       | 108 +++++++++--
 nexus_core/cli/tui/stream.py                       |   4 +-
 nexus_core/cli/wizard.py                           |   7 +
 nexus_core/tests/unit/test_cli_banner.py           | 116 ++++++++++-
 nexus_core/tests/unit/test_cli_banner_integration.py | 28 ++-
 nexus_core/tests/unit/test_cli_prompt_polish.py    |  21 +-
 nexus_core/tests/unit/test_cli_session.py          |   9 +-
 nexus_core/tests/unit/test_cli_shell_polish_regression.py | 3 +-
 nexus_core/tests/unit/test_tui_integration.py      |   2 +-
 nexus_core/tests/unit/test_tui_regression.py       |   6 +-
 nexus_core/tests/unit/test_tui_status.py           |  49 ++++-
 nexus_core/tests/unit/test_tui_visual_startup.py   |   1 +
 18 files changed, 617 insertions(+), 111 deletions(-)
```

### 7.5 Aviso de fallo preexistente no relacionado con la suite

`nexus_core/tools/handlers/knowledge_facts.py:11` tiene un `F401 typing.Any`
**preexistente** que no se toca (ajeno a la fase).

---

## 8. Notas de desviación (auditoría → implementación)

| Sugerencia de la auditoría | Implementado | Motivo |
| --- | --- | --- |
| Quitar el engagement de la barra de estado | **Parcial**: se mantiene como segmento de **prioridad 0** | Mantener acceso rápido (accesibilidad): en terminal estándar se ve; bajo presión de ancho cae primero. La cabecera sigue siendo la fuente canónica. |
| Sustituir el arte ASCII por un logo/emoji | **No**: arte preservado tras `--about`/`--banner` | El arte es parte del *feel* del producto; solo se evita en el arranque por defecto (scrollback). |
| Cablear `cli/face.py` (cara cyborg/máscara) al arranque | **No** | `face.py` es truecolor de 100×24 celdas, demasiado ancho para el valor que aporta; se mantiene como módulo independiente (`python -m nexus_core.cli.face`) y como recurso para `--about`. Ver §10. |
| `no_color` solo por variable global | **Mixto**: parámetro explícito + estado global | El banner acepta `no_color` explícito para tests deterministas y respeta el estado global de `render` para el uso real. |
| i18n completo (H14) | **Fuera de alcance** | Se priorizó coherencia de marca y legales; el i18n sistemático pertenece a una fase de producto posterior. |

---

## 9. Auto-auditoría de cierre

### 9.1 ¿Hay casos borde a 60 columnas?

**Sí, se encontró uno y se corrigió.** `build_header` usaba
`DEFAULT_HEADER_WIDTH = 68` fijo cuando `width=None` (el caso del REPL real, que
no pasa `width`). En un terminal de 60 columnas la cabecera medía 68 y **envolvía**.

Corrección (cambio mínimo, `banner.py`):

```python
if width is None:
    # Follow the real terminal so a narrow window never wraps the header,
    # but never grow past the designed width on a very wide one.
    total = max(40, min(DEFAULT_HEADER_WIDTH, _terminal_width() - 2))
else:
    total = max(40, min(100, int(width) - 2))
```

Resultado a 60 columnas (58 de ancho, sin wrap):

```
╭─ BAJIOWARE · OMNIAGENTCS ── Team Red ◈ ── scanme-lab ──╮
│ scope  1 CIDR · 1 dominio · 0 URLs hasta 2026-10-07T1… │
│ sandbox local_strict (sin aislamiento de red) audit ok │
╰────────────────────────────────────────────────────────╯
```

Cobertura: `test_header_follows_narrow_terminal_when_width_unspecified` (60 cols)
y `test_header_never_grows_past_designed_width` (terminal ancho → sigue en 68).

### 9.2 ¿El test de propiedad de la barra cubría todos los anchos?

**No.** Antes solo había un ancho puntual
(`test_status_drops_engagement_first_when_narrow`, width=16). Se añadieron tres
tests:

- `test_status_alert_and_phase_survive_every_width`: barre `width ∈ [mínimo, 120]`
  y exige que `TRUST` (alert) y `▸ Recon 1/5` (phase) **nunca** se pierdan.
- `test_status_never_exceeds_width_for_any_width`: barre `width ∈ [0, 200]` con un
  estado denso (alerta, sesión, fase, tokens, coste, facts, engagement) y exige
  que el ancho renderizado **nunca** exceda `width`.
- `test_status_drops_droppable_before_protected`: a width=20, el proveedor
  (descartable) cae y los protegidos sobreviven.

Para que estas propiedades sean **ciertas**, se introdujo `PROTECTED_PRIORITIES`:
antes, con alerta presente y ancho mínimo, el bucle de descarte podía eliminar
`phase` (menor prioridad que `alert`). Ahora `alert` y `phase` están excluidos del
descarte y solo se truncan por celda (ver §4.2).

### 9.3 ¿Quedan `TODO`/comentarios temporales?

**No.** `rg "TODO|FIXME|XXX|HACK" nexus_core/cli` → **0 coincidencias**.

### 9.4 Mejoras obvias de bajo riesgo implementadas en esta auditoría

| Mejora | Archivo | Test |
| --- | --- | --- |
| Cabecera se adapta al ancho real del terminal (antes: 68 fijo) | `cli/banner.py` | `test_header_follows_narrow_terminal_when_width_unspecified`, `test_header_never_grows_past_designed_width` |
| `alert`/`phase` protegidos del descarte (antes: `phase` podía caer) | `cli/tui/status.py` | `test_status_alert_and_phase_survive_every_width` |
| Barrido de anchos 0–200 sin overflow | (tests) | `test_status_never_exceeds_width_for_any_width` |
| Precedencia descartable vs. protegido | (tests) | `test_status_drops_droppable_before_protected` |

Total: **2 correcciones de código + 5 tests**. Suite intacta salvo el fallo
preexistente de `test_installer.py`.

### 9.5 Riesgos residuales / traspaso a fases siguientes

- **H1 (prompt injection)**: la Fase 1 **no** endurece el canal de observación;
  el `system prompt` y `_inject_observation` son el objetivo de la Fase 2.
- **H3 (sandbox)**: la cabecera ya **muestra** el modo y su garantía, pero el
  aislamiento en sí (red/FS/usuario) y `~/.local/bin` en el PATH del sandbox
  pertenecen a la Fase 2.
- **H8 (headless)**: `--json` sigue existiendo solo para `--doctor`/`--setup`.
- **i18n**: aplazado (ver §8).

---

## 10. Anexo — `cli/face.py`

`nexus_core/cli/face.py` (nuevo, sin trackear) renderiza una cara partida
(cyborg | máscara Anonymous) con *half-blocks* Unicode y color 24-bit, definida
por matemáticas puras (sin assets externos). **No se importa desde el banner**: se
ejecuta de forma independiente (`python -m nexus_core.cli.face [--no-color]`) y
queda disponible como recurso para `--about`/easter egg. Cualquier cableado al
arranque requeriría decidir ancho/altura y coste de render; se deja fuera de la
Fase 1.

---

## 11. Cierre

Fase 1 implementada, verificada y auditada. Sin regresiones en la suite
(1747 passed, solo el fallo preexistente de `test_installer.py`), sin deuda de
lint nueva y sin `TODO`s. La gobernanza verificable —el foso competitivo— quedó
intacta.

**Fase 1 documentada y auditada. Lista para Fase 2.**
