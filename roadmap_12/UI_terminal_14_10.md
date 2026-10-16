# Interfaz de terminal — 14 de octubre de 2026

La CLI incorpora renderables de Rich dentro de su TUI existente. En este repositorio `nexus_core/cli/tui` es un paquete, no un archivo `tui.py`. Prompt-toolkit conserva la propiedad del cursor, el editor, la pantalla y las actualizaciones; Rich genera texto formateado en memoria.

## Estructura actualizada

```text
nexus_core/cli/
├── session.py              # Estado operacional, eventos, entradas y fallos
├── commands.py             # /history, /expand y /status
└── tui/
    ├── presentation.py     # Renderables Rich, plegado, chips, diffs y spinner
    ├── stream.py           # Adaptación de resultados y mensajes a tarjetas
    ├── session.py          # Tarjetas interactivas, pensamiento y refresco
    ├── status.py           # Barra fija, prioridades y anchura en celdas
    ├── paste.py            # Referencias de pegado y reconstrucción íntegra
    └── output.py           # Router único y decorador que conserva firmas
```

## Comportamiento

| Área | Implementación |
|---|---|
| Salidas largas | Más de seis líneas: tres iniciales, tres finales y `[ Show N more lines ]`. Clic en el pie expande únicamente esa tarjeta; `/expand on` y `/expand off` actúan sobre todas. Se conservan stdout y stderr. |
| Pensamiento | `• Thinking...` en estilo tenue. Resumen de una línea, tarjeta expandible y overlay durante el streaming. |
| Actividad | `rich.spinner.Spinner` se muestrea dentro del bucle existente. Refresco activo y límite de redibujado de 0,1 segundos. Los eventos actualizan `Working` o `Executing <tool_id>`. No se inicia otro escritor `Live` ni se borra la pantalla por fotograma. |
| Entradas largas | Más de 500 caracteres: `[ 📋 Pasted Input · 10,778 characters ]`. Se compactan el eco, el objetivo visible y `/history`; el contexto y la persistencia conservan el texto íntegro. El editor mantiene expansión, eliminación, undo y recuperación de pegados. |
| Fallos | `× failed · <tool_id>` seguido de detalle legible. Se eliminan controles de terminal del texto no confiable y se conserva el layout. |
| Diffs | `rich.syntax.Syntax` con lexer `diff`, adiciones verdes y eliminaciones rojas. Acepta `diff`, `patch` o contenido explícito `before`/`after`. No lee archivos ni inventa cambios cuando solo existe una referencia de artefacto. |
| Barra inferior | `BAJIOWARE · OMNI-AGENTCS | Scope: N targets | Model: provider/model | Tokens: X | Budget: $Y | Status: IDLE/RUNNING`. Prioridades y recorte por celdas mantienen el ancho; los avisos de confianza/sesión y fase conservan su protección. |

`Scope` cuenta entradas configuradas únicas entre CIDR, dominios y URLs; no enumera hosts de una subred. `Budget` muestra un presupuesto monetario proporcionado explícitamente al estado de presentación. Si no existe, muestra `$—`: no se deduce del gasto ni convierte tokens a dólares. `/status show` conserva el detalle de gasto estimado y otros contadores. Este cambio visual no añade un control financiero al motor.

## Fragmentos de implementación

```python
@dataclass(frozen=True)
class FoldedLines:
    head: tuple[str, ...]
    tail: tuple[str, ...]
    hidden: int

# limit=6: tres líneas iniciales y tres finales.
folded = fold_lines(stdout, expanded=False, limit=6)
```

```python
# Rich produce una cadena en memoria. La aplicación TUI la dibuja.
text = indicator.frame(
    "Executing nexus.workspace.read",
    now=time.monotonic(), elapsed=3, width=100, no_color=False,
)
```

```python
# Solo cambia la representación. El texto original sigue siendo la entrada.
visible = render_rich(input_chip(original_input), no_color=True)
```

## Configuración y compatibilidad

- Rich se declara en `pyproject.toml` y `nexus_core/requirements.txt` como `rich>=13,<15`; las pruebas utilizaron 14.3.4.
- `NEXUS_PASTE_CHARS` conserva su ajuste; el valor predeterminado pasa a 500. El eco de entradas largas se compacta independientemente de cómo se hayan introducido.
- `NO_COLOR`, `--no-color`, `--no-tui` y la salida redirigida siguen disponibles. `CI=1/true/yes` desactiva la selección automática de TUI y el spinner del flujo CLI.
- El modo sin TUI usa salida estática. Los indicadores de plegado no son botones en un log de CI; los resultados íntegros siguen en la persistencia del motor.
- Se tiparon los renderizadores y sus adaptadores, incluidos los valores de retorno `StyleAndTextTuples`, el modelo de pegados y el decorador genérico de routing. Mypy usa las anotaciones publicadas de Rich y prompt-toolkit.

## Validación

- Regresión CLI/TUI: **576 pruebas aprobadas**.
- Pseudo-terminal real: **1 prueba aprobada**; logs dentro del router, sin duplicación fuera del panel.
- Mypy estricto: **9 archivos sin errores** — ocho módulos de producción y la nueva suite `test_tui_rich_presentation.py`.
- **63 pruebas focalizadas aprobadas** después de los últimos ajustes; registradas en `evidencia_ui_terminal/focalizadas.log`.

Las pruebas utilizan fixtures, pipes y una pseudo-terminal local. No ejecutan herramientas ofensivas ni contactan objetivos. El informe describe esta entrega de UI; no certifica el cierre de la auditoría previa del kernel.

Evidencias: [regresión](evidencia_ui_terminal/regresion.log), [mypy](evidencia_ui_terminal/mypy.log), [PTY](evidencia_ui_terminal/pty.log). Vista ilustrativa: [UI_terminal_preview.txt](UI_terminal_preview.txt).
