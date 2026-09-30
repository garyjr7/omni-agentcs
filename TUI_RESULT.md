# Migración TUI: resultado final

Rama: `feat/tui-prompt-toolkit`. Fecha: 2026-09-30.

La migración pendiente quedó integrada y validada junto con los fixes
visuales. Los bloqueos de las corridas anteriores están resueltos.

- prompt_toolkit 3.0.53 instalado y declarado en ambos requirements.
- Entrada inferior, panel de salida y barra persistentes en aplicación con
  loop dedicado; historial XDG compatible con readline y fallback completo.
- `/status`, preferencias XDG, `--no-tui`, `NEXUS_NO_TUI`, modo busy y
  routing de salidas del daemon implementados.
- Color y logging corregidos sin modificar kernel, scope, agent, tools ni
  integrations. Banner y respuestas aparecen una sola vez en el panel.
- Ocho regresiones visuales añadidas; 74 tests de TUI y /status pasan.
- Suite completa con NO_COLOR=1: **925 passed, 18 skipped in 39.72s**.
- Suite completa sin NO_COLOR: **925 passed, 18 skipped in 43.48s**.
- Los 847 tests originales siguen pasando. Ruff F/E9 y diff check limpios.
- Verificación interactiva en PTY tmux de 120×35, con y sin color: un banner,
  cero INFO, `/status` responde una sola vez, input fila 34, barra fila 35.
- Fallback por pipe verificado con `/help`, `/status` y `/exit`.

El panel usa la pantalla alternativa y no se vuelca por segunda vez al
cerrar; `/history` y `/export` permiten consultar/conservar la conversación.
El coste necesita tarifas configuradas; sin ellas, las respuestas cloud
muestran n/d. Fake/Ollama tienen coste de API cero. Los tokens proceden de
respuestas reales, con persistencia de consumo ReAct por run desde CLI y
estadísticas locales para `/ask`.

El reconocimiento original se conserva en `TUI_RECON.md`; sus referencias
son al código base. El fix ambiental está en `FIX_ENV_RESULT.md`.
El informe detallado, las capturas y la evidencia del resultado definitivo
están en `TUI_FIX_RESULT.md`. No se hizo push.
