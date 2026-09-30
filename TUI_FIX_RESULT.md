# Fix visual del arranque de OmniAgentCS

Rama: `feat/tui-prompt-toolkit`. Fecha: 2026-09-30.

## Resultado

Corregidos el banner duplicado, el logging anterior al banner y la intensidad
del ASCII. Verificado con tests y con el REPL real en terminales PTY de tmux,
de 120 columnas por 35 filas, con color y con `--no-color`.

No se modificaron kernel, scope, agent, tools ni integrations. No se hizo
push. El commit de esta entrega incluye la migración TUI que permanecía sin
commit en el directorio de trabajo y estos fixes visuales.

## Cambios

1. `run_repl` activa `patch_stdout`, limpia mediante el backend de terminal,
   prepara el banner, actualiza el estado y comienza a leer. `clear_screen`
   no hace nada en fallback. El panel es la única salida de la TUI: sus
   mensajes no se imprimen también en la pantalla principal. Esto corrige
   tanto el banner inicial como la duplicación de respuestas a `/status`.
2. `omni.main` configura logging antes de cargar `.env` y antes de
   onboarding/creación de clientes. Reaplica la política después de `.env`
   para respetar una preferencia definida allí. `_llm_stats` sigue leyendo
   exclusivamente el entorno y `build_banner` recibe todos sus datos.
3. El ASCII y su leyenda usan el color predeterminado del terminal, sin
   negrita. El código anterior usaba cyan normal más negrita, no SGR 96;
   quitar ambos evita que la paleta brillante dependa del emulador.
4. Corregido el aislamiento del test de detección TTY pendiente: pytest
   cambia stdout entre setup y ejecución. La fixture ahora sustituye las
   referencias de streams del módulo y conserva intacta la captura de pytest.

En la TUI, al salir se restaura la pantalla anterior sin volver a imprimir el
panel completo. `/history` y `/export` permiten consultar o conservar la
conversación. El fallback mantiene su salida tradicional y omite el banner
cuando stdout no es un terminal.

## Regresiones reproducidas antes del fix

Archivo: `nexus_core/tests/unit/test_tui_visual_startup.py`.

- Banner emitido físicamente además de almacenarse en el panel.
- Orden incorrecto entre patch, limpieza, banner, estado y primer prompt.
- Log `[INFO] Groq client created` antes del banner. Se comprobó contra el
  entry point anterior cargado en memoria, sin revertir archivos del fix.
- ASCII con secuencias de color/negrita.
- Respuesta `/status` emitida físicamente y también dibujada en el panel.

También se comprueban la ausencia de creación de clientes al contar
proveedores, la limpieza mediante el backend y el no-op en fallback.
**Los ocho tests del archivo pasan.** El total de tests TUI y `/status`
es **74 passed in 4.66s**.

Logs de reproducción: `/tmp/tui-visual-before.txt`,
`/tmp/tui-log-before.txt`, `/tmp/tui-duplicate-output-before.txt`.
La prueba de logging necesitó corregir su mock del módulo `main` antes de
obtener la reproducción real del INFO; no se contó ese error de mock como
prueba del bug del producto.

## Verificación final

```text
NO_COLOR=1 .venv/bin/python -m pytest nexus_core/tests -q
======================= 925 passed, 18 skipped in 39.72s =======================

env -u NO_COLOR .venv/bin/python -m pytest nexus_core/tests -q
======================= 925 passed, 18 skipped in 43.48s =======================
```

Los 847 tests originales siguen pasando, junto con cuatro casos ambientales,
66 casos de migración TUI y ocho regresiones visuales. Los 18 omitidos ya
estaban omitidos en la base.

Ruff `--select F,E9` sobre CLI, `omni.py`, conftest y tests nuevos:
`All checks passed!`. `git diff --check`: sin errores.

Logs definitivos: `/tmp/tui-fix-final-color-tests.txt`,
`/tmp/tui-fix-final-no-color-tests.txt`,
`/tmp/tui-visual-targeted-final.txt`.

## Terminal interactiva: descripción y captura

Se ejecutó el proceso real, con stdin/stdout TTY, dentro de tmux y `script`;
no se usó DummyOutput para esta comprobación. No hay un emulador gráfico
adjunto ni una captura de píxeles: la evidencia es la pantalla de terminal
decodificada por tmux y el registro de bytes emitidos.

Comandos probados con `NEXUS_LOG_LEVEL=warning` y sin `NO_COLOR` heredado:

```bash
.venv/bin/python omni.py --engagement eng-scanme --no-wizard
.venv/bin/python omni.py --engagement eng-scanme --no-wizard --no-color
```

En ambos modos se introdujo `/status` y después `/exit`. Cada pantalla
capturada contiene exactamente un banner. Después de `/status` contiene
exactamente una respuesta `status bar: ON`. La entrada está en la fila 34
y la barra en la 35, antes y después del comando. El tiempo de sesión avanza.
No hay `[INFO]` en ninguno de los dos registros completos de terminal.

Captura con color, después de `/status` (se omiten únicamente filas vacías):

```text
 ██████╗ ███╗   ███╗███╗   ██╗██╗
██╔═══██╗████╗ ████║████╗  ██║██║
██║   ██║██╔████╔██║██╔██╗ ██║██║
██║   ██║██║╚██╔╝██║██║╚██╗██║██║
╚██████╔╝██║ ╚═╝ ██║██║ ╚████║██║
 ╚═════╝ ╚═╝     ╚═╝╚═╝  ╚═══╝╚═╝
   A G E N T C S   ·   C L I

       =[ OmniAgentCS v3.0.0                                             ]
 + -- --=[ 16 tools · 1 providers · engagement: scanme-lab               ]
 + -- --=[ audit-chain ✓ · msfrpcd 6.5.3-dev- · groq/openai/gpt-oss-120b ]

 Tip: Use Ctrl+C to interrupt input without killing the session.
• omni listo · tenant=system · engagement=eng-scanme · /help para comandos
┌──(OmniAgentCS)─[scanme-lab]
└─$ /status
status bar: ON

┌──(OmniAgentCS)─[scanme-lab]
└─$
scanme-lab · groq/openai/gpt-oss-120b · 0 tok · ~$0.0000 · 1m04s
```

En las primeras siete filas no hay SGR de color ni negrita, incluso en modo
color. Con `--no-color` no hay SGR de color en toda la pantalla; permanece
el formato monocromo invertido de la barra (SGR 7), además de los controles
de cursor necesarios para la TUI. El ASCII conserva sus formas y usa el
contraste de la paleta predeterminada. Su apariencia exacta depende del tema
y de la fuente del terminal del operador.

Capturas completas de pantalla:

- `/tmp/tui-fix-final-color-startup.txt` y `.ansi`.
- `/tmp/tui-fix-final-color-status.txt`.
- `/tmp/tui-fix-final-plain-startup.txt` y `.ansi`.
- `/tmp/tui-fix-final-plain-status.txt`.
- Registros PTY: `/tmp/tui-fix-final-color.raw` y
  `/tmp/tui-fix-final-plain.raw`.

También se comprobó el fallback con `/help`, `/status`, `/exit` mediante
pipe. Salida en `/tmp/tui-fix-fallback.txt`. No se ejecutaron objetivos,
escaneos ni llamadas al modelo. Las dos demos interactivas se cerraron con
`/exit`.

## Commit

Mensaje solicitado: `fix(cli): single banner, no info logs at startup, softer ASCII colors`.
El hash y `git log --oneline -3` se incluyen en la respuesta de entrega;
se omite el hash propio dentro del archivo para no invalidarlo al escribirlo.
