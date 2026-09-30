# Neutralidad del entorno de tests

La fixture autouse `_neutralize_no_color` elimina la preferencia heredada
`NO_COLOR` y restaura su valor original al finalizar cada test. Los tests con
fixture/parámetro `no_color_env` pueden gestionar explícitamente esa variable.
No se cambió el shell, `.bashrc` ni el comportamiento del producto.

`test_env_neutrality.py` ejecuta los tres tests afectados en subprocesos con
`NO_COLOR` ausente y con los valores `1`, `true` y cadena vacía. Cada ejecución
comprueba los tres tests reales, con timeout de 60 segundos.

Resultados antes de migrar la TUI:

```text
NO_COLOR=1 .venv/bin/python -m pytest nexus_core/tests -q
851 passed, 18 skipped in 46.58s

env -u NO_COLOR .venv/bin/python -m pytest nexus_core/tests -q
851 passed, 18 skipped in 49.60s
```

Los 847 tests anteriores pasan en ambos entornos; los cuatro casos nuevos
elevan el total a 851. Logs: `/tmp/tui-env-color.txt` y
`/tmp/tui-env-no-color.txt`. La única variable ambiental consultada por el
renderizador de color existente es `NO_COLOR`.
