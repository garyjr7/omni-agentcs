# Benchmark sintético de autonomía

Evaluación **offline** del comportamiento del bucle sobre trazas ficticias. No
abre sockets, no llama a un modelo y no ejecuta herramientas: cada escenario
declara resultados de herramienta, hechos de tablero y, cuando aplica, el
intercambio con el modelo. El runner los evalúa con los predicados de producción
(`ToolResult`, `derive_assertions`, telemetría de turno, ledger de cobertura,
firma semántica y resumen terminal).

```bash
python bench/autonomy/run.py
python bench/autonomy/run.py --json /tmp/after.json
python bench/autonomy/run.py --baseline /tmp/before.json
```

## Métricas

| métrica | significado |
| --- | --- |
| `objective_complete_with_verified_evidence` | escenarios declarados completables cuyo cierre está respaldado por hechos verificables |
| `success_rate` | esa proporción; el 90 % es la meta para las condiciones declaradas, no una garantía por sala |
| `repeated_without_progress` | invocaciones cuya firma semántica ya apareció y que no aportaron progreso accionable |
| `open_branches` / `closed_branches` | ramas pendientes y resueltas según el ledger |
| `provenance_precision` | hechos que dicen ser verificados y no tienen procedencia del modelo |
| `tokens` / `ms` | coste declarado por las trazas (sintético) |
| `correct_stops` | paradas por scope/seguridad o límite del proveedor con causa explícita |

## Separación calibration / reserved

Los escenarios `calibration` se usan para ajustar reglas; los `reserved` solo se
leen al informar. El informe publica ambos por separado (`by_split`) y por
categoría (`success`, `negative_observation`, `tool_error`, `barrier`,
`provider_limit`, `safety_stop`).

## Límites

- No mide la calidad de un modelo: el resultado es determinista y no depende del
  proveedor. Ejecutarlo con varios modelos requiere un arnés que sustituya el
  intercambio sintético por respuestas reales; este runner no lo hace.
- No sustituye a un E2E contra salas reales (que siguen siendo opt-in con
  `NEXUS_E2E=1`).
- Los hechos son ficticios y usan rangos de documentación (RFC 5737). No hay
  nombres de sala, flags reales, credenciales reales ni CVE reales.
- La equivalencia entre herramientas distintas que hacen el mismo trabajo (p.
  ej. `nmap` frente a `shell.exec` con `nmap`) sigue fuera del guard: la
  deduplicación compara la firma semántica de la *misma* herramienta.
