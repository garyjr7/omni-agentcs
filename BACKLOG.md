# Deuda explícita después de Fase 0

La implementación de Fase 0 se limita a las cinco grietas P0. El backlog
histórico se conserva en [docs/missions/BACKLOG.md](docs/missions/BACKLOG.md).
Estas P1 no se presentan como garantías disponibles:

| Prioridad / ID de auditoría | Trabajo pendiente | Impacto actual | Criterio de cierre |
| --- | --- | --- | --- |
| P1-A · A-01 | Journal durable de invocaciones y reconciliación de efectos tras crash | Los nuevos `invocation_id` permiten atribución, **no** exactly-once. Caer después de un efecto y antes de guardar el resultado puede provocar reejecución, incluido un exploit. | Estado reservado/ejecutando/observado/reconciliado y pruebas de caída en cada frontera; ningún replay automático de efectos desconocidos. |
| P1-B · P2-3 | `oci_network` con egress validado por scope | El modo sigue indisponible y falla explícitamente. `oci` no tiene red; local no aísla egress. | Pruebas reales de rutas permitidas/denegadas, DNS/rebinding, IPv4/IPv6, cierre y cleanup sin degradación a local. |
| P1-C · A-05 | Sustituir el validador subset del gateway por JSON Schema completo | `minimum`, `maximum`, `pattern` y otras restricciones siguen sin validarse universalmente en entradas de herramientas. Los checks específicos de handlers siguen vigentes. | Suite por dialecto y constraints, errores compatibles, tratamiento explícito de `$ref`; no añadir dependencias sin autorización. MCP ya trae `jsonschema` transitivamente, utilizado para validar su outputSchema. |

Estimación orientativa: P1-A 3–5 días; P1-B 5–8 días; P1-C 1–2 días más
regresiones. Son trabajos separados, en ese orden, no parte del cierre P0.

## Límites explícitos del verificador

La promoción de hechos requiere un parser determinista específico. Una tool
sin parser semántico continúa devolviendo observaciones útiles, pero no puede
acreditar por sí sola una fase ni un hallazgo confirmado. Ampliar cobertura de
parsers exige casos positivos y negativos por tipo; no se permite volver a
confiar en `verified` o `source` proporcionados por el modelo.

Un outputSchema MCP describe estructura, no demuestra que un efecto remoto
ocurrió. Mantener `mcp_unverified` hasta disponer de un verificador independiente
es deliberado. La declaración de efectos del operador no es una barrera de
seguridad del sistema operativo para un servidor stdio malicioso en modo local.
