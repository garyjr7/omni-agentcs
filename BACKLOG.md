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


## Fase 1 · UX pendiente

| Prioridad / ID | Pendiente e impacto | Criterio de cierre |
| --- | --- | --- |
| P1-UX-6 · U-05 | Transcript conserva todos los bloques y cola sin backpressure. El pegado compacto no limita la memoria de sesiones largas. La medición offline de 10.000 eventos retuvo 10.000 segmentos (~26,6 MB de pico trazado; ~1,539 s en la revisión final de este entorno). | Paginación de bloques a disco, ventana visible e índice/cola acotados; prueba de productor más rápido que renderer; medir memoria y latencia antes de cambiar renderer. |
| P1-UX-7 · U-06 | No hay estados separados de «enviar al terminar» e «interrumpir con instrucción», editor externo ni navegación por teclado de tarjetas individuales. Las teclas F3–F7 cubren chips/tareas, no esas funciones. | Máquina de estados explícita, prioridad de instrucciones/cancelación, editor seguro y navegación de tarjetas con pruebas PTY y sin perder entradas. |
| P1-3 · O-03 | AgentSupervisor y delegación con contextos aislados siguen pendientes. El panel de Fase 1 visualiza perfiles y fan-out existentes. | Ciclo de vida durable de agentes, contexto y presupuestos separados, resultados atribuibles y cancelación/reanudación sin contaminación del principal. |
| Calidad · Tipado TUI | Mypy incremental sobre ocho módulos UX conserva 23 errores preexistentes en `session.py` (atributos del layout dinámico, opcionalidad y anotaciones). El check no pasa; no se añadieron supresiones. | Contrato tipado de construcción del layout y sesión, cero hallazgos en esos módulos y pruebas de interfaz completas sin debilitar controles. Evidencia: `docs/missions/evidence/phase1/typecheck.txt`. |
| U-03 · Telemetría | Ventana depende de configuración/metadato conocido; el conteo previo al response es estimado. El aviso al 80% no cambia los umbrales existentes de compactación; tasa oculta sin dato. | Descubrimiento confiable por despliegue, tokenizer/usage consistente y telemetría de límites del proveedor. Cambiar la política de compactación requiere otra misión del orquestador. |

P1-A/A-01, P1-B/P2-3 (`oci_network`) y P1-C/A-05 permanecen con los criterios
anteriores. No se amplió esta fase para declararlas resueltas.
