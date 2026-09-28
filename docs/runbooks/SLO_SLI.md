# SLO y señales operativas

Objetivos iniciales mensuales, sujetos a revisión después de obtener 30 días de datos:

- API del control plane: 99.9% de disponibilidad; p95 menor a 500 ms, excluyendo ejecución de modelos/tools.
- Aceptación durable de tareas: 99.9%; p95 menor a 750 ms.
- Inicio de una tarea lista: 99% antes de 60 segundos.
- Tool calls de lectura: 99% exitosas, descontando rechazos correctos de política.
- Pérdida de tareas confirmadas: cero; RPO PostgreSQL 15 minutos y RTO 4 horas.

Señales: `nexus_model_requests_total`, `nexus_model_tokens_total`, `nexus_tool_calls_total`, `nexus_tool_duration_ms_total`, estados/DLQ de tareas, latencia HTTP y verificación de la cadena de auditoría. `/system/metrics` exige administrador. Las alertas mínimas son: error sostenido mayor a 5%, DLQ creciente, circuito de modelo abierto, cuota al 80%, auditoría inválida y backup vencido.
