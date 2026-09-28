# ADR-002: Ejecución Zero Trust

Estado: aceptado (2026-08-04)

Toda herramienta se autoriza en el Tool Gateway y se registra en auditoría. La ejecución de comandos queda fuera del API y usa un sandbox efímero no privilegiado. Producción exige OCI; el sandbox local es solo para desarrollo.

Las operaciones de escritura externa, destructivas o de alto riesgo requieren aprobación durable. El solicitante no puede aprobar su propia acción. El código heredado con ejecución directa permanece deshabilitado.
