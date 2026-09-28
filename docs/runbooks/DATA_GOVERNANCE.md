# Retención, exportación y borrado

Cada memoria tiene `tenant_id`, clasificación y expiración opcional. Los jobs de mantenimiento ejecutan `MemoryStore.purge_expired(tenant_id)` por tenant. La auditoría es append-only: una solicitud de borrado no altera evidencia obligatoria; se seudonimizan referencias conforme a la política legal aplicable y se documenta la excepción.

Los exports incluyen únicamente el tenant solicitado y deben registrar actor, motivo, ventana y hash del artefacto. Los objetos se eliminan primero del índice y luego del almacenamiento; los backups expiran conforme a su calendario. Nunca se reutilizan conversaciones o outputs de clientes como fixtures sin sanitización y autorización.

Valores iniciales recomendados: memoria operativa 30 días, telemetría 30 días, artefactos internos 90 días y auditoría de seguridad 365 días. Son defaults de política, no sustituyen requisitos contractuales o legales.
