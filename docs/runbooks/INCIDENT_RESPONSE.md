# Runbook de incidentes

1. Revocar el token, sesión, conector o service account afectado.
2. Pausar workers si continúa un efecto externo; no borrar la cola ni auditoría.
3. Exportar eventos por tenant, `trace_id`, `run_id` y ventana temporal.
4. Verificar la cadena hash de auditoría y hashes de artefactos.
5. Rotar secretos mediante el proveedor externo y reconstruir contenedores.
6. Restaurar en un entorno aislado, ejecutar smoke tests y promover con aprobación.
7. Documentar causa, alcance, datos afectados y acciones preventivas.
