# Backup y restauración

Producción usa backups nativos de PostgreSQL y snapshots/versionado del almacén de objetos. SQLite solo se respalda en desarrollo con el proceso detenido o mediante su API de backup; nunca se copia únicamente el archivo principal mientras WAL está activo.

Para SQLite, `./nexus_backup.sh --database data/nexus_pro.db` crea un snapshot consistente, manifiesto y SHA-256 sin copiar `.env`. La restauración requiere un destino explícito: `./nexus_restore.sh ARCHIVO --database /ruta/aislada/nexus.db`; para reemplazar un archivo existente debe agregarse `--force` con el servicio detenido. PostgreSQL se respalda con `pg_dump --format=custom` y se restaura con `pg_restore` usando una credencial dedicada.

Cada restauración se hace primero en un ambiente aislado y valida: migraciones, conteos por tenant, cadena de auditoría, hashes de artefactos, login, una tarea Fake LLM y revocaciones. Una copia no se considera backup hasta superar una restauración trimestral documentada.
