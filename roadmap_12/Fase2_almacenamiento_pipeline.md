# BAJIOWARE — Fase 2: almacenamiento y pipeline

Fecha: 12 de octubre de 2026. Alcance: P1 D06, D07, D10 y D11. Los cambios de concurrencia P0 existentes se conservaron.

## 1. Captura incremental y memoria — D06

`kernel/output_capture.py` incorpora `BoundedCapture` y el modelo inmutable `StreamManifest`. `LocalSandbox.run()` y `OCISandbox.run()` comparten `_capture_process()`: stdout y stderr se drenan concurrentemente en bloques de 64 KiB. Se conserva únicamente el prefijo configurado por canal; el resto se contabiliza y se procesa para el hash, sin acumularlo ni escribir credenciales crudas en archivos temporales.

```python
while chunk := await reader.read(65536):
    self.total += len(chunk)
    self.digest.update(chunk)
    self.buffer.extend(chunk[:max(0, self.limit - len(self.buffer))])
```

Cada `SandboxResult` expone `stdout_manifest` y `stderr_manifest`:

```python
@dataclass(frozen=True)
class StreamManifest:
    total_bytes: int
    retained_bytes: int
    discarded_bytes: int
    sha256: str
    retained_sha256: str
    truncated: bool
    complete: bool
    error: str | None
```

- SHA-256 se calcula sobre bytes originales antes de decodificar UTF-8; el hash del prefijo permite comprobar lo conservado.
- `truncated` indica descarte por capacidad; `complete` indica que se recibió EOF. No significa que el comando terminara exitosamente. Un drenaje interrumpido conserva sus contadores y señala `DrainInterrupted`.
- Memoria de captura: O(límite de stdout + límite de stderr + buffers de transporte). Predeterminado: 1.000.000 bytes por canal. El límite cero conserva solo hashes y contadores; valores negativos se rechazan antes de lanzar el proceso.
- Se mantienen timeout, cancelación y limpieza por grupo de procesos. OCI elimina explícitamente el contenedor administrado por el daemon en timeout/cancelación.
- El contenido textual no recibe sufijos que rompan parsers JSON/XML; los marcadores viven en los manifiestos. Los consumidores directos pueden inspeccionarlos en `SandboxResult`; no se alteraron todos los handlers para incorporarlos automáticamente a sus evidencias.
- `open_stdio()` conserva su contrato de transporte interactivo para MCP; no es una captura de resultado mediante `run()`.

La captura es deliberadamente limitada: el hash completo permite identificar el flujo observado, pero los bytes descartados no son recuperables. La prueba de memoria produce 32 MiB, conserva 1 KiB y exige un pico de asignaciones Python inferior a 8 MiB; no mide RSS total ni memoria del proceso hijo.

## 2. Repositorio y volumen compartido — D07

Se separaron tres contratos en `kernel/artifacts.py`:

| Componente | Función |
|---|---|
| `ArtifactStore` | API consumida por journal y observaciones: `put()`/`get()` |
| `ArtifactRepository` | Metadatos SQL, límites, validación de referencias, tamaño e integridad |
| `BlobBackend` | Publicación y lectura de bytes por tenant y digest |
| `FilesystemBlobBackend` | Implementación POSIX para disco local o volumen compartido |
| `LocalArtifactStore` | Fachada compatible con los constructores anteriores |
| `ArtifactReference` | Referencia tipada e inmutable; validación estricta en lectura/escritura |

```python
class BlobBackend(Protocol):
    def put(self, tenant_id: str, digest: str, content: bytes) -> None: ...
    def get(self, tenant_id: str, digest: str, max_bytes: int) -> bytes: ...
```

La dirección nueva en SQL es `cas:v1/<tenant>/<sha256>`. El archivo físico se ubica en `<raíz>/<tenant>/<primeros 2 caracteres del digest>/<digest>`. La raíz no se persiste: distintos workers pueden montar el mismo volumen en rutas diferentes.

La ingestión calcula SHA-256 determinista sobre bytes exactos. Los tenants aceptan únicamente identificadores acotados sin separadores de ruta; digest e identificador de artefacto tienen formatos cerrados. El recorrido usa descriptores de directorio y `O_NOFOLLOW`. La lectura rechaza enlaces simbólicos y archivos no regulares, limita los bytes y verifica tamaño y digest.

La publicación usa archivo temporal exclusivo, permisos 0600, `fsync` y enlace duro atómico sin reemplazo. Si otro escritor publicó el mismo contenido, se verifica el objeto existente antes de reutilizarlo. Los directorios se crean con 0700. La raíz y sus ancestros deben estar bajo control del operador.

```bash
# Ejemplo de configuración; el volumen debe existir y estar montado previamente.
NEXUS_ARTIFACT_MODE=shared
NEXUS_ARTIFACT_ROOT=/mnt/nexus-artifacts
```

`configured_artifact_store()` es utilizado por el gateway, las observaciones y la generación de informes. El modo compartido exige una raíz absoluta existente y no vuelve silenciosamente al almacenamiento local. El backend requiere semántica POSIX de enlaces atómicos y sincronización; todos los workers necesitan acceso con permisos compatibles. Para varios nodos, los metadatos deben residir en PostgreSQL compartido. SQLite WAL continúa siendo una opción de un solo nodo; no se recomienda alojar su base en un filesystem de red.

Límite predeterminado de artefacto: 16 MiB, configurable por constructor del repositorio. No se añadieron dependencias, SDK de nube ni un backend S3. El protocolo permite implementar otro backend sin modificar los consumidores.

## 3. Referencias versionadas y compatibilidad — D10

`kernel/result_references.py` reemplaza la escritura `JSON + "|" + digest` por JSON versionado, discriminado por `kind`:

```json
{
  "version": 1,
  "kind": "inline",
  "payload": {"output": "izquierda|derecha"},
  "sha256": "<SHA-256 de la serialización canónica del payload>",
  "size_bytes": 30
}
```

El ejemplo anterior es esquemático; digest y tamaño reales se calculan al escribir.

```json
{
  "version": 1,
  "kind": "artifact",
  "artifact": {
    "id": "artifact_<32 caracteres hexadecimales>",
    "tenant_id": "system",
    "sha256": "<64 caracteres hexadecimales>",
    "size_bytes": 123,
    "media_type": "application/json"
  }
}
```

Se validan versión, discriminante, campos permitidos, tipos, tenant, media type, longitud y hash. Un resultado con `evidence` debe usar un objeto JSON; `success`/`verified` deben ser booleanos; `assertions`, cuando está presente, debe ser una lista de objetos. Se rechazan objetos Python arbitrarios, números no finitos, claves JSON duplicadas y anidamiento superior a 64 niveles. No se utiliza `default=str` para persistir estos resultados.

`kernel/serialization.py` aplica un precontrol de volumen antes de redactar/copiar y una serialización incremental limitada a 16 MiB. El hash se calcula después de la redacción, sobre exactamente los bytes que se almacenan.

**Migración compatible:** las columnas existentes `result_ref TEXT` y `storage_uri TEXT` siguen siendo válidas en SQLite y PostgreSQL; no se requiere DDL ni reescritura masiva. El lector nuevo entiende registros antiguos: separa el digest con `rpartition("|")`, verifica integridad y luego deserializa/redacta. Las rutas absolutas antiguas solo se aceptan con la estructura esperada de tenant/prefijo/digest y se traducen a la raíz actual; nunca se abren directamente.

Esta compatibilidad permite leer datos históricos con el código nuevo. Los binarios antiguos no entienden las referencias nuevas: el despliegue de lectores y escritores debe coordinarse antes de reactivar workers. No se promete rollback de binarios antiguos sobre datos ya escritos en el formato nuevo.

## 4. Observaciones, redacción y blackboard — D11

La frontera usa `sanitized_object()` para validar y redactar antes de preparar la observación o archivar su contenido. La redacción cubre campos sensibles nombrados, asignaciones en texto y JSON embebido; se añadieron URLs HTTP con credenciales, tokens Bearer y bloques de claves privadas PEM. No pretende detectar cualquier secreto sin contexto.

Las observaciones pequeñas también se redactan. Las grandes conservan una referencia completa validada, no solo hash y tamaño. Ante error, se entrega JSON válido y acotado con estado explícito:

```json
{
  "compacted": true,
  "output_summary": {"summary_omitted": true},
  "storage": {"status": "failed", "error_code": "OSError"}
}
```

Los estados de archivo son `stored`, `unavailable` o `failed`; una observación pequeña no necesita archivado. Se expone únicamente el tipo de error, nunca su mensaje potencialmente sensible. Payloads excesivos se rechazan con `PayloadTooLarge`. Estructuras inesperadas en los compactadores producen `InvalidShape`. Si el resumen sigue siendo demasiado grande, se reduce el conjunto completo de campos, incluidos stdout y evidence, manteniendo JSON válido. El mínimo configurable es 512 caracteres.

`Blackboard.record()` valida y redacta el registro antes de persistir contenido, etiquetas y metadatos. `list_facts()` también redacta los registros históricos al leerlos. Esto no limpia retroactivamente filas antiguas del disco.

El gateway resuelve el repositorio antes de ejecutar el handler y propaga fallos de configuración o integridad; se eliminó el fallback silencioso a inline después de fallar la lectura de un artefacto. Si falla la persistencia después de ejecutar un efecto, se conserva el tratamiento previo del journal: resultado `unknown`, sin repetir automáticamente un efecto no idempotente.

`ArtifactRepository.put()` conserva los bytes suministrados para que su hash sea reproducible. La redacción del contenido ocurre en las fronteras de journal, observaciones y blackboard; un consumidor directo de blobs sigue siendo responsable de seleccionar qué datos está autorizado a archivar.

## 5. Validación

Resultados finales:

- Suite completa con SQLite y PostgreSQL: **2.894 aprobadas, 35 omitidas, 0 fallos**, 109,86 s.
- Casos dirigidos con PostgreSQL: **39 aprobadas**.
- Verificación final de fronteras, incluido el caso `InvalidShape` añadido después de lanzar la suite completa: **30 aprobadas**.
- `make lint typecheck syntax`: aprobado; mypy sin errores en los archivos modificados/nuevos.
- Una advertencia de deprecación de `google.genai`, ajena a estos cambios.

Las ejecuciones dirigidas comparten pruebas con la suite; los conteos no se suman. Evidencia: [Fase2_validacion.txt](Fase2_validacion.txt).

Cobertura añadida:

- stdout/stderr multimegabyte, límite cero, truncamiento, hashes completos y del prefijo;
- consumo de memoria al producir 32 MiB;
- misma ruta incremental OCI y limpieza del contenedor en timeout, mediante doble local del launcher;
- publicación paralela con ocho repositorios en SQLite y PostgreSQL;
- aislamiento por tenant, traversal, symlinks, corrupción, límites y traducción de rutas históricas;
- referencias inline con pipes, integridad histórica, tenant incorrecto, versiones y tipos inválidos;
- observaciones pequeñas redactadas, almacenamiento fallido, estructuras malformadas y exceso de tamaño;
- secretos ausentes del contenido/metadatos persistidos en el blackboard.

La integración usa PostgreSQL 18 temporal y esquemas aislados. Las pruebas OCI sustituyen el ejecutable del runtime por procesos Python locales; no certifican un daemon Docker/Podman real. Las pruebas de almacenamiento compartido utilizan instancias independientes sobre un directorio común; no certifican un proveedor NFS ni una topología multinodo física.

## 6. Límites operativos pendientes

- La escritura del blob precede al INSERT SQL: un fallo SQL puede dejar un blob sin referencia, pero no una referencia nueva que apunte a un blob todavía incompleto. Se necesita una política de recolección/retención para objetos huérfanos.
- El límite por artefacto no constituye una cuota agregada por tenant ni limita el crecimiento total del volumen.
- La captura limita memoria; procesar y calcular hash de salida ilimitada aún consume CPU/I/O hasta el timeout.
- Los manifiestos están disponibles en `SandboxResult`; su incorporación específica a cada formato de evidencia de handler es una integración posterior.
- El despliegue debe provisionar el volumen compartido y coordinar la actualización de los workers. El código no monta almacenamiento remoto ni aplica cambios de infraestructura.
