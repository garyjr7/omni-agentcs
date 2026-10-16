# Backlog posterior al ensayo de laboratorio

Informe técnico en español · BAJIOWARE

## Estructura implementada

```text
nexus_core/tools/handlers/
  http_request.py       # nexus.web.request; transporte HTTP compartido
  web_upload.py         # nexus.web.upload
  shell_exec.py         # nexus.post.shell_exec
  jobs.py               # nexus.post.job
  git_dump.py           # nexus.web.git_dump
  cred_bruteforce.py    # SSH/FTP existentes, TCP/Telnet añadidos
  _tcp_credentials.py   # protocolo de prompts dentro del sandbox
nexus_core/report/checksums.py
nexus_core/tests/unit/test_post_audit_backlog.py
```

Se registran cuatro herramientas nuevas: catálogo total de **68**. Se sincronizan registro, inventario JSON, evaluación del provisionador y pruebas del catálogo. No se añaden dependencias ni tablas ni migraciones. La ruta HTTP real del repositorio es `http_request.py`.

## 1. Descargas incrementales

`nexus.web.request` separa `max_response_bytes` (preview, hasta 1 MB) de `max_download_bytes` (archivo, hasta 256 MiB). Con `save_path`, lee bloques de hasta 64 KiB, calcula SHA-256 incremental y escribe un temporal en el directorio de destino. Publica con `os.replace` después de EOF y `fsync`; los errores, el exceso de cuota y un `Content-Length` incompleto impiden publicar. El handler mantiene un directorio temporal propio por descarga y lo elimina también cuando el sandbox termina por timeout o cancelación, aunque el proceso no haya ejecutado su bloque `finally`.

```json
{
  "url": "https://laboratorio.example/documento.pdf",
  "save_path": "descargas/documento.pdf",
  "max_response_bytes": 4096,
  "max_download_bytes": 67108864
}
```

`body_complete` indica si el hash cubre la respuesta completa; `preview_truncated` describe exclusivamente el preview. Sin `save_path`, se conserva la lectura acotada: el hash puede cubrir sólo el prefijo observado y `body_complete=false` lo explicita. `saved` incluye ruta, bytes y hash del archivo completo. No se implementa reanudación automática: se utiliza streaming directo. Los archivos quedan en el workspace; no se registran automáticamente en el CAS compartido.

Las redirecciones siguen desactivadas por defecto. Si se solicitan, sólo se siguen dentro del mismo origen (esquema, host y puerto); otros destinos necesitan autorización separada. Es una restricción deliberada frente al comportamiento previo de seguimiento sin límite de origen.

## 2. Subida dedicada

`nexus.web.upload` reutiliza el transporte HTTP y la validación del workspace. Acepta POST multipart o PUT con `upload.mode="raw"`. El cuerpo es un iterador; `Content-Length` se calcula antes de transmitir. Se reemplazan los encabezados de framing proporcionados por el llamador para evitar longitudes contradictorias.

```json
{
  "url": "https://laboratorio.example/archivos",
  "method": "PUT",
  "upload": {"field": "file", "path": "datos/fixture.bin", "mode": "raw"}
}
```

La ruta local viaja en argv y el contenido se transmite por el cuerpo HTTP, sin expandirlo en una query. Límite de archivo: 256 MiB. La modalidad multipart existente de `nexus.web.request` conserva su contrato y obtiene la misma mejora de memoria.

## 3. Adaptador de sesiones

`ShellRequest` es un DTO Pydantic estricto, congelado y sin campos extra. Selecciona Metasploit, Sliver o una sesión `webshell` previamente registrada. Antes de acceder al transporte se validan firma del scope, pertenencia de la sesión al tenant/engagement, estado abierto y compatibilidad del tipo de sesión.

Metasploit y Sliver conservan sus validadores y clientes existentes. Webshell requiere correspondencia exacta del hostname con la sesión y revalida la URL contra el scope; transmite el comando como formulario POST. La herramienta tiene riesgo **HIGH** y pasa por la aprobación del gateway. No registra sesiones automáticamente ni instala shells. La propiedad de la sesión es la ya definida por el registro tenant/engagement, no una nueva propiedad exclusiva por usuario.

## 4. Jobs durables

`JobRequest` admite `start` y `status`. `start` valida el esquema de la herramienta interna y encola `tool.invoke` con identidad, roles, engagement y run originales. El worker vuelve a atravesar el gateway: scope, políticas, aprobación, journal y auditoría. No se aceptan identidades o permisos inventados en los argumentos. El gateway sella `RunContext.authorized_permissions` con los permisos de la invocación autenticada; el job propaga esos permisos y el runtime conserva una lista de roles vacía, sin convertirla en `operator`. Este ajuste añade un campo opcional al final de `RunContext`, conservando los argumentos posicionales históricos. Se rechaza la recursión hacia `nexus.post.job`.

```python
task = context.store.enqueue_task(
    tenant_id=context.tenant_id,
    run_id=context.run_id,
    task_type="tool.invoke",
    payload=payload,
    max_attempts=1,
    timeout_seconds=definition.timeout_seconds + 30,
)
```

Se reutilizan leases y fencing del kernel, tanto en SQLite como PostgreSQL. El inicio devuelve `queued`, no éxito de la ejecución interna. `status` exige el mismo tenant, engagement y actor que encoló el job y devuelve estado e intentos sin copiar resultados sensibles al contexto. La evidencia de ejecución permanece en el journal.

Requiere un worker activo. Se preserva el run original para que las aprobaciones sigan ligadas al mismo run; el estado de la **task** es la referencia de progreso del job. No extiende los límites individuales del handler: desacopla la espera del llamador. Una operación de alto riesgo sigue necesitando `approval_id` válido para la herramienta interna. Se limita a un intento automático para evitar repetir efectos no idempotentes. No se añade cancelación a esta interfaz start/status.

## 5. Recuperación Git

`nexus.web.git_dump` descarga `HEAD`, su referencia y el grafo alcanzable de objetos sueltos: commits, padres, trees, blobs y tags. Comprueba nombre de objeto hexadecimal, tamaño declarado, descompresión acotada y SHA-1 del formato Git. Conserva los objetos comprimidos en un ZIP bare con configuración mínima generada localmente; registra el ZIP como artefacto tenant-scoped con SHA-256 mediante el backend configurado.

Cuotas: 4 MiB por objeto descargado/descomprimido, 8 MiB de descarga agregada, máximo configurable de 2.000 objetos y archivo final de hasta 10 MB. No ejecuta checkout, hooks ni configuración obtenida del servidor. Los gitlinks de submódulos no disparan descargas externas.

**Cobertura parcial explícita:** recupera el historial alcanzable desde HEAD con objetos sueltos. No soporta packfiles, packed-refs, todas las ramas ni formatos de object ID distintos de SHA-1. Si falta un objeto o se supera una cuota, devuelve `incomplete` y no publica un repositorio aparentemente completo. El servidor debe permitir leer los objetos: no se evaden controles HTTP.

## 6. TCP y Telnet

Se conservan SSH y FTP mediante Hydra. TCP y Telnet usan un cliente stdlib dentro del sandbox, con intentos secuenciales, pausa entre intentos, timeout por socket y límite de respuesta. Telnet procesa negociación IAC fragmentada y rechaza opciones no soportadas.

Como TCP no define un protocolo universal de autenticación, el contrato requiere un `success_marker` literal, admite `password_prompt` y `login_prompt` y exige puerto explícito en TCP. Sin `login_prompt` se admite autenticación sólo por contraseña, como una VTY. El puerto Telnet predeterminado es 23. Una conexión fallida se registra en `errors`; no se presenta como rechazo confirmado de credenciales.

Las listas permanecen confinadas al workspace, con máximo de 16 MB de origen, 4.096 caracteres por entrada y hasta 5.000 intentos. Cada invocación tiene directorio exclusivo, evitando colisiones entre workers. El cliente no soporta protocolos binarios de autenticación arbitrarios, STARTTLS ni diálogos de múltiples factores. Las pruebas usan fixtures, no daemons o credenciales reales.

## 7. Checksums de reportes

Se conservan `report_sha256` y la verificación semántica histórica, que excluye el propio campo del JSON. Se añade `canonical_report_sha256` como etiqueta explícita en la salida del generador. `report.sha256` contiene ahora hashes de **los bytes reales** de los archivos publicados, en formato GNU:

```text
<sha256 de report.html>  report.html
<sha256 de report.json>  report.json
<sha256 de report.md>  report.md
```

El generador y la exportación CLI usan `write_checksums`; la salida del generador incluye `report_path_sha256`. El listado cubre los archivos del reporte seleccionados, no el propio checksum ni el manifiesto CLI. Se valida con `sha256sum -c report.sha256` desde el directorio de entrega, incluyendo prueba negativa tras alterar un archivo. No se intenta hacer que un hash semántico autorreferente coincida con el hash del JSON serializado.

## Validación

Las pruebas nuevas ejercitan los scripts enviados al sandbox con respuestas en memoria y transportes sustituidos, además de almacenamiento SQLite real y la utilidad local `sha256sum`. Las pruebas HTTP preexistentes utilizan servidores locales. No se ejecutaron herramientas contra objetivos externos ni una campaña de ataque.

El tipado estricto cubre los ocho módulos de producción de este backlog; el gate incremental cubre también los cambios anteriores presentes en el workspace. Se conserva la configuración de mypy del proyecto (`follow_imports=skip` salvo excepciones declaradas): no se afirma haber tipado estrictamente todo el repositorio.


### Resultados obtenidos

| Verificación | Resultado | Evidencia |
| --- | --- | --- |
| Suite general, SQLite + PostgreSQL temporal, `NEXUS_E2E=0` | **2.990 pasan, 35 omitidas**, una advertencia de deprecación de `google.genai` | [suite.log](evidencia_backlog/suite.log) |
| Archivo de pruebas nuevas, revisión final | **21 pasan** | [pruebas_nuevas.log](evidencia_backlog/pruebas_nuevas.log) |
| Contratos activos/read-only, catálogo, prompt y leases | **119 pasan** | [contratos.log](evidencia_backlog/contratos.log) |
| `mypy --strict` sobre ocho módulos de producción del backlog | Sin errores | [mypy_strict.log](evidencia_backlog/mypy_strict.log) |
| Gate incremental `make typecheck`, incluyendo cambios previos | **109 archivos**, sin errores | [mypy_incremental.log](evidencia_backlog/mypy_incremental.log) |
| Ruff, compilación Python y sintaxis de scripts | Correctos | [estatico.log](evidencia_backlog/estatico.log) |

La prueba específica que rechaza `save_path="."` se añadió después de iniciar la última suite general; está incluida en las 21 pruebas focalizadas finales. No se presenta como parte de las 2.990 de esa ejecución. PostgreSQL temporal se detuvo al terminar.

Las pruebas del contrato de efectos ahora incluyen las nuevas operaciones activas, que quedan bloqueadas en modo plan. El catálogo renderizado mide 13.374 caracteres y el prompt de referencia 20.883; se conserva el límite de menos de 200 caracteres por herramienta y se ajustan los techos globales por las cuatro incorporaciones. La prueba de leases comprueba la exclusión del segundo worker **después** de vencer el plazo original, con margen para la planificación del heartbeat.

No se certifica ejecución real de Metasploit, Sliver, Quagga ni Git empaquetado: las verificaciones de transporte añadidas utilizan fixtures. La ampliación del recuperador a packfiles/packed-refs queda pendiente y no se declara resuelta por este cambio.
