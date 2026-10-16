# Fase 4 — OMNI TOOLS: contratos y preparación operativa

**BAJIOWARE · 13 de octubre de 2026**

Se endurecieron la detección, las verificaciones de versión, la unión catálogo/recetas y el transporte de evidencia hacia los parsers y los informes. Se mantienen los **64 identificadores públicos** del catálogo y los modelos de persistencia SQLite/PostgreSQL. No se instalaron herramientas, descargaron imágenes ni ejecutaron operaciones contra objetivos externos. Los tests usan salidas sintéticas, clientes RPC simulados y recursos locales temporales.

## 1. Alcance y evaluación de disponibilidad

El inventario estructural comprende **102 módulos Python** de `nexus_core/tools/` y `nexus_core/provisioner/`: rutas, funciones, clases e importaciones están en [inventario_modulos.json](evidencia_fase4/inventario_modulos.json). El cruce completo, herramienta por herramienta, está en [catalogo_readiness.json](evidencia_fase4/catalogo_readiness.json).

| Evaluación local | Resultado | Interpretación |
|---|---:|---|
| Herramientas registradas | 64 | Se conserva el catálogo público |
| Recetas | 21 | Se añadió Nikto, que carecía de receta |
| Capacidades CLI con binario detectado | 14 | Presencia en PATH, sin ejecutar el binario |
| Capacidades pendientes de verificación operativa | 50 | Incluye servicios internos, Python, Impacket por script, RPC y gRPC |
| Herramientas builtin sin clasificación en la matriz | 0 | Los plugins desconocidos se clasifican explícitamente como no evaluados |

Las 14 detecciones corresponden a Nmap, Subfinder, HTTPX, Nuclei, Ffuf, SQLmap, Gobuster, Nikto, WhatWeb, Dalfox, Searchsploit, NetExec, BloodHound y Hydra. **Esta evaluación no certifica sus versiones, identidad, conectividad ni funcionamiento dentro de una imagen OCI.** Metasploit y Sliver se verificaron mediante mocks; no hubo autenticación contra servidores reales.

## 2. Fallos corregidos

| Frontera | Hallazgo | Corrección |
|---|---|---|
| Identidad binaria | Una firma textual podía aprobar una ejecución fallida | `classify_identity` exige código cero y captura completa; excepciones del localizador/runner producen datos de fallo |
| Versiones locales | `capture_output` retenía toda la salida antes de evaluarla | `probe.bounded_probe` drena incrementalmente, retiene hasta 65.536 bytes, aplica timeout y limpia el grupo de procesos; exceso de salida devuelve 125 |
| Detección | Binario desconocido o configuración rota podía abortar el inventario | Estados `unsupported`, `absent`, `failed`, `runnable`, detalle sin volcar excepciones sensibles y búsqueda de candidatos alternativos |
| Verificación OCI | Se etiquetaba como OCI una ejecución de `LocalSandbox` | Selección con `SandboxPolicy`; OCI no depende del PATH del host ni cae a ejecución local |
| Alias y variantes | Se podían usar argumentos de verificación de otra variante del binario | `ToolStatus.verify_argv` conserva exactamente el comando localizado |
| Instalación | El código cero de la verificación no probaba identidad | Verificación posterior acotada y firma de identidad para los binarios que tienen especificación |
| Recetas | Estructuras de argv y alias ambiguos llegaban al planificador | Validación del catálogo antes de crear planes; receta Nikto y componente SQLmap sincronizados |
| Impacket | La caché conservaba ausencias/rutas obsoletas tras cambiar PATH | Resolución fresca en cada consulta, conservando la API `cache_clear` |
| Readiness | Puerto RPC fijo y configuración de diccionarios divergente | Lectura de `MSF_RPC_URL` y `NEXUS_WORDLIST_DIRS`; fallos de rutas/sondeos manejados |
| Evidencia CLI | Los handlers perdían los manifiestos de stdout/stderr | Contrato de invocación con `ContextVar`, separado por tarea concurrente |
| Captura parcial | Una salida parseable podía aparentar éxito tras truncamiento o cancelación | Se conserva el payload como evidencia parcial, pero se invalida `verified` y se retira un resultado negativo explícito |
| Archivos de salida | Lecturas completas y errores ignorados en varios handlers | Lector limitado a 1.000.000 bytes por archivo, rechazo de enlaces simbólicos finales y archivos especiales; fallos registrados aunque el handler los capture |
| Argumentos | Targets escalares se iteraban como caracteres; números se convertían a texto | Rechazo de targets no textuales, opciones iniciales, controles y espacios internos; mayor validación de flags Nmap |
| Parsers | JSON ambiguo, números no finitos, status RPC de tipo incorrecto y objetos vacíos | Validaciones locales, fallos explícitos y preservación de los formatos históricos válidos |

`present` expresa presencia física; el campo `state` comunica si la verificación falló. La evaluación histórica de `assess_environment(..., probe_binary=None)` conserva su semántica de presencia, pero añade `capability_state="detected"` y ya no afirma que se puede operar por ese solo hecho.

## 3. Estructura implementada

```text
provisioner/
  probe.py                 # runner local acotado para diagnósticos
  binaries.py              # identidad + código de salida + integridad de captura
  detector.py              # estados explícitos y selección real local/OCI
  recipes.py               # validación del catálogo y alias
  catalog.py               # cruce de las 64 tools con dependencias y recetas
  readiness.py             # evaluación de entorno y configuración
  installer.py             # verificación posterior a instalación

tools/
  execution_contract.py    # aislamiento de evidencia por invocación y DTO final
  output_files.py          # frontera archivo → parser con límite y manifiesto
  handlers/_exec.py        # transporte compartido local/OCI
  registry.py              # contrato aplicado a los builtin; overlay conservado
  parsers/                 # validación de XML, JSON/JSONL y payloads RPC
```

Los siete handlers con lectura de resultados en archivos actualizados son BloodHound, Dalfox, GetUserSPNs, Secretsdump, WhatWeb, Pivot y WordPress. Nmap usa ahora el transporte común; Workspace registra sus capturas. Los clientes RPC siguen usando sus hashes y evidencias propias: no se inventan manifiestos de terminal para respuestas RPC.

La autorización y el alcance permanecen en `ToolGateway`, antes de ejecutar el handler. El contrato añadido refuerza el transporte de targets y valida el `ToolResult` con los DTO de la fase 3. Las contribuciones externas conservan la precedencia y la identidad de registro existentes; pueden adoptar el contrato explícitamente.

```python
# Ejemplo simplificado del contrato final de evidencia
result = replace(
    result,
    evidence={**result.evidence, "execution_capture": {
        "schema_version": 1,
        "executions": captures,
        "incomplete": incomplete,
    }},
    verified=result.verified and not incomplete,
    outcome="" if incomplete else result.outcome,
)
result.to_dto()
```

Cada captura identifica su origen (`process` o `file`), código de salida, timeout/cancelación y manifiestos por stream. Estos incluyen bytes observados/retenidos/descartados, SHA-256, integridad de lectura y truncamiento. Los hashes de texto de los parsers siguen disponibles por compatibilidad; no equivalen necesariamente al hash binario del stream original. Cuando `complete=false`, el hash cubre únicamente los bytes observados.

Los resultados de mocks o integraciones antiguas sin manifiestos mantienen campos `null`; no se inventa evidencia de captura. Los metadatos no incluyen argv, contenido de archivos ni credenciales.

## 4. Parsers y compatibilidad

- **Nmap/XML:** rechazo de entidades declaradas, números no finitos normalizados y conservación de los formatos con namespace.
- **JSONL compartido:** rechazo de claves duplicadas, constantes NaN/Infinity y errores de profundidad; conversión numérica tolerante a overflow.
- **Ffuf:** se conservan JSON, envelope y JSONL. Un envelope vacío válido representa cero resultados y conserva el hash del payload real; los registros no objeto no se descartan silenciosamente.
- **Nuclei:** objetos ajenos al esquema ya no se convierten en hallazgos vacíos; se conserva el conteo de líneas inválidas y la tolerancia a ruido.
- **Metasploit:** un status de tipo lista/dict falla con `ValueError`; duraciones negativas o no finitas no llegan al dominio.
- **Sliver:** una respuesta vacía no acredita la versión; ejecución sin status, status desconocido y duración inválida se rechazan.

El contrato de parsers se actualiza a **1.1.0**. Se regeneró `docs/missions/audit-v1/catalog.json` para que catálogo, resultados y pruebas de consistencia coincidan. No se requieren migraciones SQL. El wizard omite `verify_argv` del caché TOML, evitando introducir tuplas no serializables en configuraciones existentes.

## 5. Configuración y verificación

Para verificar una herramienta en OCI se exige configurar explícitamente **la misma variable de imagen usada por su handler** y admitir esa imagen en `NEXUS_SANDBOX_IMAGES`. Por ejemplo:

```text
NEXUS_SANDBOX_MODE=oci
NEXUS_NMAP_IMAGE=<imagen autorizada que contiene nmap>
NEXUS_SANDBOX_IMAGES=<la misma imagen autorizada>
```

Sin una correspondencia explícita de imagen, el detector informa que el contenedor no está verificado. No utiliza un binario del host como sustituto. Un sondeo de versión exitoso tampoco certifica acceso de red: el modo OCI actual mantiene su política de aislamiento.

La nueva batería `test_phase4_tool_contracts.py` cubre identidad con exit no cero, errores de búsqueda, OCI sin PATH del host, receta/alias inválidos, configuración RPC, targets ambiguos, JSON/RPC malformado, capturas concurrentes, truncamiento, archivos ilegibles/symlink, límites del runner y recuperación de Impacket tras cambios de PATH.

La integración simulada cubre **Nmap, Ffuf y Nuclei → handler → parser → ToolResult → observación persistida → informe y Markdown**, incluyendo capturas parciales. Metasploit y Sliver recorren **cliente simulado → handler → parser → persistencia → timeline del informe**; metadatos de catálogo/servidor no se clasifican como vulnerabilidades.

| Comprobación | Resultado |
|---|---|
| Suite completa, SQLite + PostgreSQL temporal, E2E externo desactivado | **2.950 passed, 35 skipped**, 111,33 s |
| Contratos finales + resolver Impacket | **38 passed**; incluye la prueba adicional de actualización de PATH |
| Regresiones focalizadas de catálogo, wizard, sandbox y handlers | **108 passed** |
| `make lint typecheck syntax` | Correcto; mypy revisó 87 archivos cambiados/nuevos acumulados |
| `mypy --strict` de los seis módulos de contrato/runner/catálogo/recetas | Correcto |
| `git diff --check` | Correcto |

La suite completa se recopiló antes de añadir el caso adicional del resolver; ese caso y su módulo se verificaron en la batería final de 38 pruebas. La única advertencia fue una deprecación de `google.genai` bajo Python 3.14. Las 35 omisiones no equivalen a pruebas aprobadas.

Logs completos: [pytest](evidencia_fase4/pytest_completo.log), [contratos finales](evidencia_fase4/pytest_contratos_final.log), [regresiones](evidencia_fase4/pytest_regresiones.log), [lint/mypy/sintaxis](evidencia_fase4/lint_mypy_syntax.log), [mypy estricto](evidencia_fase4/mypy_strict.log).

## 6. Límites y siguientes verificaciones operativas

1. La aprobación operativa requiere pruebas autorizadas contra las versiones e imágenes realmente desplegadas. Las firmas de identidad actuales cubren cinco binarios; las demás recetas acreditan ejecución del comando de verificación, no identidad criptográfica ni compatibilidad exhaustiva de versiones.
2. Los RPC remotos requieren comprobar configuración, SDK, autenticación y conectividad real. Detectar `msfconsole` o `sliver-server` localmente no demuestra que el cliente RPC pueda operar.
3. Se mantienen recetas con referencias `@latest` y nombres de imágenes sin digest. Para reproducibilidad de despliegue, fijar versiones/digests y conservar su procedencia en configuración de entrega.
4. El límite por archivo evita materializar un archivo arbitrariamente grande. No introduce cuotas globales del directorio ni de todos los archivos de una invocación. Las salidas mayores requieren un flujo de artifacts/streaming específico; por ahora se rechazan explícitamente.
5. La captura de comandos administrativos de instalación continúa separada del runner de versiones; `installer.probe_command` conserva su comportamiento histórico de captura. No se certificó la ejecución real de recetas ni la preparación de servicios del sistema.
6. La protección común se instala al resolver el catálogo builtin. Las llamadas directas a funciones handler y los plugins externos deben adoptar `with_execution_contract` si requieren la agregación de manifiestos; el gateway continúa siendo la frontera obligatoria para autorización y scope.

No se declara el ecosistema listo para operar únicamente a partir de este inventario. El resultado entregado es un contrato más estricto, pruebas reproducibles y estados de disponibilidad que hacen visibles las verificaciones pendientes.
