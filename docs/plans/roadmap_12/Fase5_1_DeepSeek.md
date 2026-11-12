# Fase 5, paso 1 — Integración DeepSeek

**BAJIOWARE · 13 de octubre de 2026**

Se implementó `DeepSeekClient` como especialización de `OpenAIClient`, con configuración, construcción de mensajes, normalización de respuestas, reservas TPM/RPM y reintentos propios. Los otros adaptadores mantienen su implementación y selección histórica.

## Identificador y configuración

El identificador público de V4.1-Flash es **`deepseek-flash`**, según el [anuncio oficial](https://api-docs.deepseek.com/news/news260910/). Se normaliza la entrada previa `deepseek-v4.1-flash` a ese identificador. `deepseek-chat` se conserva como identificador explícito para instalaciones que lo utilicen; su disponibilidad depende del endpoint. No se promete que un nombre legado siga disponible en el servicio actual.

```python
client = LLMFactory.create(LLMConfig(
    provider=LLMProvider.DEEPSEEK,
    model="deepseek-flash",
    # Si se omite api_key, DeepSeekClient lee DEEPSEEK_API_KEY.
    base_url="https://api.deepseek.com",
    max_tokens=4096,
))
response = await client.complete(
    messages,
    response_format={"type": "json_object"},
)
action = parse_react_response(response.content)  # DTO Pydantic v2 de fase 3
```

La URL predeterminada es `https://api.deepseek.com`; se conserva una URL explícita, incluido el formato histórico `/v1`. El SDK existente transmite la clave mediante Bearer y procesa SSE. No se añadieron dependencias ni se hicieron llamadas reales a DeepSeek.

El [perfil de ejemplo](deepseek_primary.env.example) selecciona DeepSeek como principal mediante `NEXUS_LLM_DEFAULT_PROVIDER=deepseek`. Debe suministrarse `DEEPSEEK_API_KEY` desde el entorno o el gestor de secretos. No se modificaron credenciales ni configuraciones personales. La configuración TOML acepta el proveedor y el wizard lo ofrece como opción 7, conservando las opciones 1–6.

## Peticiones y respuestas

`DeepSeekClient._payload` construye copias de los mensajes: conserva las instrucciones de sesión e incorpora `config.system_prompt`. Maneja una lista vacía sin indexarla y rechaza peticiones sin mensajes. Transmite `max_tokens`, temperatura, `stop` y `top_p` cuando corresponden. Flash utiliza por defecto `thinking=disabled`, compatible con el historial textual existente; se puede pedir `thinking="enabled"` explícitamente. El razonamiento del proveedor no se concatena al contenido enviado al parser.

El modo JSON envía `response_format={"type":"json_object"}` e instrucciones explícitas para devolver un objeto. ReAct lo solicita automáticamente para este adaptador; las llamadas generales conservan salida de texto. La [documentación de JSON Output](https://api-docs.deepseek.com/guides/json_mode/) exige ambas partes. Se rechazan contenido vacío, JSON duplicado/no válido, arrays como respuesta estructurada y finales truncados. La validación semántica de las acciones sigue perteneciendo al parser y a los DTO, no a un diccionario permisivo dentro del cliente.

En streaming se solicita consumo mediante `stream_options.include_usage`. Se aceptan tanto chunks sin choices como estadísticas incluidas en el chunk final, de acuerdo con el [contrato Chat Completions](https://api-docs.deepseek.com/api/create-chat-completion/). Se preservan ceros reales de uso. Si no se recibe uso, no se inventa un conteo exacto: se conserva la estimación únicamente en el pacer y se indica `usage_available=false` en los metadatos del resultado streaming.

`LLMResponse` conserva modelo informado, proveedor, tokens de entrada/salida y duración. Un stream sin marcador final o interrumpido no publica `last_stream_response` como éxito. El stream se cierra y su reserva se liquida también al cancelar.

## Reservas y recuperación

DeepSeek publica [límites de concurrencia por cuenta](https://api-docs.deepseek.com/quick_start/rate_limit/), no una cuota universal de TPM/RPM. Los valores siguientes son política local configurable:

| Variable | Predeterminado | Efecto |
|---|---:|---|
| `DEEPSEEK_TPM` | 1.000.000 | Presupuesto estimado de tokens por ventana de 60 s |
| `DEEPSEEK_RPM` | 60 | Intentos por ventana de 60 s |
| `NEXUS_LLM_TPM_PACING` | activado | `0` desactiva este control local, incluidos TPM/RPM |
| `NEXUS_LLM_BACKOFF_SECONDS` | 2 | Base exponencial de reintentos |
| `DEEPSEEK_TIMEOUT` | 180 | Lectura máxima de una completion, en segundos (mínimo 120) |
| `DEEPSEEK_MAX_ATTEMPTS` | 4 | Intentos totales del cliente ante fallo transitorio (1–8) |
| `NEXUS_LLM_REQUEST_TIMEOUT` | 300 | Guarda exterior del router; debe superar el timeout del cliente |

Un límite individual igual a cero desactiva esa dimensión. Valores negativos o no enteros se rechazan.

```python
reservation = await pacer.reserve("deepseek", estimated_tokens=estimate)
try:
    response = await send_request()
finally:
    pacer.settle(reservation, actual_tokens)  # None conserva la estimación
```

La reserva es atómica mediante un lock corto; la espera ocurre fuera del lock. Cuenta la petición antes del envío y evita el defecto de dos solicitudes que consultan simultáneamente el mismo margen disponible. La estimación conservadora incluye bytes UTF-8 de todos los mensajes, sobrecarga por mensaje y la reserva de salida. Al recibir uso real se sustituye la reserva, sin contar dos veces. Una petición que excede por sí sola el TPM configurado falla inmediatamente. Sin uso fiable, se mantiene el cargo estimado; los intentos fallidos conservan su plaza RPM.

El cliente eleva el timeout de lectura por encima de los 60 s históricos (`httpx.Timeout`: lectura `DEEPSEEK_TIMEOUT`, conexión/escritura/pool cortas) para que un proveedor lento pero vivo no corte el turno ReAct. El presupuesto de lectura se rearma en cada chunk del stream, así que la latencia sostenida del proveedor no provoca desconexiones prematuras.

Se reintentan con backoff exponencial, jitter y consideración de `Retry-After` numérico tanto los estados transitorios (408/409/425/429/500/502/503/504) como los cortes de transporte (timeout de conexión/lectura, socket caído), hasta `DEEPSEEK_MAX_ATTEMPTS` intentos totales. Autenticación, petición malformada y otros estados terminales no se reintentan ni incluyen cuerpos del proveedor en el mensaje de error. Cada reintento es una petición HTTP nueva: toma su propia reserva del pacer y se liquida una sola vez, de modo que un fallo transitorio no duplica la contabilidad del turno. Streaming solo reintenta antes de entregar contenido; no repite deltas parciales. Se desactivan los reintentos internos del SDK para que cada intento pase por el pacer. La recuperación exterior de ReAct mantiene su comportamiento histórico y puede pedir una nueva completion tras fallar el turno streaming.

**Límite de alcance:** el pacer se comparte entre clientes del mismo proceso, no entre hosts/procesos. Los despliegues multiworker deben repartir los presupuestos locales o aportar coordinación distribuida. La estimación no sustituye al tokenizer/facturación del proveedor ni garantiza ausencia total de 429; los errores se recuperan hasta agotar el presupuesto de reintentos.

## Archivos y verificación

- `llm/abstraction.py`: adaptador, factory, payload y normalización.
- `llm/limits.py`: reservas atómicas, liquidación, RPM y configuración DeepSeek; APIs históricas preservadas.
- `agent/react_support.py`: selección de JSON para turnos del adaptador compatible.
- `cli/llm_env.py`, `config/schema.py`, `cli/wizard.py`: selección como principal y configuración persistente.
- `tests/unit/test_deepseek_provider.py`: transporte HTTP/SSE simulado, autenticación, parámetros, JSON→DTO, 429/503, interrupciones, RPM y concurrencia.

| Comprobación | Resultado |
|---|---|
| Suite completa con SQLite y PostgreSQL temporal; E2E externo desactivado | **2.965 passed, 35 skipped**, 111,98 s |
| Proveedores, streaming, selección, límites y ReAct; prueba adicional de rol system incluida | **61 passed**, 3,64 s |
| `make lint typecheck syntax` | Correcto; mypy revisó 93 archivos acumulados de las fases |
| `mypy --strict` de `limits.py` y `cli/llm_env.py` | Correcto |
| `git diff --check` | Correcto |

La prueba adicional de rol system se añadió después de recopilar la suite completa y se validó con la batería final de 61 pruebas. La advertencia existente corresponde a `google.genai` bajo Python 3.14. Las omisiones no se cuentan como aprobaciones. PostgreSQL temporal quedó detenido.

Evidencia: `suite completa`, `proveedores`, `lint/mypy/sintaxis`, `mypy estricto`. Las pruebas no certifican una clave real ni disponibilidad comercial del modelo para una cuenta determinada.
