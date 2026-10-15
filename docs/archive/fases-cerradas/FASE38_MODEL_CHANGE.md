# Fase 3.8 — Cambio de modelo por defecto (solo Groq)

**Autor:** BAJIOWARE · Team Red
**Rama:** `feat/model-change-phase-3-8` (desde `efda931`, Fase 3.7)
**Estado:** implementado y verificado en este entorno
**Objetivo de la fase:** que el agente arranque por defecto con el **mejor modelo
gratuito de Groq** para pentesting ético, y dejar por escrito por qué se evaluó
ese conjunto y no otro.

---

## 1. Alcance: el encargo cambió a "solo Groq"

El encargo original de la Fase 3.8 era **cambiar el modelo por defecto a Pony
Alpha (GLM-5) vía OpenRouter**. El operador lo **descartó explícitamente**:

> *"hay que continuar con Groq solamente e indica que yo no quise [OpenRouter]
> porque la configuración es mucha ahora; continúa con el plan que creaste para
> esta fase pero con la API de Groq que ya tenemos."*

Por tanto, esta fase **no** añade OpenRouter, **no** añade proveedores
secundarios y **no** toca la configuración de red. El plan se conserva (elegir
modelo por defecto con evidencia); el proveedor sigue siendo **Groq como único
proveedor**.

### Por qué se descartó OpenRouter (evidencia, queda documentada)

1. **`openrouter/pony-alpha` ya no existe.** `GET https://openrouter.ai/api/v1/models`
   (466 modelos) no lo contiene, y una llamada real a `chat/completions` devuelve
   **HTTP 404**: *"Pony Alpha was a stealth model revealed on February 11th as an
   early testing version of GLM-5."*
2. **La cuenta no tenía crédito disponible** (`total_credits` ≈ `total_usage`), y
   las alternativas verificadas (`z-ai/glm-5`, `z-ai/glm-5.3-flash`) son de pago.
3. **Decisión del operador:** el coste de configuración no se justifica ahora.
   Solo modelos **gratuitos**.

Nada de esto se implementó: es el registro de por qué **no** se hizo.

---

## 2. Inventario real de modelos (con la key del operador)

`GET https://api.groq.com/openai/v1/models` → **11 modelos**. Solo 4 son
utilizables como chat del agente (contexto 131 072):

| Modelo | Contexto | TPM gratis | ¿Candidato? |
|---|---|---|---|
| `openai/gpt-oss-120b` | 131 072 | 8 000 | Sí (era el default) |
| `openai/gpt-oss-20b` | 131 072 | 8 000 | Sí |
| `qwen/qwen3.8-27b` | 131 072 | 8 000 | Sí |
| `openai/gpt-oss-safeguard-20b` | 131 072 | **2 000** | **No** (ver §4) |

El resto son modelos de voz/guardas (`whisper-*`, `*-prompt-guard-*`,
`allam-2-7b` de 4 KB de contexto) y no sirven para el bucle ReAct.

Límites del tier gratis (fuente pública, sep-2026): **30 RPM · 1 000 RPD ·
8 000 TPM · 200 000 TPD**, idénticos para los tres viables. Coincide con
`PROVIDER_TPM["groq"] = 8_000` en `nexus_core/llm/limits.py` (sin cambios).

---

## 3. Metodología: banco de pruebas **fiel al contrato real**

El agente **no usa function calling nativo**: el modelo devuelve **JSON de
texto** que `nexus_core/agent/parser.py::parse_react_response` decodifica y que
`nexus_core/kernel/schema_validation.py` valida contra el `input_schema` de cada
tool. Evaluar con *tool calling* nativo habría sido infiel, así que el banco
reutiliza, sin reimplementar:

- `nexus_core/agent/prompts.py::render_system_prompt` (prompt real, anti-injection),
- `nexus_core/tools/registry.py::durable_tool_definitions` (catálogo real: 43 tools),
- `nexus_core/agent/subagents.py::select_for_plan` + `filter_catalog`
  (subagente real: `recon`, 13 tools),
- `nexus_core/agent/parser.py::parse_react_response`,
- `nexus_core/kernel/schema_validation.py::validate`.

Prompt de sistema resultante: **9 933 caracteres**. Cada modelo pasa **3 pasos
reales de la cadena Bounty Hacker**:

1. `it1` sin datos → se espera `nexus.recon.nmap` (profile `full_tcp`).
2. `it2` puertos 21/22/80 abiertos → se espera enumeración.
3. `it3` FTP anónimo con `locks.txt` → se espera recuperar/usar el loot.

---

## 4. Resultados

| Modelo | JSON/esquema (3 pasos) | Veredicto |
|---|---|---|
| `openai/gpt-oss-120b` | 3/3 válidos | Viable, pero **falló el E2E #4** |
| `openai/gpt-oss-20b` | 3/3 válidos | Viable |
| `qwen/qwen3.8-27b` | 3/3 válidos | Viable |
| `openai/gpt-oss-safeguard-20b` | **0/3** | **No viable** |

**Hallazgos que sí discriminan:**

1. **`gpt-oss-safeguard-20b` es inusable aquí.** Su TPM gratis es 2 000, menor que
   el propio prompt del sistema (~3 100 tokens): Groq responde **HTTP 413**
   incluso tras reducir `max_tokens` a 375. Se descarta por **presupuesto**, no
   por calidad.
2. **`qwen/qwen3.8-27b` exige un turno `user`.** En el bucle real devolvía
   **HTTP 400** — *"No user query found in messages"* — porque `react.py`
   construye cada iteración como `[system] + historial` y **la iteración 1 no
   tenía ningún mensaje de usuario**. Es un **bug del bucle**, no del modelo:
   una conversación sin turno de usuario es inválida para plantillas estrictas.
   Corregido en esta fase (ver §5).
3. **Los 3 modelos viables empatan en JSON/esquema de un solo turno.** El banco
   no los separa: ninguno encadenó de forma ideal (los tres repitieron `nmap`
   incluso con el FTP ya enumerado), lo que **reproduce el hallazgo del E2E #4**
   (`TEST_E2E_BOUNTY_HACKER_RUN4.md` §5–6): el fallo de `gpt-oss-120b` es de
   *instruction-following*, no de esquema.

Holgura de TPM: con 8 000 TPM y ~3 100 tokens por turno (prompt + reserva de
salida) el techo práctico es **~2 llamadas/minuto**. Es el cuello real del E2E,
no el modelo.

---

## 5. Decisión y cambios

**Modelo por defecto: `qwen/qwen3.8-27b`.**

Justificación, en orden de peso:

1. Es el **único candidato de familia distinta**. Los otros dos viables
   (`gpt-oss-120b`/`gpt-oss-20b`) son hermanos del modelo que **ya falló** el
   E2E #4; no hay motivo para esperar un cambio de comportamiento.
2. Contexto 131 072, sin *guardrails* de contenido (el `safeguard` sí los lleva,
   y encima no cabe).
3. JSON/esquema válidos contra el contrato real en los 3 pasos.
4. Mismo presupuesto de tier gratis (8 000 TPM) que los demás.

Cambios aplicados (coherentes entre sí):

| Fichero | Cambio |
|---|---|
| `nexus_core/config/schema.py` | `DEFAULT_MODELS["groq"]` y `LlmConfig.default_model` → `qwen/qwen3.8-27b` |
| `nexus_core/cli/llm_env.py` | `PROVIDER_MODEL_ENVS["groq"]` → `("GROQ_MODEL", "qwen/qwen3.8-27b")` |
| `nexus_core/llm/abstraction.py` | fallback de `create_from_env` para groq → `qwen/qwen3.8-27b` |
| `nexus_core/cli/tui/pricing.py` | fila `qwen3.8-27b: (0.0, 0.0)` (tier gratis: coste real 0) |
| `nexus_core/agent/react.py` | **fix**: `with_kickoff_user_turn` garantiza un turno `user` en cada iteración |
| `~/.config/omni/config.toml` | `llm.default_model` → `qwen/qwen3.8-27b` (backup en `config.toml.bak-38`) |

Tests añadidos: `test_default_model_phase38.py` (coherencia schema/CLI/factory y
coste 0) y `test_react_kickoff_turn.py` (el turno `user` se añade una sola vez).

**No se tocó** la gobernanza: scope firmado HMAC, cadena de auditoría,
fail-closed y anti-injection siguen intactos.

---

## 6. Cómo revertir

```bash
# 1. Volver al modelo anterior en código y config
git revert <commit-de-esta-fase>          # o editar los 4 puntos de §5
cp ~/.config/omni/config.toml.bak-38 ~/.config/omni/config.toml

# 2. O, sin tocar código, solo para este entorno:
export GROQ_MODEL="openai/gpt-oss-120b"   # gana sobre el config
```

El fix del turno `user` **no** debe revertirse: es un bug real del bucle y es
inocuo para los modelos que ya aceptaban el prompt sin usuario.

---

## 7. Limitaciones (honestidad)

1. **Un solo banco por modelo, `temperature` sin fijar.** No se midió
   reproducibilidad; el empate de §4 es orientativo.
2. **El banco no reproduce el fallo del E2E #4.** Solo ejercita un turno por
   paso; el fallo real fue multi-turno (registrar hechos, seguir metodología).
   La decisión se apoya también en la evidencia multi-turno de RUN4.
3. **La red del entorno es intermitente.** El `resolv.conf` lista primero
   `8.8.8.8`/`8.8.4.4`, que **no responden**, así que cada resolución de nombres
   cuesta ~8 s (y `apt` parece colgado). Ver §8.
4. El resultado del E2E #5 con el nuevo default está en
   `TEST_E2E_BOUNTY_HACKER_RUN5.md`.

---

## 8. Anexo — lentitud reportada por el operador (red, no código)

**Confirmado: no se modificó ninguna configuración del sistema en esta fase.**

Causa medida: `/etc/resolv.conf` es un fichero estático que lista
`8.8.8.8`, `8.8.4.4` y `10.0.0.1`, pero **los dos primeros no responden**
(solo contesta el DNS virtual de VMware). glibc espera a los DNS muertos antes
de usar el bueno:

| Resolución de `deb.debian.org` | Tiempo |
|---|---|
| Tal como está | **8,08 s** |
| `RES_OPTIONS=timeout:1 attempts:1` | **2,01 s** |
| Directa a `10.0.0.1` | **0,06 s** |

Arreglo (requiere `sudo`; el operador debe ejecutarlo):

```bash
sudo cp /etc/resolv.conf /etc/resolv.conf.bak
printf 'nameserver 10.0.0.1\nsearch localdomain\n' | sudo tee /etc/resolv.conf
```

---

## 9. Atribución

BAJIOWARE · Team Red. Fase 3.8 sobre `efda931` (Fase 3.7). Evidencia del modelo
anterior: `TEST_E2E_BOUNTY_HACKER_RUN4.md` §5–6.
