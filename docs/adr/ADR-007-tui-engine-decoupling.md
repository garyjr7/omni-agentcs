# ADR-007: Desacoplar el motor del agente de la TUI antes de considerar Rust

- Estado: propuesto
- Fecha: 2026-11-13
- Nota de numeración: el `ADR-005` solicitado ya está ocupado por
  `ADR-005-surface-coverage-ledger.md`; este documento usa el siguiente número
  libre para no duplicar identificadores.

## Contexto

La TUI actual está implementada en Python con `prompt_toolkit` y `rich`. El
operador quiere una experiencia más avanzada y pregunta si Python es el límite,
o si conviene reescribir la interfaz en Rust como hacen Cursor, Claude Code o
Zed.

La respuesta corta es: **el límite no es Python; el límite es el acoplamiento
entre la sesión, el motor ReAct y la capa de presentación**. Una reescritura en
Rust antes de separar esas responsabilidades trasladaría el mismo problema a
otro lenguaje y multiplicaría el coste.

### Cómo está construido hoy

- `nexus_core/agent/react.py` y `nexus_core/agent/react_coordinator.py` no
  importan nada de `nexus_core/cli/`. El motor ya es, por sí mismo, usable desde
  la CLI, el worker y el modo headless.
- `OmniSession` (`nexus_core/cli/session.py`) es el punto donde se juntan las
  responsabilidades: construye `TuiSession`, resuelve el cliente LLM, crea el
  `run`, llama a `run_react_loop`, arranca el hilo que lee eventos y, además,
  escribe directamente en `_tui` (pensamiento, respuesta, tarjetas, paneles,
  estado, cancelación).
- `TuiSession` (`nexus_core/cli/tui/session.py`) ejecuta la aplicación de
  `prompt_toolkit` en su propio hilo y programa las mutaciones con
  `call_soon_threadsafe`; el motor corre en el hilo principal con
  `asyncio.run`. Ya existe, por tanto, una separación de hilos, pero no un
  contrato entre ambos lados.
- El motor publica eventos durables (`react.action`, `tool.complete`,
  `react.turn_telemetry`, `react.scope_violation`, etc.) en el `ControlStore`, y
  `_stream_run_events` los relee para pintarlos. Ese es el mejor seam existente:
  ya hay un flujo de eventos, aunque el consumidor sea un método privado de la
  misma sesión.
- Las decisiones que requieren al humano (aprobación de una tool) no viajan por
  eventos: el motor llama a un callback síncrono
  (`ReActConfig.on_approval_needed`) que termina leyendo la terminal. Es el
  punto más difícil de extraer a un daemon y el que un protocolo debe modelar
  explícitamente.

### Qué se puede afirmar sobre Python

`prompt_toolkit` y `rich` ya permiten pantalla alternativa, layouts, mouse,
autocompletado, overlays, streaming token a token, paneles, historial y tareas
en segundo plano. La TUI actual usa varias de esas capacidades. El rendimiento
de pintado no es el cuello de botella: el coste dominante es la latencia del
LLM y la coordinación de eventos, no dibujar unas decenas de líneas por segundo.

Las carencias de experiencia que se perciben vienen, sobre todo, de:

1. `OmniSession` mezcla estado de dominio, orquestación y presentación.
2. Demasiados puntos escriben en `_tui` directamente, así que el estado visual
   no tiene una única fuente de verdad.
3. El canvas, los paneles y el flujo de aprobación comparten hilos y callbacks
   en vez de hablar un protocolo pequeño y verificable.
4. No existe un modo "cliente remoto" ni una forma limpia de conectar otra
   interfaz sin reutilizar la sesión Python completa.

Ninguno de esos cuatro puntos se arregla cambiando de lenguaje; se arreglan
separando responsabilidades.

## Decisión

No reescribir la TUI en Rust antes de la v1.0.0.

Sí extraer, antes de la v1.0.0, una frontera estable entre motor y presentación:

### 1. Contrato `EngineClient`

La TUI no debe conocer `run_react_loop`, `ExecutionContext` ni el `ControlStore`.
Debe hablar con un objeto que cumpla algo equivalente a:

```text
submit_objective(text, engagement_id, options) -> run_id
ask(question, engagement_id) -> answer
cancel(run_id)
approve(request_id, decision)
resume(run_id, after_sequence)
events(after_sequence) -> stream de EngineEvent
```

En la primera fase ese `EngineClient` puede ser un adaptador **en proceso** que
llama a lo que hoy hace `OmniSession`. No hace falta un daemon para empezar.

### 2. `EngineEvent` como única salida del motor

El motor ya escribe eventos durables; el contrato los formaliza:

```text
{ "run_id": "...", "sequence": 42, "type": "tool.complete", "payload": {...} }
```

La TUI solo renderiza eventos. No llama a `set_thought`, `append_card` o
`append_result_block` desde el orquestador; esos métodos pasan a ser detalles
del renderer que consume el stream. La secuencia permite reconectar y reanudar
sin perder eventos.

### 3. Transporte local: UDS + JSON-RPC/NDJSON, no gRPC todavía

Para un daemon local, la opción recomendada es un Unix Domain Socket con
JSON-RPC 2.0 sobre NDJSON (el mismo estilo que LSP):

- socket en `$XDG_RUNTIME_DIR/omni/engine.sock`, permisos `0600`;
- validación de par con `SO_PEERCRED` en Linux;
- request/response para `submit_objective`, `ask`, `approve`;
- notificaciones para `cancel` y para el stream de eventos;
- reanudación por `run_id` + `after_sequence`;
- errores como objetos JSON con `code`, `message` y un `data` saneado, nunca un
  volcado del SDK.

gRPC queda para una fase remota/multiusuario: añade codegen, dependencias,
TLS y gestión de versiones que un socket local no necesita. Si más adelante se
quiere gRPC, el contrato de eventos y métodos sigue siendo el mismo.

### 4. Migración por fases

| Fase | Cambio | Cuándo |
|---|---|---|
| 0 | Definir `EngineEvent`, `EngineClient` y un transporte en memoria | Antes de v1.0 |
| 1 | Mover `run_objective` y `/ask` detrás de `EngineClient`; la TUI deja de llamar al motor directamente | Antes de v1.0 |
| 2 | Daemon `omni engine serve` + UDS/JSON-RPC; autoarranque y fallback en proceso | Después de v1.0, salvo que se necesiten varios clientes |
| 3 | TUI Rust o second frontend contra el mismo protocolo | v4.0, solo con paridad funcional y métricas de UX |

La fase 0 y la fase 1 son las que desbloquean el diseño: permiten testear la TUI
con un motor falso, eliminan el "god object" y preparan el daemon sin cambiar la
experiencia del operador.

### 5. Qué debe seguir siendo cierto

- El motor conserva el scope firmado, la aprobación humana, el sandbox, el
  journal y la auditoría. El daemon no relaja ninguna de esas garantías.
- La aprobación sigue siendo fail-closed: si el cliente se desconecta, la
  petición no se aprueba sola.
- Los secretos y las claves LLM viven en el proceso del motor, no en el cliente
  de UI.
- El modo headless/worker sigue funcionando sin TUI y sin daemon.
- El protocolo tiene versión y rechaza clientes incompatibles.

## Consecuencias

### Positivas

- La TUI se vuelve testeable sin `prompt_toolkit`, sin terminal y sin LLM real.
- Un frontend Rust, una web o un cliente remoto pueden reutilizar el mismo
  motor.
- Un fallo de render no tumba el run; un reinicio de la TUI puede reanudar por
  secuencia.
- Se puede medir la UX (latencia de evento, tiempo hasta el primer token,
  eventos por run) sin mezclarla con la lógica del agente.
- La migración es incremental y reversible: el adaptador en proceso mantiene el
  comportamiento actual mientras se prueba el protocolo.

### Negativas y riesgos

- Añade una capa IPC, versionado de protocolo y gestión de ciclo de vida del
  daemon.
- La aprobación interactiva es un request bidireccional: hay que definir
  timeouts, cancelación y qué pasa si el cliente desaparece.
- Hay que evitar doble render o eventos duplicados al reconectar; la secuencia
  durable es obligatoria.
- Empaquetar un daemon y un cliente en Windows/macOS requiere trabajo extra;
  el fallback en proceso debe seguir existiendo.
- El daemon concentra más privilegios: hay que endurecer permisos del socket,
  autenticación local y logs.

## Alternativas consideradas

- **Reescribir la TUI en Rust ahora**: rechazada. No arregla el acoplamiento,
  duplica la superficie de tests y retrasa la v1.0.0 varios meses. Rust sería
  útil después de congelar el protocolo, no antes.
- **Migrar a Textual**: puede mejorar el layout y el estado, pero sigue siendo
  una decisión de framework, no de arquitectura. Es compatible con la fase 1 y
  puede evaluarse como renderer alternativo.
- **gRPC desde el primer día**: rechazada para local. Es más pesado de operar y
  de depurar que un UDS con NDJSON; se reserva para despliegues remotos.
- **Mantener todo en proceso**: rechazada como estado final. Es el punto de
  partida (fase 0/1) y sigue siendo el fallback, pero impide clientes
  alternativos y aislamiento de fallos.

## Recomendación

Antes de la v1.0.0:

1. Extraer `EngineClient` y `EngineEvent` con un adaptador en proceso.
2. Hacer que la TUI consuma eventos y comandos, no métodos privados del motor.
3. Añadir tests de contrato con un motor falso y con replay por secuencia.

Después de la v1.0.0:

4. Implementar el daemon UDS/JSON-RPC y el autoarranque.
5. Medir si la UX sigue limitada por el renderer. Si la respuesta es sí,
   construir una TUI Rust contra el protocolo, no un reemplazo del motor.

**No recomiendo Rust para la v1.0.0 ni para "arreglar" la UX actual.** Python
puede sostener la TUI; lo que falta es una frontera limpia entre quien decide y
quien dibuja.
