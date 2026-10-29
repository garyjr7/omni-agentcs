# Ajuste de rendimiento — hardware, `nice` y concurrencia dinámica

**Fecha:** 2026-10-29 · **Alcance:** que un `nmap -p-`, un `gobuster` o un `john`
no puedan congelar la CLI/TUI ni tumbar la caja, y que el número de herramientas
en paralelo se derive de la máquina en vez de ser un 3 fijo.

Antes: tres tools a la vez siempre, hijas al mismo `nice` que el operador y un
`--doctor` que no decía ni cuántos núcleos había.

---

## 1. Inyección de `nice` (y `cpulimit`) en el sandbox

### Dónde

Un solo punto: `nexus_core/kernel/sandbox.py`. Todo handler ofensivo ejecuta a
través de `sandbox_for_environment(...)` y nunca lanza procesos por su cuenta
(hay tests que lo garantizan), así que la inyección cubre el camino completo sin
tocar 60 handlers.

```python
# LocalSandbox.run / LocalSandbox.open_stdio
if not argv or argv[0] not in self.allowed_programs:   # 1. allowlist primero
    raise PermissionError(...)
priority = with_priority(argv)                          # 2. prologue
process = await asyncio.create_subprocess_exec(*priority, ...)
```

`with_priority` pregunta a `nexus_core/kernel/hardware.py::priority_prefix`:

| Proceso | argv efectivo |
|---|---|
| `nmap` | `nice -n 10 nmap …` |
| `hashcat` / `john` / `aircrack-ng` | `nice -n 10 cpulimit -l 80 -- hashcat …` |
| `bash -lc "hashcat …"` | `nice -n 10 cpulimit -l 80 -- bash -lc "hashcat …"` |

### Por qué protege la TUI

La CLI y la TUI viven en el **proceso padre**, a `nice 0`. Las hijas arrancan a
`nice +10`, y `nice` se hereda por todo el árbol (`fork`/`exec`). Cuando la caja
está al 100 %, el planificador da el turno al padre: el hilo de prompt_toolkit
sigue dibujando y leyendo teclas. No es una promesa de "más rápido", es una
promesa de **prioridad**, que es lo único que hace falta para no perder el
control.

`cpulimit` va un paso más allá y limita el porcentaje real de CPU (80 % por
defecto) de las herramientas que se comen todos los núcleos. Se aplica **solo**
a una lista corta (`hashcat`, `john`, `aircrack-ng`, `aircrack`, `reaver`,
`wifite`), porque capar un `nmap` cambiaría sus tiempos de sondeo y con ellos
los resultados.

### Casos que el prologue cubre además

* **`shell.exec`**: el handler ejecuta `bash -lc "<comando>"`. `heavy_target()`
  mira la primera palabra del script, así que un `hashcat` lanzado por la shell
  genérica también recibe el tope (y un `nmap -p-` solo el `nice`).
* **`crack_hash`**: el handler lanza un cliente Python que a su vez ejecuta
  `john`. `john` hereda el `nice`, pero no el tope, así que el cliente lee
  `NEXUS_TOOL_CPU_LIMIT` (el sandbox se la pasa en el entorno) y antepone
  `cpulimit` él mismo.
* **`open_stdio`**: las sesiones interactivas (PTY, listeners) también arrancan
  nicedas; el sandbox sigue siendo el único que crea procesos.

### Límites honestos

* **Solo Linux.** `nice`/`cpulimit` son el mecanismo real aquí; en Windows/macOS
  el prologue queda vacío y solo actúan el techo de concurrencia y los timeouts.
* **OCI no lo necesita**: el contenedor ya lleva `--cpus`/`--memory`/`--pids-limit`,
  que es un límite más fuerte que `nice` dentro del host.
* **`cpulimit` es opcional** en la mayoría de distros. Si no está, el sandbox lo
  omite (la tool corre igual, solo niceda) y `--doctor` lo dice con el comando
  que lo instala.
* **La inyección nunca salta la allowlist**: se comprueba `argv[0]` original
  antes de anteponer nada, y el `nice`/`cpulimit` inyectados son del propio
  sandbox, no del modelo.
* El prologue aplicado se guarda en `SandboxResult.priority`, así que la
  auditoría puede mostrar qué se ejecutó de verdad.

---

## 2. Cómo se calcula la concurrencia dinámica

`nexus_core/kernel/hardware.py` detecta la máquina una vez (cacheado: leer
`/proc` en cada llamada es justo el tipo de I/O pequeño que hace temblar una
TUI) y de ahí sale el techo:

| Núcleos lógicos | Tools simultáneas |
|---|---|
| 1–2 | 1 |
| 3–8 | 2 |
| > 8 | 3 (tope duro: `MAX_PARALLEL_TOOLS`) |

Además, si la RAM total detectada es **menor de 4 GiB**, el techo baja a 1: con
menos memoria un segundo escaneo no acelera nada, solo mete swap.

Se usan núcleos **lógicos** a propósito: estas herramientas son sobre todo I/O
(`nmap`, `gobuster`, `httpx`) y los hyperthreads sí ayudan; lo que no ayuda es
un tercer proceso peleando por el mismo bus de memoria.

El número llega al orquestador en un solo sitio:

```python
# nexus_core/agent/parallel.py
def parallel_limit() -> int:
    return parallel_tools()      # hardware + NEXUS_PARALLEL_TOOL_LIMIT
```

`execute_calls` lo usa como `asyncio.Semaphore(limit)` y el bloque consolidado lo
publica (`concurrency`) junto al evento `react.parallel_batch`. **Nada más
cambia**: el LLM sigue recibiendo una sola observación con las N ramas, solo que
en una caja de 2 núcleos se ejecutan de una en una.

### Detección

| Fuente | De dónde salen los datos |
|---|---|
| `psutil` (preferida) | núcleos físicos/lógicos reales y RAM total/disponible |
| `/proc` (fallback) | `cpuinfo` (pares `physical id`/`core id`) y `meminfo` |
| `unknown` | sin `/proc`: se asume lo que diga `os.cpu_count()`, RAM desconocida |

`psutil` está en `nexus_core/requirements.txt` y en el lock
(`requirements-dev.lock`, `psutil==7.2.2` con hashes). Si un host no lo tiene
instalado, el detector cae a `/proc` en vez de fallar: la dependencia acelera,
no bloquea.

---

## 3. Cómo ajustarlo en tu máquina

Todo se sobrescribe con variables de entorno. `--doctor` muestra los valores
**resueltos**, incluido si el binario existe:

```bash
omni --doctor                # sección "Hardware"
omni --doctor --json | python -c "import json,sys;print(json.load(sys.stdin)['hardware'])"
```

```
Hardware:
  CPU: 2 cores · RAM: 3.8 GB
  fuente:            psutil
  RAM disponible:    2.0 GB
  tools en paralelo: 1 (hardware)
  nice:              +10 (/usr/bin/nice)
  tope CPU:          80% pero falta `cpulimit` (apt install cpulimit)
  tools pesadas:     aircrack, aircrack-ng, hashcat, john, reaver, wifite
```

### Las variables

| Variable | Por defecto | Para qué |
|---|---|---|
| `NEXUS_PARALLEL_TOOL_LIMIT` | derivado del hardware | fuerza las tools simultáneas (1 = secuencial, se recorta a 3) |
| `NEXUS_TOOL_NICE` | `10` | incremento de `nice` (0 = sin inyección, máx. 19) |
| `NEXUS_TOOL_CPU_LIMIT` | `80` | % de CPU para tools pesadas (0 = sin `cpulimit`) |
| `NEXUS_CPU_HEAVY_PROGRAMS` | lista corta | añade nombres separados por comas (`medusa,sqlmap`) |
| `NEXUS_PARALLEL_CALL_TIMEOUT` | `timeout_per_tool_seconds` | techo por llamada dentro del batch |

### Recetas

**Máquina débil (2 núcleos, 4 GB, o una VM compartida):**

```bash
export NEXUS_PARALLEL_TOOL_LIMIT=1
export NEXUS_TOOL_NICE=15
export NEXUS_TOOL_CPU_LIMIT=50
```

**Estación potente (16+ núcleos, 32 GB) y quieres aprovecharla:**

```bash
export NEXUS_PARALLEL_TOOL_LIMIT=3        # 3 es el máximo del contrato tool_calls
export NEXUS_TOOL_NICE=5                  # sigue cediendo prioridad a la TUI
export NEXUS_TOOL_CPU_LIMIT=0             # sin tope: confías en la máquina
```

**Demo o benchmarks (nada debe competir):** `NEXUS_TOOL_CPU_LIMIT=0` y
`NEXUS_PARALLEL_TOOL_LIMIT=3`.

**Diagnóstico:** `NEXUS_TOOL_NICE=0 NEXUS_TOOL_CPU_LIMIT=0` desactiva toda la
inyección (los comandos quedan idénticos a los de antes), útil para comparar.

Lo que **no** conviene: subir `NEXUS_PARALLEL_TOOL_LIMIT` por encima de 3 (el
contrato `tool_calls` no acepta más de 4 llamadas y el semáforo lo recorta) ni
bajar `NEXUS_TOOL_NICE` a 0 en una caja de 2 núcleos mientras corre `hashcat`: es
exactamente el escenario en que la TUI deja de responder.

---

## 4. TUI: por qué no se bloquea

El bucle de prompt_toolkit corre en su propio hilo (`omni-tui`); el agente corre
en `asyncio` en el hilo principal. Mientras una tool espera, el hilo de la TUI
puede redibujar, pero **todos los frames llegan por el loop del agente**
(`_dispatch` → `call_soon_threadsafe`, el streamer de eventos, el spinner). Si un
handler bloqueara ese loop, la pantalla se quedaría congelada aunque el proceso
estuviera vivo.

Por eso la ejecución de tools es 100 % asíncrona
(`asyncio.create_subprocess_exec` dentro del sandbox, nunca `subprocess.run` en
el loop) y hay un test que lo mide: `test_tui_responsiveness.py` corre un
heartbeat junto a un batch real (incluidos hijos reales del sandbox), falla si
el hueco máximo entre ticks supera 0,2 s y falla también si algo llama a
`subprocess.run` durante el batch. Además comprueba que un hilo externo -como el
de la TUI- sigue recibiendo frames (`call_soon_threadsafe`) mientras las tools
trabajan.

Con las hijas a `nice +10` y el tope de CPU puesto, el hilo de la TUI gana
además la pelea por la CPU real, que es la otra mitad del problema.

---

## 5. Verificación

```bash
pytest nexus_core/tests/unit/test_hardware.py -q            # tiers, overrides, detección
pytest nexus_core/tests/unit/test_sandbox_priority.py -q    # nice/cpulimit en procesos reales
pytest nexus_core/tests/unit/test_tui_responsiveness.py -q  # el loop no se bloquea
pytest nexus_core/tests/unit/test_parallel_tools.py -q      # el batch respeta el techo
```

Los tests de sandbox leen el `nice` real del hijo desde `/proc/<pid>/stat` y usan
un `cpulimit` falso que se sustituye por el comando: se comprueba el efecto en el
kernel, no el string del `argv`.

## 6. Límites conocidos

* **Sin cgroups.** `nice` da prioridad y `cpulimit` acota el porcentaje, pero
  ninguno pone un techo duro de memoria por proceso; eso sigue siendo trabajo del
  OCI sandbox (`--memory`, `--cpus`).
* **`nice` es herencia, no aislamiento**: un proceso que llame a `setpriority`
  para subirse la prioridad puede hacerlo (solo hacia abajo, con permisos de
  usuario normal no puede pasar de 0).
* **El `fan-out` de un objetivo por CIDR** (`session.fan_out_tool`) tiene su
  propio límite; este documento cubre el batch de `tool_calls`.
* **El tiempo no se reparte**: un batch en una caja de 2 núcleos tarda lo mismo
  que secuencial (y puede tardar algo más por el arranque de los sandboxes). La
  ganancia de paralelismo aparece a partir de 3–4 núcleos.
