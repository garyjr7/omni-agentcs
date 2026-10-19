# ADR-005: Cobertura por servicio con veredicto, no un subagente por puerto

- Estado: aceptado
- Fecha: 2026-10-19

## Contexto

Los runs de RootMe, Blue, Blackbox y Vulnversity se arreglaron uno a uno: cada
sala añadía una regla o una skill que resolvía *esa* sala. Eso no generaliza. La
siguiente prueba de penetración tendrá otros puertos, otra versión vulnerable y
otro vector, y el agente volvería a atascarse en el mismo patrón: insiste en el
servicio que ya sabe muerto mientras otro puerto sigue sin explorar.

La propuesta inicial fue lanzar un subagente por cada puerto abierto (5 puertos
→ 5 agentes). Se descartó:

- **Coste**: cada subagente reenvía prompt de sistema y catálogo por turno
  (~5–8 k tokens); cinco ramas multiplican el gasto sin garantizar cobertura.
- **Coordinación**: los hallazgos de ramas distintas deben converger en el mismo
  blackboard; un subagente que descubre una credencial en FTP tiene que
  entregarla al que ataca SSH, y no existe hoy un bus de resultados entre
  perfiles.
- **El fallo medido no era falta de paralelismo**: en Blackbox el agente seguía
  probando el servicio parcheado *teniendo* otros puertos abiertos; en Simple CTF
  el plan cerraba `enumeration` con el primer endpoint. Lo que faltaba era
  contabilidad de superficie y un cierre explícito de ramas, no más hilos.

## Decisión

Se introduce un **ledger determinista de superficie** (`nexus_core/agent/coverage.py`)
que se calcula desde el blackboard en cada turno y viaja en el prompt:

1. Cada hecho `service` (host, puerto, protocolo, producto, versión) es un ítem.
2. Cada ítem recibe un estado derivado de la evidencia:
   `pendiente` → `sondeado` → `comprometido`, o `descartado`.
3. `descartado` exige un hecho tipado nuevo, **`barrier`**, con la razón
   (parcheado, sin vector, requisito que no se tiene). Es la memoria que impide
   volver a atacar un callejón. Un barrier del agente cierra la rama aunque un
   nmap posterior redescubra el puerto.
4. El bloque `COBERTURA DE SERVICIOS` muestra el mapa y la `FRONTERA` (cuántos
   servicios siguen sin veredicto y cuál es la siguiente rama). La **regla**
   viaja con el dato: no se paga en el prompt estático, solo en los turnos que
   tienen superficie (el techo de presupuesto por turno no cambia).
5. Una corrección determinista (`pivot_hint`) se inyecta una vez por run cuando
   la acción apunta a una rama ya `descartada`, o cuando la racha sin hechos
   nuevos alcanza el umbral de estancamiento y aún hay ramas abiertas. Ordena
   registrar el veredicto y pasar a la siguiente rama concreta.

No se añaden tools ni perfiles: el agente sigue siendo uno, con el catálogo
completo (`omni`). No se cambian los estados del planner: el ledger es el mapa
que el modelo razona, no una condición de cierre (una condición así podría dejar
un run en `enumeration` para siempre por un puerto señuelo; para eso ya existe
el techo de endpoints y la escalada por enumeración agotada).

## Consecuencias

**Positivas**

- Es genérico por construcción: no menciona salas, productos ni CVEs; funciona
  con cualquier superficie que descubra el recon.
- Es barato: sin llamadas al modelo, sin procesos, sin tools nuevas.
- Es auditable: `react.coverage_pivot` registra foco, estado, ramas abiertas y
  el texto exacto inyectado; el `barrier` queda en el blackboard con procedencia.
- Encaja con lo existente: `nexus.knowledge.record_fact` ya valida tipos y el
  verificador sigue siendo la única fuente de evidencia verificada.

**Límites explícitos**

- El `barrier` lo declara el agente, no un verificador: documenta una decisión,
  no demuestra una ausencia de vulnerabilidad.
- El ledger no altera fases ni cierra el engagement; un run puede terminar con
  ramas pendientes si el objetivo ya se cumplió.
- El trabajo profundo sigue siendo secuencial (una rama a la vez). El ledger
  evita la fijación, no reduce el wall-clock con paralelismo real.
- La extracción de `host:port[:proto]` no cubre literales IPv6 con corchetes;
  el parser de recon ya normaliza los servicios a IPv4/hostname.

## Alternativas consideradas

- **Subagente por puerto**: rechazada por coste, coordinación y porque el fallo
  medido era de contabilidad, no de paralelismo. Queda como línea futura solo si
  existe un bus de hechos entre perfiles y un presupuesto por rama medido.
- **Exigir veredicto para cerrar `enumeration`**: rechazada; convierte un puerto
  señuelo en un bloqueo del plan y rompe el contrato de cierre por evidencia.
- **Una skill nueva por tipo de servicio**: rechazada como mecanismo principal;
  las skills son recetas que el modelo carga al atascarse, no estado del
  engagement. El ledger y el `barrier` sí son estado durable.
