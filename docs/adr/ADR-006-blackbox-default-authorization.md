# ADR-006: Caja Negra por defecto — la Kill Chain completa, limitada solo por el RoE

- Estado: aceptado
- Fecha: 2026-10-21

## Contexto

El run V9 (Hijack) encontró el vector y se detuvo en el primer muro técnico: el
export NFS era visible, `mount` pedía root y el sandbox no lo tiene; el agente
documentó el callejón y cerró la rama. El prompt tampoco ayudaba: decía "si
necesitas una herramienta que no existe, responde `task_complete`" y "el scope
es SAGRADO, si falla reporta y para". Leído por un modelo, eso no es una regla
de autorización: es una lista de excusas para no seguir.

El resultado fue un agente que trata cada engagement como un puzzle lineal con
permiso implícito para una sola técnica, cuando la autorización real de una
prueba de penetración es todo lo contrario: **si el cliente no ha prohibido una
técnica en el objetivo o en el RoE, está autorizada**, y el trabajo del agente es
agotar la Cyber Kill Chain completa antes de documentar un límite.

## Decisión

### 1. Autorización por defecto (prompt)

`REACT_SYSTEM_PROMPT` incorpora `BLACK_BOX_PHILOSOPHY_PROMPT`, que se renderiza
**siempre** (es política del bucle, no capacidad de un subagente):

- el objetivo autoriza **todas** las fases de la Cyber Kill Chain sobre el scope
  firmado: reconocimiento, weaponización, entrega, explotación, instalación
  (persistencia), C2 y acciones sobre el objetivo (exfiltración);
- no hay límites artificiales por fase ni por herramienta;
- **solo** el objetivo o el RoE restringen ("no uses DoS", "solo reporta, no
  explotes", "no hagas pivoteo"). Si lo dicen, se obedece; si no lo dicen, es
  vía libre dentro del scope;
- un muro técnico (puerto cerrado, sandbox sin root, binario ausente) no es el
  final: se pivota, se usa otra tool o se instala lo que falte.

### 2. Precedencia y frontera

El orden es explícito y no se solapa:

1. **Scope firmado** (`EngagementScope`): qué *targets* se pueden tocar. No
   cambia, no se relaja y sigue validándose antes del handler y de la política.
   El prompt lo dice así: "el scope limita los TARGETS, nunca las técnicas ni
   las fases dentro de ellos".
2. **Objetivo / RoE**: única fuente de restricciones de *técnica* ("no DoS",
   "solo reporta", "sin pivoteo", "sin persistencia"). Si el operador las
   escribe, el agente obedece sin discutirlas.
3. **Por defecto**: todo lo anterior no esté prohibido, está permitido.

"N/A" no es una restricción: la ausencia de una prohibición es autorización.

### 3. Herramientas que faltan

- Binario ausente → `nexus.system.install_tool` con la receta del catálogo
  (`nfs-common`, `libnfs-utils`, `sqlmap`, …). El operador aprueba el comando
  exacto; el modelo nunca inventa argv.
- Técnica sin tool propia → `nexus.shell.exec`, el sustrato universal.
- Rendirse solo es válido cuando la técnica no existe ni como binario
  instalable; entonces se documenta el barrier, no se cierra el run.

### 4. Esperas pasivas prohibidas

`sleep`, `wait` y `timeout > 10 s` se deniegan en `nexus.shell.exec`,
`nexus.post.shell_exec` y `nexus.post.ssh_exec` con `outcome="denied"` y el
mensaje que nombra las alternativas (`nexus.post.listener` para un reverse
shell, `nexus.post.job` para un proceso, barrier + pivote si no hay plan).
El guard es léxico, honra comillas, acepta prefijos `VAR=…` y entra en
`bash -c`.

### 5. NFS sin root

`nexus.recon.nfs` enumera exports con `showmount -e` y lee con `nfs-ls` /
`nfs-cat` (libnfs, espacio de usuario). Nunca monta. Si el cliente userland no
está, devuelve `outcome="partial"` con los exports visibles y el mensaje
"Solicita al humano que monte el recurso o usa `nfs-ls` si está disponible", más
la receta de instalación. Un `showmount` ausente es `unavailable` con
`nfs-common` como instalación.

## Consecuencias

**Positivas**

- El agente deja de confundir "no sé cómo" con "no puedo": el muro técnico es
  un dato para pivotar, no un veredicto.
- Es genérico: la política no menciona salas, productos ni CVEs. Cualquier
  engagement hereda el mismo default.
- El RoE sigue siendo la palanca del operador, y el scope sigue siendo la
  frontera dura. No se ha relajado ninguna validación de target.

**Costes**

- Las dos órdenes viajan en cada turno: medido 6,819 tokens de media por turno
  (antes 6,524) y 27,831 caracteres de prompt estático. 250k de presupuesto
  compran ~36 turnos en vez de ~38; el techo por turno y el de catálogo por tool
  no se movieron.
- `nexus.recon.nfs` añade una línea de catálogo (216 caracteres) y `nfs-common`
  / `libnfs-utils` dos recetas de instalación.
- La instalación sigue requiriendo aprobación humana: la autonomía crece en
  técnica, no en privilegio local.

## Cómo restringir OMNI (operador)

En el objetivo o en el RoE, en lenguaje natural, por ejemplo:

```
Objetivo: comprometer 10.0.0.1. RoE: sin DoS, sin persistencia, sin pivoteo;
solo lectura de flags y reporte.
```

El prompt convierte cada prohibición explícita en límite de técnica. Lo que no
se prohíbe no se pregunta: se ejecuta dentro del scope firmado.
