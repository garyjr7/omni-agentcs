# SECURITY TODO · redacción de credenciales

Backlog de seguridad pendiente. **Este archivo no cambia comportamiento**: solo
registra hallazgos para revisarlos en una tarea aparte. El código del kernel
(`nexus_core/kernel/redaction.py`) y sus pruebas quedan intactos.

## 1. `--password=<valor>` no se redacta por el guion pegado al campo

**Estado:** abierto. Observado en `nexus_core/kernel/redaction.py`.

**Problema observado.** `sanitize_text()` localiza asignaciones con `_ASSIGNMENT`,
cuyo lookbehind es `(?<![\w-])`: la clave debe empezar detrás de algo que no sea
letra, dígito, `_` ni `-`. En una bandera con el guion pegado al nombre del campo
(`--password=...`) el carácter anterior es `-`, así que la coincidencia no se
produce y el valor viaja sin redactar. La forma sin guiones (`password=...`) sí
coincide.

Ejemplo con valores **ficticios**:

```text
entrada:  nmap --script-args=user=admin --password=FAKE-EXAMPLE -sV 10.0.0.5
hoy:      --password=FAKE-EXAMPLE
esperado: --password=[REDACTED]
```

**Alcance.** Afecta al texto libre que pasa por `sanitize_text` (flags, rutas,
mensajes). No afecta a los dicts con nombre de campo secreto, que `sanitize()`
redacta por clave.

**Cambio propuesto (fuera de esta tarea).**

1. Revisar la regla para admitir el guion pegado al nombre del campo sin abrir
   falsos positivos en identificadores que terminan en `-password` ni romper
   variantes como `--password-file=/ruta` (que no transporta el valor).
2. Añadir una prueba unitaria del kernel que fije el resultado esperado, con el
   caso anterior y al menos un valor ficticio de control por cada forma
   (`password=`, `--password=`, `"password":`).

**Resultado esperado:** `--password=[REDACTED]` en el texto presentado al
operador, sin exponer el valor.

**Fuera de alcance aquí:** no se modifica `nexus_core/kernel/redaction.py` ni
ninguna otra lógica de seguridad; esta nota es solo documentación del backlog.
