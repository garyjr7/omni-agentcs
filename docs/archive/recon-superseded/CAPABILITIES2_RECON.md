# CAPABILITIES2 — reconocimiento e historial de bloqueos

Fecha: 2026-09-30. Rama: `feat/capabilities-ad-attacks`.
Base: `02d0b7a` (`feat/capabilities-web-recon`). Árbol limpio al comenzar.

Los apartados iniciales registran el hallazgo original. Los fixes posteriores
y el nuevo pre-flight se resumen al final; los problemas de redacción y
consumo de approvals descritos originalmente ya tienen corrección verificada.

## Bloqueo verificado: redacción de credenciales

La premisa de la misión «El AuditWriter ya redacta password/hash en el
payload» no se cumple en esta revisión.

`nexus_core/kernel/audit.py:110` define los campos sensibles:

```python
secret_terms = {"password", "secret", "token", "api_key", "authorization"}
```

`hash` no está incluido. Reproducción ejecutada con datos completamente ficticios:

```python
from nexus_core.kernel.audit import AuditWriter

payload = {"arguments": {
    "username": "TestUser",
    "password": "SYNTHETIC_TEST_PASSWORD",
    "hash": "a" * 32,
}}
sanitized = AuditWriter._sanitize(payload)
print("password_redacted:", sanitized["arguments"]["password"] == "[REDACTED]")
print("hash_redacted:", sanitized["arguments"]["hash"] == "[REDACTED]")
print("hash_preserved_unchanged:", sanitized["arguments"]["hash"] == payload["arguments"]["hash"])
```

Resultado:

```text
password_redacted: True
hash_redacted: False
hash_preserved_unchanged: True
```

Esto verifica el sanitizador, no una fuga real de credenciales de un operador.
No se utilizaron secretos reales.

## Persistencia anterior al handler

`nexus_core/agent/react.py:404` llama a `memory.append_step()` con la respuesta
original del modelo y con `arguments: action.arguments` antes de invocar la
herramienta. `nexus_core/agent/memory.py:113` pasa el contenido y metadata al
store. Redactar solamente el ToolResult o la observation en un nuevo handler
no protege esa persistencia previa.

El evento `tool.invoke` del gateway, por su parte, guarda las **claves** de los
argumentos; no se le atribuye aquí una escritura de valores secretos.

## Aprobaciones: revisión pendiente

La CLI sí excluye DESTRUCTIVE de la autoaprobación por trust_mode
(`nexus_core/cli/approval.py:208`). Sin embargo, `ApprovalService.verify()`
comprueba run, acción y estado aprobado; no consume la aprobación ni la vincula
a argumentos concretos. Antes de afirmar «approval explícito por invocation»
debe probarse también la reutilización de una aprobación en el gateway. Este
punto es una observación del código, no una prueba E2E realizada.

## Binarios y formato

La verificación inmediatamente anterior a esta misión encontró:

| Paquete | Versión | Ejecutables disponibles |
| --- | --- | --- |
| NetExec | 1.5.0 | `nxc`, `netexec` |
| BloodHound | 1.9.0 | `bloodhound-python` |
| Impacket | 0.13.1 | `secretsdump.py`, `GetUserSPNs.py`, `psexec.py` |

Los tres comandos de Impacket devolvieron ayuda y exit code 0; los nombres
`impacket-secretsdump`, `impacket-GetUserSPNs` e `impacket-psexec` no estaban en
PATH. La integración debe contemplar esta diferencia de empaquetado.
La recipe de Impacket ya existe y contiene variantes apt/pipx, con verificación
específica para pipx; no debe sobrescribirse sin preservar esa compatibilidad.

No se capturaron nuevos formatos de salida contra un DC ni se inventaron
fixtures. El reconocimiento completo de flags quedó pendiente al detectar
el bloqueo. No se contactó ningún target.

## Suite base

Comando ejecutado antes de cualquier cambio funcional:

```bash
NO_COLOR=1 .venv/bin/python -m pytest nexus_core/tests/unit -q
```

Resultado: `1219 passed in 50.20s`. Salida local:
`/tmp/capabilities2-baseline.txt`.

El conteo observado corresponde a unit tests; no se afirma que equivalga a
los 1220 tests de la misión ni que se haya ejecutado toda la suite.

## Reanudación: ayudas reales capturadas

Se capturaron con exit code 0, sin targets, las ayudas de `nxc --help`,
`nxc smb --help`, `nxc ldap --help`, `nxc winrm --help`, `nxc mssql --help`,
`bloodhound-python --help`, `secretsdump.py -h`, `GetUserSPNs.py -h` y
`psexec.py -h`. Capturas completas: `/tmp/capabilities2-help/*.txt`.

Diferencias comprobadas respecto al pseudocódigo de la misión:

- NetExec no anuncia `-q`; dispone de `--no-progress`.
- Shares, users y grupos son flags de enumeración (`--shares`, `--users`,
  `--groups`), no nombres que deban enviarse indiscriminadamente con `-M`.
  Las sesiones SMB usan `--smb-sessions` y los discos `--disks`.
- `--continue-on-success` continúa tras éxitos, no cambia la semántica de fallos.
- BloodHound admite `--auth-method ntlm` en minúsculas. La ayuda de esta versión
  no enumera `ComputerOnly`; distingue `-dc HOST` de `-ns NAMESERVER`.
- Secretsdump trata `-outputfile` como prefijo y añade extensiones. `-just-dc`
  solo extrae NTDS; no equivale a los modos SAM/LSA.
- GetUserSPNs recibe `domain/username:password`, no el mismo target posicional
  `domain/user:password@host` de secretsdump/psexec.
- Psexec de Impacket se identifica como basado en RemComSvc; no se debe asumir
  un nombre fijo PSEXESVC.exe en la documentación de evidencias.

Estas ayudas acreditan flags y sintaxis, no resultados de un pentest AD.
No se inventaron muestras de recolección contra un DC.

## Reanudación: probe dentro del sandbox

NetExec y BloodHound pasan la ayuda dentro del sandbox real. El siguiente
probe, `secretsdump.py -h`, falla con `ModuleNotFoundError: No module named
'impacket'`. Se detuvo ahí; detalle en `CAPABILITIES2_RESULT.md`.
