# CAPABILITIES2 — fixes verificados; tools detenidas por pre-flight

Fecha: 2026-09-30. Rama: `feat/capabilities-ad-attacks`.

Los tres fixes de seguridad están verificados. Véase
[CAPABILITIES2_FIX_RESULT.md](CAPABILITIES2_FIX_RESULT.md).
Las cinco nuevas tools **no están implementadas ni registradas**; siguen
pendientes recipes, parsers, handlers, tests específicos y E2E AD.

## Nuevo fallo comprobado

Las ayudas de los ejecutables funcionan en el shell del operador. Sin embargo,
la ejecución de handlers debe pasar por el sandbox real de Omni.
Se probaron los comandos de ayuda con `sandbox_for_environment`, un workspace
temporal, el ejecutable absoluto en la allowlist y un timeout de 20 segundos.

```text
nxc sandbox exit: 0 timeout: False
bloodhound-python sandbox exit: 0 timeout: False
secretsdump.py sandbox exit: 1 timeout: False
Traceback (most recent call last):
  File "/home/operator/.local/bin/secretsdump.py", line 61, in <module>
    from impacket import version
ModuleNotFoundError: No module named 'impacket'
```

Se detuvo el probe en el primer fallo, conforme a «Si algo falla, PARA y
reporta». No se ejecutaron las otras dos ayudas de Impacket dentro del sandbox.

`secretsdump.py` usa `#!/usr/bin/python3`; el paquete está instalado en el
site-packages del usuario. El sandbox cambia HOME y el intérprete ya no
encuentra ese paquete. Resolver la ruta absoluta del script no resuelve sus
dependencias. NetExec y BloodHound, instalados en venvs de pipx, sí arrancan.

## Próximo paso necesario

Proporcionar a Impacket un entorno autocontenido, por ejemplo una instalación
pipx, y repetir este probe para las tres utilidades. Debe verificarse qué
ejecutable elige el resolver: los scripts existentes en `~/.local/bin` pueden
seguir teniendo prioridad. No se modificó HOME del sandbox ni se añadió
PYTHONPATH para eludir su aislamiento. No se instalaron paquetes en esta misión.

## Estado de verificación

- Suite completa, con NO_COLOR: **1264 passed, 23 skipped**.
- Suite completa, sin NO_COLOR: **1264 passed, 23 skipped**.
- E2E de redacción estructurada: **3 variantes passed**.
- E2E de aprobación no reutilizable: **passed**.
- Ruff en kernel/agent/tools/tests: **All checks passed!**
- No hubo conexiones a targets, extracción de credenciales ni ejecución remota.
- Únicamente se entrega el commit de fixes; no el commit de capabilities.
- No se hace push.

Las capturas de ayuda se encuentran en `/tmp/capabilities2-help/`; son
artefactos locales temporales. El reconocimiento actualizado detalla las
diferencias de CLI observadas.
