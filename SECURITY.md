# Política de seguridad — OMNI / OmniAgentCS

OMNI es una CLI de pentesting asistido que se instala **en la máquina del
operador** y ejecuta herramientas reales (nmap, ffuf, impacket, Metasploit RPC,
`nexus.shell.exec`). No es un servidor multi-tenant ni un servicio alojado. Esta
página describe qué garantiza el producto hoy, qué **no** garantiza, y cómo
reportar un problema. Se escribió a partir de la auditoría técnica integral
([`docs/audits/AUDIT_OMNI.md`](docs/audits/AUDIT_OMNI.md)).

## 1. El modelo de privilegios, sin adornos

El agente corre con **los privilegios del operador**. Un objetivo hostil no
necesita escalar en tu máquina: le basta con conseguir que el modelo ejecute una
orden, vía prompt injection, en el contenido que controla (un banner, un HTML,
la salida de un `nmap --script`). La defensa no es "el agente no puede", es
"toda orden pasa por el gateway y queda auditada".

Por eso:

- **`local_strict` no aísla la lectura del host.** Confina `cwd` al workspace,
  arma el `argv` contra una allowlist, configura un `HOME` efímero y limpia el
  grupo de procesos. Dentro del `bash -lc` resultante, `cat
  /home/<operador>/.ssh/id_rsa` o `~/.config/omni/secrets.json` **se leen**. La
  tabla de garantías lo declara en código
  ([`kernel/sandbox_modes.py`](nexus_core/kernel/sandbox_modes.py)) y el banner
  lo repite. Trátalo como "aislamiento de escritura y de proceso", no de lectura.
- **`oci` y `oci_network` son los únicos modos que aíslan de verdad**
  (namespace; `oci` sin red y `oci_network` con salida únicamente por el proxy
  SOCKS5 gobernado por el scope), y por eso `NEXUS_ENV=production` los exige: con
  `NEXUS_ENV=production` y `NEXUS_SANDBOX_MODE=local` o `local_strict` el arranque
  **falla** (`SandboxModeForbidden`).
- **`local_sudo` no es un control de seguridad.** La denylist del shell es
  léxica (dice "guard-rail, not a security boundary" en su propio docstring):
  `python3 -c 'import os; os.system("sudo -n id")'` no casa con el patrón. El
  control real es que ya tienes los privilegios de ese usuario.
- **El scope firmado cubre `nexus.web.request`, no el shell universal.** El
  handler de `nexus.shell.exec` valida el destino de `curl`, `wget`, `nc`,
  `ncat` y `netcat` contra el engagement con el mismo validador, pero un
  `python3 -c`, `ssh`, `openssl s_client` o `bash -c 'exec 3<>/dev/tcp/…'` no se
  inspecciona. Es el hallazgo abierto **SEC-01** (§4).

## 2. Qué garantiza el producto hoy

| Garantía | Cómo |
|---|---|
| Nada se ejecuta sin pasar por el gateway | scope → RoE → policy → approval → journal, en un único punto (`kernel/tool_gateway.py`). |
| Un scope sin firma no autoriza nada en producción | `governed` por defecto; `NEXUS_SCOPE_MODE=lab` **falla** con `NEXUS_ENV=production` (`LabScopeForbidden`). |
| Las herramientas HIGH/DESTRUCTIVE piden aprobación humana | incluido `--trust-mode`, que no autoaprueba `impacket_psexec` ni `sliver_deploy`. |
| Headless falla cerrado | sin `--trust-mode`, no autoaprueba nada. |
| Los secretos no se escriben en claro en la evidencia | el artefacto de `nexus.shell.exec` se redacta antes de almacenarse (`redact_secret_values` + `sanitize_text`, SEC-09) y la observación ya lo estaba. |
| Las claves no viven en el repositorio | keyring del sistema y, si no está, `secrets.json` con permisos `0600`; `gitleaks` corre en CI. |
| La auditoría es encadenada | cada decisión y cada resultado se registran con hash; el reporte **muestra** si la cadena está rota en vez de ocultarlo. |

## 3. Secretos y datos del engagement

- Las claves de proveedor y el secreto de firma del scope se guardan con
  `omni secrets set NOMBRE` (keyring o fichero `0600`), nunca en `config.toml`
  ni en el prompt. El CLI solo imprime **nombres**.
- Los datos de los engagements viven en la base local
  (`~/.local/share/omni/control.db`) y en el árbol de artefactos
  (`~/.local/share/omni/artifacts`). No se envían a ningún servicio propio: la
  única salida de red es el proveedor de LLM que configures y las herramientas
  que apuntes a un objetivo autorizado.
- Si compartes un reporte, recuerda que el JSON/Markdown incluye evidencia. El
  repositorio público **no** versiona informes de misión, bases KeePass, claves
  DPAPI ni credenciales de laboratorio: los tests usan fixtures sintéticos y los
  datos de runs reales se quedan fuera del índice.

## 4. Hallazgos abiertos conocidos

Se listan a propósito: una limitación documentada es una decisión, una
sorpresa es un incidente.

| ID | Qué falta | Estado |
|---|---|---|
| SEC-01 | El scope no cubre el egress del shell universal (`python3`, `ssh`, `openssl s_client`, `/dev/tcp`). Mitigación real: proxy de egress por engagement. | Parcial: modo `egress` opt-in (`NEXUS_SHELL_ISOLATION=egress`), ver nota |
| SEC-02 | Aislamiento de **lectura** en modo local (`bwrap`/namespace sobre el HOME real). | Abierto |
| SEC-03 | `oci_network` implementado: contenedor en una red `--internal` cuya única salida es el proxy SOCKS5 del scope; sin proxy configurado falla cerrado. | Cerrado ([ADR-004](docs/adr/ADR-004-sandbox-modes.md)) |
| SEC-05 | Los plugins que añaden tools vía entry points `nexus.tools` declaran su propio `risk`; no hay allowlist ni firma. | Cerrado: hash de la distribución en `tools-trust.json`, fallo cerrado |
| SEC-07 | `ApprovalService.decide()` comprueba que el aprobador tenga rol `approver` o `admin` en su tenant (explícito o leído de `kernel_users`/`kernel_service_accounts`). | Cerrado (v3.2.0) |
| SEC-10/11 | Lockfile con hashes y `make audit` **bloqueante** en CI. Queda una excepción aceptada (§4.1). | Parcial (una excepción) |

**SEC-05.** Un entry point de `nexus.tools` no se importa hasta que un operador
humano lo aprueba con `omni tools trust <name>`. La aprobación vive en
`~/.config/omni/tools-trust.json` (0600) y fija el SHA-256 de **todos los ficheros
de la distribución**, así que cualquier cambio —no solo en el módulo del entry
point— revoca la confianza. `registration.py` comprueba el hash antes de
`entry.load()` y registra el plugin como no confiable si falta o no coincide. El
pin cubre la distribución, no sus dependencias: un plugin aprobado que importe
una dependencia comprometida sigue siendo riesgo de cadena de suministro.

**SEC-01, modo `egress` (opt-in).** `nexus_core/kernel/egress_bridge.py` ejecuta
el shell dentro de un netns de `bwrap` (`--unshare-net`) cuyo único egreso es el
`Socks5EgressProxy` del engagement, alcanzado por un socket UNIX y dos `socat`;
el workspace se monta en lectura-escritura y `/run`/`/tmp` como tmpfs. Se activa
con `NEXUS_SHELL_ISOLATION=egress`; sin la variable, el comportamiento no cambia.
El comando completo se ejecuta bajo `proxychains4`, de modo que el `LD_PRELOAD`
se hereda a los hijos y un `bash -c "nmap …"` anidado tampoco puede saltarse el
proxy. Así, `nmap`/`sqlmap` **solo funcionan en TCP connect** (`nmap -sT`): SYN
(`-sS`), UDP y detección de OS necesitan red directa y no están soportados en
este modo. El comando en segundo plano se rechaza porque
el netns muere con la llamada. Si falta `bwrap`, `socat` o `proxychains4`, el
handler falla cerrado.

### 4.1 Excepción de auditoría aceptada

`make audit` (y el job de CI, que ya no es `continue-on-error`) falla ante
cualquier advisory **salvo** los declarados aquí. Una excepción sin justificación
 escrita es un gate decorativo; por eso va con nombre, advisory y motivo, y se
retira en cuanto haya release corregida.

| Paquete | Advisory | Por qué se acepta |
|---|---|---|
| `paramiko 3.5.1` | `PYSEC-2026-2858` | No existe versión publicada con el fallo corregido. `paramiko` sostiene `nexus.post.*` (`ssh_exec`, `ssh_upload`, `enum_system`, `pivot_*`), que se ejecutan **contra el objetivo del engagement** con credenciales que aporta el operador, nunca contra un servidor de terceros. El riesgo residual es el de un SSH hablando con un destino ya autorizado. |

Lo que **no** se ignora: `pyasn1 0.6.4` arrastraba
`CVE-2026-119194`…`CVE-2026-119197`, con fix en 0.6.5, así que se subió el pin
(`nexus_core/requirements.txt`) en vez de añadirlo a la lista blanca de
advisories. Ignorar un advisory que tiene parche es la forma más rápida de
convertir una auditoría en un trámite.

## 5. Reportar una vulnerabilidad

Usa el canal privado del repositorio (**Security → Report a vulnerability**,
GitHub Security Advisories). No abras un issue público con el detalle.

Incluye: versión (`omni --version`), sistema, comando o tool implicado, y una
reproducción mínima. Si la reproducción necesita un objetivo, describe el
comportamiento en lugar de apuntar a un tercero.

**Nunca** envíes claves reales, tokens ni volcados de la base de un engagement.
Rota cualquier credencial que hayas pegado antes de reportar: si una clave
llegó a un issue, un log o una captura, considérala comprometida.

Lo que puedes esperar: acuse de recibo en unos días, y si el hallazgo toca el
modelo de privilegios (§1) o la gobernanza, el parche entra con el hallazgo
declarado en esta página en vez de silenciarlo.
