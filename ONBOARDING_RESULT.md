# Resultado: distribución y onboarding

Fecha: 2026-09-29. Rama: `feat/distribution-onboarding`.

Implementados config XDG, catálogo de diez herramientas, provisioner,
meta-tools durables, wizard, doctor y comandos de configuración. Sin nuevas
dependencias. No se instalaron herramientas durante las pruebas. Sin push.

## Verificación

- 12 imports solicitados: OK, incluido `omni` sin efectos de ejecución al importar.
- `durable_tool_definitions()`: **11 tools**.
- Suite unitaria completa: **470 passed in 14.53s** (373 anteriores + 97 nuevos).
- Suite específica: **97 passed in 4.94s**.
- Ruff `--select F,E9` en módulos nuevos, entry point y tests nuevos: **All checks passed!**
- `git diff --check`: limpio.
- Residuos TODO/FIXME/XXX/HACK/NotImplementedError: ninguno en los módulos solicitados.
- Búsqueda subprocess en config/provisioner/handlers administrativos:
  único resultado `nexus_core/provisioner/installer.py:43`, `subprocess.run`.
- JSON de doctor válido y sin claves/tokens. Tests de redacción incluyen valores
  que coinciden con literales JSON para preservar el tipo de los datos.
- `--config-path`: `/home/operator/.config/omni/config.toml`.
- Wizard y aprobaciones probados mediante inputs, subprocess y which simulados;
  ninguna receta ejecutada contra gestores reales.

### Pruebas nuevas por archivo

| Archivo | Tests |
|---|---:|
| test_config_loader | 12 |
| test_detector | 13 |
| test_doctor | 8 |
| test_installer | 13 |
| test_onboarding_cli | 5 |
| test_recipes | 6 |
| test_system_env_handler | 6 |
| test_system_install_handler | 12 |
| test_wizard | 14 |
| test_xdg | 8 |

Los casos extra cubren corrupción y fallo de escritura, XDG relativo/vacío,
colisión con httpx Python, banners de versiones, gestores macOS, plan falsificado,
aprobación para otro plan o para dry-run, llamada directa sin aprobación,
visualización del comando antes del permiso, cancelación del wizard, rollback
del engagement y adaptación Anthropic mediante MockTransport.

## Decisiones de implementación

1. `config.py` se convierte en paquete conservando sus constantes legacy y
   corrigiendo la raíz del repositorio. El CLI y store_factory resuelven la DB
   efectiva en tiempo de ejecución. Entorno y .env explícitos preceden al TOML;
   una instalación nueva usa SQLite XDG. La DB anterior no se mueve.
2. Config atómico con archivo temporal, fsync y replace, permisos 600 y
   directorios 700. Config corrupto se respalda; fallos de recuperación usan
   defaults en memoria con advertencia por stderr. Reset conserva otro respaldo.
3. Todas las invocaciones de procesos de estos módulos, incluidas las versiones
   solicitadas por detector, systemctl y el editor, se centralizan en installer.
   Se resuelve así la contradicción entre exigir subprocess en detector y exigir
   una única frontera subprocess. Se usa argv, nunca shell=True.
4. El gateway exige aprobación durable HIGH ligada al hash del plan, incluido
   dry-run. El callback CLI muestra comando exacto, modificación de PATH y notas.
   Editar argumentos exige mostrar y aprobar otra vez. El instalador vuelve a
   validar el plan contra el catálogo antes de ejecutar. No acepta argv del LLM.
5. El wizard usa confirmación humana explícita por instalación. Un aborto no
   revierte paquetes ya instalados con permiso; no deja config parcial.
   El engagement opcional usa firma HMAC, instantánea DNS, 24 horas y confirmación
   del alcance. Si guardar el config falla, se elimina el engagement recién creado.
6. Se priorizan gestores de usuario; Go recibe GOBIN para respetar install_dir.
   PATH se actualiza solo tras verificar. Sudo usa -n y falla si no está
   autorizado: no solicita contraseñas dentro de un proceso capturado.
   No se añaden repositorios ni se descargan templates de nuclei implícitamente.
7. Algunas recetas tienen restricciones por distro; Metasploit necesita un
   repositorio ya configurado. El soporte multi-distro se verificó con mocks y
   consulta de instrucciones oficiales, no instalando paquetes en cada sistema.
8. Anthropic no tenía adaptador previo: se añadió Messages API con httpx existente.
   El provider configurado se respeta; si falta su clave, el runtime usa Fake
   offline y no elige silenciosamente otro proveedor cloud. La verificación de
   API keys en el wizard se omite; no hay llamadas pagadas.
9. Doctor inspecciona SQLite de solo lectura y no consulta PostgreSQL remoto.
   El estado de msfrpcd combina puerto loopback y systemd, sin autenticar RPC.
   Versión ausente no implica binario ausente cuando vence el timeout de 3s.
10. Pip/npm publicados siguen siendo futuros. La instalación de esta entrega es
    desde checkout con venv activo y symlink. Claves TOML con permisos 600;
    keyring queda documentado como mejora posterior. auto_install no evita permisos.

## Comandos utilizados

```bash
.venv/bin/python -m pytest nexus_core/tests/unit -q
.venv/bin/python -m pytest nexus_core/tests/unit/test_xdg.py nexus_core/tests/unit/test_config_loader.py nexus_core/tests/unit/test_detector.py nexus_core/tests/unit/test_recipes.py nexus_core/tests/unit/test_installer.py nexus_core/tests/unit/test_system_env_handler.py nexus_core/tests/unit/test_system_install_handler.py nexus_core/tests/unit/test_wizard.py nexus_core/tests/unit/test_doctor.py nexus_core/tests/unit/test_onboarding_cli.py -v
.venv/bin/ruff check nexus_core/config nexus_core/provisioner nexus_core/tools/handlers/system_*.py nexus_core/cli/wizard.py nexus_core/cli/doctor.py nexus_core/llm/anthropic_client.py omni.py --select F,E9
.venv/bin/python omni.py --config-path
.venv/bin/python omni.py --doctor --no-wizard
.venv/bin/python omni.py --doctor --no-wizard --json | python3 -m json.tool | head -30
```

## Salida real: doctor

El config global aún no existe: ejecutar doctor no fuerza el wizard ni guarda
credenciales. `LLM_PROVIDER=fake` y la DB del checkout proceden del entorno/.env
actual. Msfrpcd sigue activo y escucha en 127.0.0.1:55552 con MessagePack.

```text
OmniAgentCS Doctor
══════════════════════════════════════════════════════

Sistema:
  system: "Linux"
  distro: "ubuntu"
  version: "24.04"
  arch: "x86_64"

Python:
  "3.12.3"

Shell:
  "/bin/bash"

Rutas XDG:
  config: {"path": "/home/operator/.config/omni/config.toml", "exists": false}
  data: {"path": "/home/operator/.local/share/omni", "exists": true}
  state: {"path": "/home/operator/.local/state/omni", "exists": true}
  cache: {"path": "/home/operator/.cache/omni", "exists": true}

Config:
  exists: false
  schema_version: 1
  default_provider: "fake"
  default_model: "nexus-fake-v1"
  api_keys: {"groq": true, "openai": false, "anthropic": false, "gemini": false}

Base de datos:
  path: "/home/operator/NEXUS/data/nexus_pro.db"
  exists: true
  size_bytes: 630784
  backend: "sqlite"
  diagnostic: "local read-only"

Gestores:
  ["apt", "snap", "go"]

Herramientas:
  nmap         ✓ /usr/bin/nmap  Nmap version 7.94SVN ( https://nmap.org )
  subfinder    ✓ /usr/local/bin/subfinder  [INF] Current Version: v2.16.0
  httpx        ✓ /usr/local/bin/httpx  [INF] Current Version: v1.12.0
  nuclei       ✓ /usr/local/bin/nuclei  [INF] Nuclei Engine Version: v3.11.1
  ffuf         ✓ /usr/local/bin/ffuf  ffuf version: 2.1.0-dev
  amass        ✗ (ausente)
  msfconsole   ✓ /usr/bin/msfconsole
  sqlmap       ✗ (ausente)
  gobuster     ✗ (ausente)
  impacket     ✗ (ausente)

msfrpcd:
  host: "127.0.0.1"
  port: 55552
  listening: true
  systemd_active: true
  transport: "msgpack"

Auditoría (últimos 5 eventos):
  [{"created_at": "2026-08-05T00:15:48.552008+00:00", "action": "workflow.dispatch", "resource_id": "run_864bec55ed2440c08e52bb6e273d6c06", "decision": "allow"}, {"created_at": "2026-08-05T00:15:14.455779+00:00", "action": "workflow.register", "resource_id": "workflow_dbb7a3f3003443a0ab34633fb524774b", "decision": "allow"}]
```

## Salida real: JSON (primeras 30 líneas)

```text
{
    "os": {
        "system": "Linux",
        "distro": "ubuntu",
        "version": "24.04",
        "arch": "x86_64"
    },
    "python": "3.12.3",
    "shell": "/bin/bash",
    "paths": {
        "config": {
            "path": "/home/operator/.config/omni/config.toml",
            "exists": false
        },
        "data": {
            "path": "/home/operator/.local/share/omni",
            "exists": true
        },
        "state": {
            "path": "/home/operator/.local/state/omni",
            "exists": true
        },
        "cache": {
            "path": "/home/operator/.cache/omni",
            "exists": true
        }
    },
    "config": {
        "exists": false,
        "schema_version": 1,
```

## Referencias consultadas

- [XDG Base Directory](https://specifications.freedesktop.org/basedir/0.8/).
- [ProjectDiscovery httpx](https://docs.projectdiscovery.io/opensource/httpx/install),
  [subfinder](https://docs.projectdiscovery.io/opensource/subfinder/install),
  [nuclei](https://docs.projectdiscovery.io/opensource/nuclei/install).
- [ffuf](https://github.com/ffuf/ffuf), [gobuster](https://github.com/OJ/gobuster),
  [Impacket](https://github.com/fortra/impacket).
- [Anthropic Messages API](https://platform.claude.com/docs/en/api/messages/create).
