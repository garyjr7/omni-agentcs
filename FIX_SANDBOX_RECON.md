# FIX_SANDBOX_RECON — HOME efímero + templates de nuclei

Rama: `fix/sandbox-home-and-nuclei-templates` (desde `feat/toolkit-recon`, árbol
limpio). `.gitignore` ya contenía `.sandbox_home/` (commit `0f71610`).

---

## 1. Estado actual del sandbox (`nexus_core/kernel/sandbox.py`)

| Punto | Hoy |
| --- | --- |
| `LocalSandbox.run(argv, *, cwd=".", timeout_seconds=30)` | lanza el hijo con `env={"PATH": "/usr/local/bin:/usr/bin:/bin", "NEXUS_SANDBOX": "1"}` → **sin `HOME`** |
| `LocalSandbox.resolve_workspace(relative)` | solo comprueba escape del workspace |
| `OCISandbox.build_argv(image, command)` | `--network none`, `--read-only`, `--cap-drop ALL`, `no-new-privileges`, `--pids-limit`, `--memory`, `--cpus`, `--user 65532:65532`, `--tmpfs /tmp:rw,noexec,nosuid,size=64m`, bind del workspace en `/workspace`, `--workdir /workspace`. **Sin `HOME` ni XDG** |
| `OCISandbox.run(image, command, timeout_seconds=120)` | env del proceso `docker` (no del contenedor): `{"PATH": ...}` |
| `sandbox_for_environment(workspace_root, allowed_programs=None)` | OCI si `NEXUS_ENV=production`, si no `LocalSandbox` |

Consumidores que dependen de las firmas:

- `nexus_core/tools/handlers/{subfinder,httpx,nuclei,ffuf}.py` +
  `handlers/_exec.run_in_sandbox` (normaliza OCI vs local).
- `nexus_core/evolution/runner.py::EvolutionRunner.evaluate` → `sandbox.run(command)`
  y `sandbox.run(image, command)` (posicional).
- `nexus_core/tests/unit/test_kernel_offline.py::test_oci_sandbox_has_mandatory_isolation_flags`
  afirma que el argv contiene `--network none`, `--read-only`, `--cap-drop ALL`,
  `no-new-privileges` y **`--user 65532:65532`** → no se puede cambiar el UID.

Firmas de `run`/`build_argv` sin cambios obligatorios: el parámetro `home_dir`
se añade **keyword-only con default `None`**, así que
`EvolutionRunner` y los handlers siguen funcionando igual.

---

## 2. Efecto real de no tener `HOME` (medido en este host)

Corriendo los binarios ProjectDiscovery a través de `LocalSandbox`:

| Situación | Efecto observado |
| --- | --- |
| `HOME` ausente en el env del hijo | los binarios resuelven el home vía `/etc/passwd` → `/home/operator` |
| cwd del sandbox | `workspace_root` (el repo si `NEXUS_WORKSPACE_ROOT` no se fija) |
| `httpx` | deja `./httpx/config.yaml` en el workspace; funciona |
| `subfinder` | deja `./subfinder/config.yaml` y `./subfinder/provider-config.yaml`; funciona |
| `nuclei` | crea `~/nuclei-templates`, y sin templates instalados se queda intentando descargarlos hasta agotar el timeout del sandbox (`verification_method="nuclei_timeout"`) |

Es decir: el workspace se ensucia con configuración y nuclei no arranca nunca.

---

## 3. Templates de nuclei en este host

```
/opt/nuclei-templates -> /home/operator/nuclei-templates   (symlink)
/home/operator/nuclei-templates                            (85 MB, 13742 *.yaml)
```

Que el default sea `/opt/nuclei-templates` (el symlink) tiene una trampa
**verificada**:

| Comando | Resultado |
| --- | --- |
| `nuclei -t /opt/nuclei-templates -tags tech -severity info -u …` | `[FTL] Could not run nuclei: no templates provided for scan` (0.26 s) |
| `nuclei -t /home/operator/nuclei-templates -tags tech -severity info -u …` | carga 13.7k templates y escanea (>30 s) |
| `nuclei -t /opt/nuclei-templates/http/technologies/tech-detect.yaml -tags tech -severity info -u http://scanme.nmap.org` | OK, 1.3 s, exit 0 |

**nuclei no sigue un directorio symlinkeado** (sí sigue un fichero dentro de él).
Por eso el handler debe ejecutar con la ruta **resuelta** del directorio:
`Path(NEXUS_NUCLEI_TEMPLATES or "/opt/nuclei-templates").resolve()`. El default
configurado sigue siendo `/opt/nuclei-templates` (el enunciado lo pide), pero el
argv lleva la ruta canónica, que es la que funciona.

Segundo hallazgo práctico: apuntar `-t` al directorio completo cuesta >30 s solo
de carga. Por eso el nuevo argumento `templates` (que selecciona ficheros
concretos) es la vía rápida y determinista, y el E2E lo usa.

`nuclei` también acepta `-duc / -disable-update-check` (presente en `nuclei -h`):
evita el chequeo de updates al arrancar, que en un sandbox sin red es una
pérdida de tiempo y otro motivo para escribir en el HOME.

---

## 4. Plan de cambio (todo aditivo)

1. `LocalSandbox`:
   - `SANDBOX_HOME_DIRNAME = ".sandbox_home"` + propiedad `sandbox_home`.
   - `_sandbox_env(home_dir=None)`: env mínimo + `HOME`, `XDG_CONFIG_HOME`,
     `XDG_CACHE_HOME`, `XDG_DATA_HOME` bajo el workspace, con los directorios
     creados antes de lanzar el hijo.
   - `run(..., home_dir=None)` (keyword-only) usa ese env.
   - `resolve_workspace` rechaza cualquier ruta dentro de `.sandbox_home`.
2. `OCISandbox.build_argv`: `--tmpfs /home/sandbox:rw,nosuid,nodev,mode=1777,size=32m`
   + `--env HOME=/home/sandbox` y los tres XDG. Se mantiene `--user 65532:65532`
   (lo exige un test existente) y `mode=1777` (sticky, como `/tmp`) es lo que
   permite escribir al usuario sin privilegios. Resto del aislamiento intacto.
3. `nexus_core/tools/handlers/nuclei.py`: `DEFAULT_NUCLEI_TEMPLATES`,
   `_nuclei_templates_dir()`, fail-closed si el directorio no existe,
   `-t <templates>` siempre, `-duc`, y nuevos argumentos de schema `templates`
   (subconjunto, validado dentro del directorio de templates) y `tags`.
4. `nexus_core/tools/handlers/ffuf.py`: el wordlist no puede vivir dentro de
   `.sandbox_home` (consecuencia directa de meter el HOME efímero en el
   workspace; antes esa ruta no existía o estaba fuera).
5. Tests: `test_sandbox_home.py`, `test_nuclei_templates.py`, fixture autouse
   hermético en `test_nuclei_handler.py` y E2E de nuclei sin skip.
