# FIX_SANDBOX_RESULT — HOME efímero + templates de nuclei

Rama: `fix/sandbox-home-and-nuclei-templates`. Sin push.

---

## 1. Entregado

### `nexus_core/kernel/sandbox.py`
- `SANDBOX_HOME_DIRNAME = ".sandbox_home"` y `SANDBOX_BASE_ENV` (PATH, LANG,
  LC_ALL, TZ, `NEXUS_SANDBOX=1`) como constantes de módulo.
- `LocalSandbox.sandbox_home` (propiedad), `_is_within_sandbox_home()`.
- `LocalSandbox._sandbox_env(home_dir=None)`: añade **siempre** `HOME`,
  `XDG_CONFIG_HOME`, `XDG_CACHE_HOME` y `XDG_DATA_HOME` bajo
  `<workspace>/.sandbox_home`, creando los directorios antes de lanzar el hijo.
- `LocalSandbox.run(..., home_dir=None)`: parámetro **keyword-only y aditivo**
  (override para tests/evals); `env=self._sandbox_env(home_dir)`.
- `resolve_workspace` rechaza cualquier ruta (incluidos symlinks que resuelvan
  ahí) dentro de `.sandbox_home`.
- `OCISandbox.build_argv`: `--tmpfs /home/sandbox:rw,nosuid,nodev,mode=1777,size=32m`
  + `--env HOME=/home/sandbox` y los tres XDG, con comentario del trade-off.
  Se mantienen `--network none`, `--read-only`, `--cap-drop ALL`,
  `no-new-privileges` y `--user 65532:65532`.

### `nexus_core/tools/handlers/nuclei.py`
- `DEFAULT_NUCLEI_TEMPLATES = "/opt/nuclei-templates"` +
  `_nuclei_templates_dir()` (override `NEXUS_NUCLEI_TEMPLATES`, alias público
  `nuclei_templates_dir`).
- **Fail-closed**: si `Path(templates_dir).is_dir()` es falso devuelve
  `ToolResult(verified=False, verification_method="nuclei_templates_missing")`
  y **no ejecuta nuclei**.
- El argv lleva **siempre** `-t <templates>`; con selección explícita, un `-t`
  por template. La ruta que se usa en la ejecución es la **canónica**
  (`Path(...).resolve()`), porque nuclei no sigue un directorio symlinkeado.
- `-duc` (disable update check) añadido a los flags gestionados.
- Nuevos argumentos de schema: `templates` (≤10, validados dentro del
  directorio de templates y existentes) y `tags` (≤10, `^[A-Za-z0-9_][\w.-]{0,63}$`).
- Evidencia ampliada: `templates_dir`, `templates`, `tags`.

### `nexus_core/tools/handlers/ffuf.py`
- `resolve_wordlist` rechaza también rutas dentro de `.sandbox_home` (el HOME
  efímero vive dentro del workspace, así que había que excluirlo explícitamente).

### Tests
- `nexus_core/tests/unit/test_sandbox_home.py` (11).
- `nexus_core/tests/unit/test_nuclei_templates.py` (18).
- `test_nuclei_handler.py`: fixture `autouse` que apunta el handler a un
  directorio de templates temporal (el suite deja de depender del host).
- `test_ffuf_handler.py`: +1 test del guardia de `.sandbox_home`.
- `test_toolkit_e2e.py`: skip coherente con el nuevo default y el test de nuclei
  ahora usa `templates` + `tags` (un solo template no intrusivo).

### `README.md`
- `## Requisitos del sistema` (binarios + `/opt/nuclei-templates`, cómo
  instalarlo, `NEXUS_NUCLEI_TEMPLATES`, nota del symlink).
- `## Sandbox` (HOME efímero en LocalSandbox y tmpfs `/home/sandbox` en OCI).

---

## 2. Verificación

| Check | Resultado |
| --- | --- |
| 3 imports (`sandbox`, `handlers.nuclei`, `omni`) | OK |
| `pytest nexus_core/tests/unit -q` | **309 passed** (279 previos + 30 nuevos) |
| `pytest test_sandbox_home.py -v` | 11 passed |
| `pytest test_nuclei_templates.py -v` | 18 passed |
| `NEXUS_E2E=1 pytest test_toolkit_e2e.py -v` | **4 passed, 0 skipped** (37.68 s) |
| `ruff --select F,E9` (kernel, tools, tests) | All checks passed |
| residual TODO/FIXME/XXX/HACK en `sandbox.py` + `nuclei.py` | limpio |
| `git status` | solo los archivos de la misión; `.sandbox_home/` ignorado |

### E2E (los 4 en verde, nuclei ya sin skip)
```
test_e2e_subfinder_against_nmap_org_in_scope          PASSED
test_e2e_httpx_against_scanme_in_scope                PASSED
test_e2e_nuclei_against_scanme_in_scope               PASSED   ← antes SKIPPED
test_e2e_ffuf_against_scanme_denied_when_out_of_scope PASSED
============================== 4 passed in 37.68s ==============================
```

### Artefactos en el repo (criterio pedido)
```
$ ls -la ~/NEXUS | grep -E "httpx|subfinder|nuclei"
(vacío)

$ ls .sandbox_home
.cache  .config  .local          # 36K, ignorado por git (!! .sandbox_home/)
$ find .sandbox_home -maxdepth 3 | head
.sandbox_home/.config/httpx/config.yaml
```
Antes de este fix, un run real dejaba `./httpx/config.yaml` y
`./subfinder/{config,provider-config}.yaml` en la raíz del repo y
`~/nuclei-templates` en el home real. Ahora httpx escribe su config en
`.sandbox_home/.config/httpx/config.yaml` (respeta `XDG_CONFIG_HOME`).

### Demostración por CLI (Groq real + sandbox real, workspace = repo)
```
⚙️  nexus.recon.httpx
     targets: ['http://scanme.nmap.org']   tech_detect: True   noise: low
✓ nexus.recon.httpx — ok | noise: low
• estado=completed iteraciones=2
```
seguido de `git status` sin artefactos y `.sandbox_home/` ignorado.

---

## 3. Decisiones de diseño no cubiertas por el prompt

1. **Ruta de templates canónica en el argv.** `/opt/nuclei-templates` es un
   symlink en este host y **nuclei no sigue un directorio symlinkeado**
   (`[FTL] … no templates provided for scan` en 0.26 s). El default configurado
   sigue siendo `/opt/nuclei-templates`, pero se ejecuta con
   `Path(...).resolve()`; un fichero dentro del symlink sí funcionaba, un
   directorio no.
2. **Los `templates` explícitos se validan dentro del directorio de templates.**
   Permitir rutas arbitrarias convertiría la tool en un lector de ficheros
   arbitrario (el mismo motivo por el que `-t` sigue prohibido en `flags`).
   Además deben existir y hay tope de 10.
3. **`-duc` siempre**: un run sandboxeado no debe consultar updates (y en OCI
   `--network none` lo haría fallar). También evita más escrituras al HOME.
4. **`tags` con regex estricta** que exige empezar por alfanumérico/guion bajo:
   un tag no puede colarse en el argv como si fuera un flag.
5. **`mode=1777` en el tmpfs de OCI** (sticky, como `/tmp`): es lo que permite
   que `--user 65532:65532` escriba en su HOME sin cambiar el UID (un test
   existente lo exige). Nada persiste: muere con el contenedor.
6. **El HOME efímero está dentro del workspace pero es opaco**: bloqueado en
   `resolve_workspace` y excluido del wordlist de ffuf. `nexus.workspace.search`
   sí podría listar sus ficheros de config (son inocuos), no se ha tocado.
7. **Suite hermética**: `test_nuclei_handler.py` recibió un fixture `autouse`
   con un directorio de templates temporal, para que los 20 tests existentes no
   dependan de que el host tenga `/opt/nuclei-templates`. El E2E mantiene el
   `skipif` real (solo se ejecuta con templates instalados).
8. **`.sandbox_home/` no se añadió a `.gitignore`** porque ya estaba (commit
   `0f71610`).

## 4. Nota de rendimiento (observado, no un fallo)
Apuntar `-t` al directorio completo de templates cuesta >30 s solo en carga
(13 742 ficheros). Es el comportamiento normal de nuclei, pero para runs rápidos
conviene el argumento `templates` (el E2E usa un único template y tarda ~2 s).
