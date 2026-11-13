# Checklist de lanzamiento público — OMNI / OmniAgentCS

Estado: **saneamiento de historial completado**, 2026-11-13, sobre
`v3.0.0-rc3`. Este documento resume la auditoría y enumera lo que debe
completarse antes de cambiar la visibilidad del repositorio.

## 0. Bloqueadores del historial (resueltos)

La reescritura se ejecutó con `git-filter-repo` sobre un backup completo. Todos
los SHA cambiaron y los tags se recrearon sobre la historia nueva.

| # | Hallazgo original | Resolución aplicada | Verificación |
|---|---|---|---|
| B1 | 184 rutas de la etapa NEXUS bajo `data/`, con nombres de proyectos/clientes, rutas personales y una WAL de SQLite de 1,78 MB. | Purgado con `--path data/ --invert-paths`. | `git rev-list --objects --all \| grep -E ' data/'` no devuelve nada. |
| B2 | Los 303 commits usaban el correo personal del operador. | Reescritos al alias noreply `juniormcgary7@users.noreply.github.com`. | `git log --format='%ae' \| sort -u` muestra solo el alias. |
| B3 | 213 commits llevaban el trailer de atribución de la herramienta. | Eliminado con `--message-callback`, junto con las líneas "Generated with". | `git log --grep='Codebuff'` no devuelve nada. |

La reescritura se hizo **antes** de activar branch protection y de anunciar el
repositorio. El run #49 de CI quedó asociado al SHA antiguo y hay que ejecutar
CI de nuevo sobre el SHA reescrito.

## 1. Secretos en el árbol actual

Resultado medido:

- Sin claves de proveedor reales (AWS, GitHub, OpenAI, Anthropic, Google,
  Slack) ni JWT utilizables en archivos rastreados.
- `.env.example` solo contiene placeholders
  (`postgresql://user:password@localhost/omni`, secretos vacíos).
- Los `-----BEGIN … PRIVATE KEY-----` encontrados son fixtures/documentación:
  `nexus_core/tests/unit/test_phase3n_fixes.py` (PEM truncado usado para probar
  redacción) y `docs/audits/SEC00_VERIFICATION.md` (falso positivo citado).
- `CI` ya tiene un job `secrets` con `gitleaks-action` y `fetch-depth: 0`.

Checklist:

- [ ] Ejecutar `gitleaks detect --source . -v` (si no está instalado:
      `docker run --rm -v "$PWD:/repo" zricethezav/gitleaks:latest detect --source /repo -v`).
- [ ] Ejecutar `trufflehog git file://. --only-verified` si está disponible.
- [ ] Revisar a mano `.env.example`, ejemplos de configuración y fixtures.
- [ ] Si aparece una clave real: **revocarla primero**, rotarla, y después
      sustituirla por un placeholder. No basta con borrar el archivo.
- [ ] Confirmar que `gitleaks` sigue bloqueando en CI.

## 2. Historial de Git

### 2.1 Correo y atribución

```bash
git log --format='%ae' | sort | uniq -c
git log --format='%an <%ae>' | sort -u
git log --grep='Co-Authored-By: Codebuff' --oneline | wc -l
```

Situación tras el saneamiento: un único correo
(`juniormcgary7@users.noreply.github.com`) y cero trailers de atribución. Los
SHA y los tags fueron reescritos; cualquier clon existente debe re-clonarse, no
hacer `pull`.

La pasada combinada aplicó:

- `--path data/ --invert-paths` para retirar la carpeta legacy.
- `--email-callback` para sustituir el correo personal por el alias noreply.
- `--message-callback` para retirar el trailer y las líneas de atribución.
- `--replace-text` para sanear rutas y usuario personales en todos los blobs.

- [x] Verificar que `data/` ya no existe en ningún commit:
      `git log --all --oneline -- data/`.
- [x] Verificar el correo: `git log --format='%ae' | sort -u`.
- [x] Verificar que no quedan mensajes con la atribución:
      `git log --grep='Codebuff' --oneline`.
- [ ] Re-ejecutar CI sobre el SHA nuevo.
- [ ] Avisar a cualquier colaborador con clones existentes: deben re-clonar, no
      hacer `pull`.

## 3. Llaves SSH de la máquina

- [ ] Listar llaves y permisos:

```bash
ls -la ~/.ssh
```

- [ ] Comprobar si una llave tiene passphrase. Si el comando pide passphrase, la
      tiene; si termina sin pedirla, no la tiene:

```bash
ssh-keygen -y -f ~/.ssh/id_ed25519 > /dev/null
```

- [ ] Añadir o cambiar la passphrase:

```bash
ssh-keygen -p -f ~/.ssh/id_ed25519 -a 100
```

- [ ] Confirmar que ninguna llave privada está en el repo:

```bash
git grep -n -E 'BEGIN (OPENSSH|RSA|EC|DSA) PRIVATE KEY' || echo 'sin claves privadas rastreadas'
git log --all --name-only --pretty=format: | \
  grep -E '(^|/)(id_rsa|id_ed25519|\.ssh/)' || echo 'sin claves privadas en el historial'
```

- [ ] Revisar `~/.ssh/config` por si contiene hosts, usuarios o rutas internas
      que no quieras publicar. No forma parte del repo, pero sí de tu OpSec.
- [ ] Usar una llave distinta para GitHub si mezclas trabajo y proyectos
      personales.

## 4. Cuenta de GitHub y configuración del repositorio

### 4.1 Cuenta

- [ ] Activar 2FA (TOTP o llave de seguridad) y guardar los códigos de
      recuperación fuera del repo.
- [ ] Revisar **Settings → Sessions** y cerrar sesiones desconocidas.
- [ ] Revisar **Settings → SSH and GPG keys**; eliminar llaves antiguas.
- [ ] Revisar **Settings → Developer settings → Personal access tokens**:
      revocar tokens sin uso, poner expiración y preferir tokens fine-grained.
- [ ] Revisar **Settings → Applications** y revocar OAuth apps que ya no uses.

### 4.2 Repositorio

- [ ] Activar **Dependabot alerts** y **Dependabot security updates**.
- [ ] Activar **Secret scanning** y **Push protection**.
- [ ] Activar **Private vulnerability reporting** para que los reportes no
      empiecen en un issue público.
- [ ] Configurar **Actions → General**: token por defecto con permisos de solo
      lectura; exigir aprobación para workflows de forks.
- [ ] Opcional: activar **CodeQL** para el código Python.
- [ ] Revisar **Settings → Collaborators** y dejar solo a quien corresponda.
- [ ] Revisar **Settings → Webhooks** y **Deploy keys**.

### 4.3 Protección de `main`

Configurar después de cualquier rewrite de historial y antes de anunciar el
repo:

- [ ] Require a pull request before merging.
- [ ] Require at least 1 approval.
- [ ] Dismiss stale approvals when new commits are pushed.
- [ ] Require review from Code Owners (si se añade `CODEOWNERS`).
- [ ] Require status checks: `cli`, `coverage`, `postgres`, `secrets`.
- [ ] Require conversation resolution before merging.
- [ ] Require linear history.
- [ ] Do not allow force pushes.
- [ ] Do not allow deletions.
- [ ] Include administrators (si el flujo del proyecto lo permite).

## 5. Perfil público y privacidad

- [ ] Revisar qué muestra tu perfil: nombre real, foto, ubicación, web, correo.
- [ ] Ocultar el correo en **Settings → Emails → Keep my email addresses
      private**.
- [ ] Usar el alias noreply de GitHub en commits nuevos:

```bash
git config --global user.name "TU NOMBRE"
git config --global user.email "<ID>+garyjr7@users.noreply.github.com"
git config --global user.useConfigOnly true
```

- [ ] Si el correo ya está en el historial y no quieres que sea público, aplicar
      la reescritura de §2.1.
- [ ] Buscar datos personales en el árbol actual:

```bash
git grep -n -E '/home/[A-Za-z0-9._-]+|/Users/[A-Za-z0-9._-]+' || true
git grep -n -E '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}' || true
```

## 6. Release y suministro

- [ ] Confirmar `LICENSE` (Apache-2.0), `NOTICE` y `DISCLAIMER.md`.
- [ ] Confirmar que `pyproject.toml` declara `license = "Apache-2.0"` y
      `license-files = ["LICENSE", "NOTICE"]`.
- [ ] Firmar el tag final: `git tag -s v3.0.0 -m "OMNI v3.0.0"`; verificar con
      `git verify-tag v3.0.0`.
- [ ] Publicar checksums de los artefactos.
- [ ] Revisar que las release notes no incluyan rutas internas, correos ni
      nombres de clientes.
- [ ] Confirmar que `install.sh` apunta a la URL pública correcta.

## 7. Gate final antes de cambiar la visibilidad

```bash
gitleaks detect --source . -v
trufflehog git file://. --only-verified   # si está instalado
make syntax lint typecheck-strict audit test
git status --short
git describe --tags
git ls-remote --tags origin 'refs/tags/v3.0.0-rc3*'
```

- [ ] `make audit` sin vulnerabilidades no ignoradas.
- [ ] `make lint` y `make typecheck-strict` en verde.
- [ ] Suite completa en verde.
- [ ] `make test-coverage` en CI (en el host de 3,8 GB puede agotar memoria; el
      propio `Makefile` documenta esa limitación).
- [x] Tag y rama `main` apuntando al commit que se va a publicar.
- [ ] CI del commit público en verde.
- [ ] Copia de seguridad del repo privado antes de cambiar la visibilidad.

## 8. Después de publicar

- [ ] Verificar que el repo se clona en limpio:
      `git clone https://github.com/garyjr7/omni-agentcs.git /tmp/omni-public-check`.
- [ ] Ejecutar `bash install.sh --dry-run` desde ese clon.
- [ ] Comprobar que los enlaces del README y de `docs/INDEX.md` resuelven.
- [ ] Vigilar los primeros reportes de seguridad y issues.
- [ ] No aceptar PRs que añadan logs, `.env`, bases de datos o evidencia de
      engagement.
