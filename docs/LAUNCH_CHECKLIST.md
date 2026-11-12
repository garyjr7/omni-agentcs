# Checklist de lanzamiento público — OMNI / OmniAgentCS

Estado: **borrador de pre-publicación**, 2026-11-12, sobre `b1f2815`
(`v3.0.0-rc3`). Este documento no publica nada ni reescribe historia: enumera
lo que debe hacerse antes de cambiar la visibilidad del repositorio.

## 0. Bloqueadores detectados en esta auditoría

| # | Hallazgo | Evidencia | Decisión requerida |
|---|---|---|---|
| B1 | El historial contiene datos de la etapa NEXUS: 184 rutas bajo `data/`, nombres de proyectos/clientes, rutas `/home/operator` y una WAL de SQLite de 1,78 MB. | `git rev-list --objects --all` + escaneo de blobs. Commits `6949587`, `98a8753`, `6ef46fa`. | Purgar `data/` del historial o publicar un historial nuevo. **No publicar así.** |
| B2 | Los 302 commits usan `juniormcgary7@users.noreply.github.com`. | `git log --format='%ae' \| sort -u`. | Decidir si se acepta el correo público o se reescribe a un alias noreply. |
| B3 | 213 commits llevan el trailer `Co-Authored-By: Codebuff <noreply@codebuff.com>`. | `git log --grep='Co-Authored-By: Codebuff'`. | Quitarlo exige reescribir el historial; no se puede editar un commit publicado sin cambiar su SHA. |

Si se decide reescribir, hacerlo **antes** de activar branch protection y
**antes** de anunciar el repositorio. El run #49 de CI quedará asociado al SHA
antiguo y habrá que ejecutar CI de nuevo sobre el SHA reescrito.

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

Situación actual: un único correo (`juniormcgary7@users.noreply.github.com`) y 213 commits
con trailer de Codebuff.

Opciones:

1. **Aceptar el correo** en el historial y usar un alias noreply solo para
   commits nuevos. Es la opción menos invasiva.
2. **Reescribir el historial** para reemplazar el correo y retirar el trailer.
   Cambia todos los SHA y obliga a force-push de ramas y tags.

Si se elige reescribir, usar un clon espejo y `git-filter-repo`, nunca el
checkout de trabajo:

```bash
# Respaldo completo antes de tocar nada
git clone --mirror git@github.com:garyjr7/omni-agentcs.git \
  ../omni-agentcs-backup.git

python3 -m pip install --user git-filter-repo

# En un clon fresco del repo (filter-repo exige un clon limpio)
git clone https://github.com/garyjr7/omni-agentcs.git omni-agentcs-public
cd omni-agentcs-public

# 1) Quitar datos legacy de la etapa NEXUS
git filter-repo --path data/ --invert-paths

# 2) Reemplazar el correo personal por el alias noreply de GitHub
#    Sustituir <ID> por el ID numérico de la cuenta de GitHub.
git filter-repo --email-callback \
  'return email.replace(b"juniormcgary7@users.noreply.github.com", b"<ID>+garyjr7@users.noreply.github.com")'

# 3) Quitar el trailer de Codebuff de los mensajes
git filter-repo --message-callback \
  'return message.replace(b"\n\n🤖 Generated with Codebuff\nCo-Authored-By: Codebuff <noreply@codebuff.com>\n", b"\n")'
```

Después del rewrite:

```bash
git remote add origin git@github.com:garyjr7/omni-agentcs.git
git push --force --all origin
git push --force --tags origin
git tag -n
git describe --tags
```

- [ ] Verificar que `data/` ya no existe en ningún commit:
      `git log --all --oneline -- data/`.
- [ ] Verificar el correo: `git log --format='%ae' | sort -u`.
- [ ] Verificar el trailer: `git log --grep='Co-Authored-By: Codebuff' --oneline`.
- [ ] Re-ejecutar CI sobre el SHA nuevo y volver a mover `v3.0.0-rc3` si aplica.
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
- [ ] Tag y rama `main` apuntando al commit que se va a publicar.
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
