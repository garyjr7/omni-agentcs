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

### 6. Entiende cada endpoint con entrada antes de atacarlo

- Un formulario de login: ¿qué parámetros? ¿hay CSRF? ¿responde distinto con
  usuario inexistente que con contraseña mala (enumeración de usuarios)? Prueba
  **una** inyección SQL por parámetro con `nexus.web.sqlmap(url=...,
  data="user=admin&pass=x")`, no una batería a ciegas.
- Una API: pide `/swagger.json`, `/openapi.json`, `/api/docs`; prueba métodos
  (`OPTIONS`) y rutas sin autenticar.
- Un CMS: `nexus.web.wp_enum`, versiones de plugins y `searchsploit`.

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
