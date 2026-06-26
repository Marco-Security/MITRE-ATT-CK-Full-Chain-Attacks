# Día 3 - Ubuntu: Juice Shop XXE e Information Disclosure

Operación Eslabón, 25 de junio de 2026.

## Objetivo

Ejecutar una cadena de ataque realista contra una aplicación web Node.js (OWASP Juice Shop) corriendo en un contenedor Docker sobre Ubuntu, partiendo exclusivamente desde lo que sería visible desde una VPS externa.

## Máquinas

Víctima: Ubuntu (192.168.1.96)
Atacante: Kali Linux (192.168.1.132)

## Superficie de ataque visible desde afuera

Aunque el nmap reveló varios servicios (FTP, SSH, Samba, MySQL), en un escenario real desde una VPS externa solo serían accesibles las aplicaciones web:

- Puerto 3000: Juice Shop (Node.js / Express)
- Puerto 80 / 8080: DVWA (Apache)

El resto (SSH, MySQL, Samba, FTP) son servicios internos que no estarían expuestos directamente. El objetivo del día fue Juice Shop en el puerto 3000.

## Desarrollo

### Fase 1: Reconocimiento

Se ejecutó nmap contra 192.168.1.96. El escaneo reveló que el puerto 3000 corría un servicio HTTP no identificado. Analizando el fingerprint HTTP del propio nmap se encontró el título OWASP Juice Shop y el nombre del autor en el HTML capturado, confirmando el servicio sin necesidad de abrirlo en un navegador.

```
nmap -sV 192.168.1.96
```

Puerto 3000 confirmado como Juice Shop.

### Fase 2: Enumeración de la aplicación

Se inspeccionaron los headers HTTP para identificar tecnologías:

```
curl -sI http://192.168.1.96:3000
```

Los headers revelaron que usa hash routing (SPA), tiene CORS abierto (Access-Control-Allow-Origin: *), y no expone el header Server (probablemente Node.js). El header X-Recruiting apuntó a /#/jobs, confirmando que es una SPA con Angular.

Se descargó el JavaScript principal del frontend (main.js) y se extrajeron todos los endpoints de la API:

```
curl -s http://192.168.1.96:3000/main.js > main.js
grep -oP '"/api/[^"]*"' main.js | sort -u
grep -oP '"/rest/[^"]*"' main.js | sort -u
```

Esto reveló 15 endpoints de API y 27 endpoints REST, incluyendo /rest/user/login, /api/Users, /file-upload, y /ftp/.

Se confirmó que el directorio /ftp/ tenía directory listing activo con archivos sensibles:

- incident-support.kdbx (base de datos KeePass con credenciales)
- package.json.bak (dependencias de la app)
- coupons_2013.md.bak (cupones de descuento)
- encrypt.pyc (script de encriptación compilado)
- quarantine/ (directorio de archivos en cuarentena)

Sin embargo, al intentar descargar los archivos, el servidor solo permitió .md y .pdf. Los demás devolvieron "Only .md and .pdf files are allowed".

Buscando en main.js funcionalidades que aceptaran archivos, se encontró que /file-upload acepta application/xml, text/xml, application/pdf y application/zip para "B2B orders". Adicionalmente, se encontraron rutas de redirect con whitelist: ./redirect?to= que solo acepta URLs conocidas.

### Fase 3: Initial Access (XXE)

El endpoint /file-upload requería autenticación. Se creó una cuenta:

```
curl -s http://192.168.1.96:3000/api/Users/ \
  -H "Content-Type: application/json" \
  -d '{"email":"test@test.com","password":"test1234"}'
```

La app permite registro abierto. Se hizo login para obtener el JWT:

```
curl -s http://192.168.1.96:3000/rest/user/login \
  -H "Content-Type: application/json" \
  -d '{"email":"test@test.com","password":"test1234"}'
```

Se obtuvo un token JWT (RS256). Al decodificar el payload en base64 se descubrió que el token contenía el hash MD5 de la contraseña del usuario en texto plano dentro del propio token. Esto es una vulnerabilidad de Information Disclosure grave: cualquiera que intercepte el token obtiene el hash.

Se envió un XML de prueba al endpoint de upload:

```xml
<?xml version="1.0"?>
<order><item>juice</item></order>
```

El servidor respondió con error 410 pero reflejó el XML completo procesado en el mensaje de error, confirmando que el parser XML estaba activo.

Se intentó XXE con una entidad externa que leyera /etc/passwd:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<order><item>&xxe;</item></order>
```

El servidor devolvió el contenido del archivo en el mensaje de error:

```
root:x:0:0:root:/root:/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/sbin/nologin
nonroot:x:65532:65532:nonroot:/home/nonroot:/sbin/nologin
```

XXE confirmado. La app es vulnerable a lectura arbitraria de archivos del servidor.

El /etc/passwd con solo 3 usuarios confirmó que Juice Shop corre dentro de un contenedor Docker con sistema mínimo.

### Fase 4: Intentos de escalación via XXE

Con la lectura de archivos confirmada, se intentaron varias rutas para escalar:

Lectura de credenciales de la app:
- /juice-shop/.env → vacío (no existe)
- /juice-shop/config/default.yml → "failed to parse" (existe pero contiene caracteres YAML que rompen el parser XML)
- /juice-shop/config/default.json → vacío (no existe)
- /juice-shop/build/routes/login.js → "failed to parse" (JavaScript con <, >, && rompe el parser)

Lectura de SSH keys:
- /home/nonroot/.ssh/id_rsa → vacío (no existe)

Lectura de llave privada RSA para falsificar JWT:
- /juice-shop/config/jwt.pem → vacío (no existe)
- /juice-shop/config/rsa.pem → vacío (no existe)

Intento de SSRF via HTTP outbound:
- Se levantó netcat en Kali (puerto 9999) y se intentó que el servidor hiciera una petición HTTP hacia Kali usando XXE con http:// en lugar de file://
- El servidor no conectó → el contenedor no puede hacer peticiones HTTP hacia afuera
- Se confirmó: no hay SSRF, solo XXE con lectura local de archivos

Lectura de variables de entorno del proceso:
- /proc/self/environ → "failed to parse" (existe pero contiene bytes nulos \0 que rompen el parser)

## Limitaciones encontradas

La XXE tiene dos restricciones prácticas en este escenario:

1. El parser solo lee archivos locales (file://). No puede hacer peticiones HTTP hacia afuera, por lo que técnicas Out-of-Band para exfiltrar archivos con caracteres especiales no son viables.

2. Los archivos con caracteres especiales de XML (como <, >, &, comillas) rompen el parser y devuelven "failed to parse". Esto impide leer código fuente JavaScript, archivos YAML, variables de entorno, y otros archivos de configuración.

Solo son legibles archivos de texto plano sin esos caracteres, como /etc/passwd.

## Técnicas MITRE ATT&CK utilizadas

T1595 - Reconnaissance: Nmap, enumeración de JS, directory listing de FTP
T1190 - Exploit Public-Facing Application: XXE en endpoint de upload XML
T1083 - File and Directory Discovery: Lectura de archivos via XXE
T1552 - Unsecured Credentials: Intento de lectura de credenciales (parcialmente exitoso con /etc/passwd)

## Hallazgos documentados

XXE (T1190): El endpoint /file-upload procesa entidades XML externas sin sanitizar. Permite leer archivos del sistema de archivos del contenedor. Severidad: Alta.

Information Disclosure en JWT: El token JWT contiene el hash MD5 de la contraseña del usuario dentro del payload. Cualquiera con acceso al token puede extraer el hash e intentar crackearlo offline. Severidad: Alta.

Directory Listing en /ftp/: El servidor expone un listado completo de archivos internos incluyendo una base de datos KeePass (incident-support.kdbx) y archivos de configuración de backup. Aunque la descarga está restringida a .md y .pdf, la visibilidad de los archivos es un hallazgo. Severidad: Media.

FTP Restrictions Bypass Potential: El archivo incident-support.kdbx y package.json.bak son visibles pero no descargables via HTTP. Podrían ser accesibles si se encontrara otro vector. Documentado para futuro.

Stack Traces expuestos: Todos los errores de la aplicación incluyen el stack trace completo con rutas absolutas del servidor (/juice-shop/build/routes/...). Esto facilita el reconocimiento. Severidad: Baja.

## Cabos sueltos

No SSRF: El contenedor no puede hacer peticiones HTTP hacia afuera. Sin Out-of-Band XXE, los archivos con caracteres especiales son inaccesibles. En un escenario real, si el contenedor tuviera salida a internet, se podría exfiltrar el contenido via DTD externo.

incident-support.kdbx: Base de datos KeePass visible en el FTP. Si se encontrara otro vector para descargarla, podría crackearse offline con hashcat o john y contener credenciales del sistema.

JWT RS256 sin llave encontrada: El servidor usa RS256 para firmar JWT. Si se encontrara la llave privada, se podrían falsificar tokens de admin. Las rutas comunes probadas no devolvieron resultados.

## Conclusión

Se completó la fase de Initial Access via XXE con lectura confirmada de archivos del sistema. La escalación posterior fue bloqueada por las limitaciones del parser XML y el aislamiento del contenedor Docker. Se documentaron cuatro hallazgos de seguridad reales y se identificaron vectores para continuar en sesiones futuras.

La cadena fue más corta de lo planeado, pero todos los pasos ejecutados son técnicas reales y replicables en cualquier aplicación que procese XML sin deshabilitar entidades externas.

Próximo: Continuar la cadena con los eslabones restantes usando los hallazgos de hoy como punto de partida, o pivotar al segundo vector disponible (DVWA en puerto 8080).
