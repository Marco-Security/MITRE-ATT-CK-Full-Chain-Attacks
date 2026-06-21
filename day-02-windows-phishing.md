# Día 2 - Windows 10: Phishing con Reverse Shell y Persistencia

Operación Eslabón, 20 de junio de 2026.

## Objetivo

Ejecutar una cadena completa de ataque phishing en Windows 10 desde reconocimiento inicial hasta persistencia, documentando cada técnica MITRE ATT&CK utilizada.

## Máquinas

Víctima: Win10-Victim (192.168.1.183, usuario "analista")
Atacante: Kali Linux (192.168.1.132)

## Vector de Ataque

Se envía un correo con adjunto Documento_Setup.exe (instalador NSIS de 8.7 MB). El nombre engañoso y el ícono PDF hacen que parezca un documento legítimo. Cuando el usuario lo ejecuta, automáticamente:

1. Se abre un PDF real (para masquerading)
2. En segundo plano, se conecta una reverse shell PowerShell a Kali
3. Se crea una tarea programada que reconecta en cada logon

## Desarrollo

### Fase 1: Reconocimiento

Se identifica al usuario "analista" como objetivo. El nombre sugiere un rol técnico, por lo que es más probable que execute archivos. Se prepara un pretexto: "Informe Q4 2025 - Lectura requerida antes de la junta del viernes".

### Fase 2: Compilación del Artefacto

Se compilan dos scripts Python:

rat_final.py: Reverse shell minimalista que embebe un PDF en base64 y abre una shell PowerShell interactiva.

build_final.py: Script que embebe el PDF en rat_final.py, compila con PyInstaller a .exe, y luego lo empaqueta con NSIS para crear un instalador.

Resultado: Documento_Setup.exe de 8.7 MB que aparece como un instalador legítimo.

### Fase 3: Entrega y Ejecución

El usuario recibe el email y ejecuta el adjunto. NSIS extrae silenciosamente el .exe y lo ejecuta. El usuario ve un PDF abriéndose (el informe Q4 falso embebido) mientras que en paralelo se establece la reverse shell.

Desde Kali, inmediatamente aparece una shell PowerShell interactiva:

```
PS C:\Users\analista\Documents> whoami
desktop-alsof1r\analista
```

### Fase 4: Discovery (Enumeración del Sistema)

Desde la reverse shell se ejecutan comandos para enumerar:

Usuario y privilegios:
- Usuario: analista (no es admin en escritorio, pero SÍ es miembro del grupo Administradores locales)
- Privilegios habilitados: SeDebugPrivilege, SeImpersonatePrivilege (peligrosos para escalación)
- Privilegios deshabilitados: SeBackupPrivilege, SeRestorePrivilege

Usuarios locales:
- Administrador (deshabilitado)
- analista (activo)
- DefaultAccount, Invitado, WDAGUtilityAccount (todos deshabilitados)

Sistema operativo:
- Windows 10 Pro, Build 19045
- 8 GB RAM, 4 GB disponible
- Dominio: WORKGROUP (no está en dominio corporativo)
- Instalación original: 18 de junio de 2026
- Último boot: 20 de junio a las 12:16 PM
- Parches: 12 instalados (actualizaciones recientes)

Red:
- IP: 192.168.1.183 (DHCP)
- Puerta enlace: 192.168.1.254
- DNS: 192.168.1.254 (local)
- Adaptador: Intel PRO/1000 MT (VirtualBox)

Hallazgo importante: El usuario "analista" tiene SeImpersonatePrivilege habilitado, lo cual permitiría un ataque de Token Impersonation (JuicyPotato) para escalar a SYSTEM.

### Fase 5: Persistencia

Se crea una tarea programada llamada "WindowsUpdate" que:

- Se ejecuta automáticamente en cada logon del usuario
- Ubica el RAT en C:\Users\analista\AppData\Roaming\.cache\documento.exe
- Lanza PowerShell con la bandera -WindowStyle Hidden para no mostrar ventana
- Está configurada en modo Limited (sin privilegios elevados)

La tarea se crea exitosamente:

```
TaskName: WindowsUpdate
State: Ready
Trigger: AtLogon
Action: powershell.exe -NoProfile -WindowStyle Hidden -Command "& '$cacheDir\documento.exe'"
```

Sin embargo, al reiniciar la máquina con Real-time Protection activo, Defender bloquea la ejecución de documento.exe basándose en su firma (PyInstaller compilado es reconocible). La tarea nunca se ejecuta (LastRunTime muestra fecha dummy 30/11/1999).

## Técnicas MITRE ATT&CK Utilizadas

T1595.003 - Reconnaissance: Búsqueda de identidad de víctima
T1566.001 - Initial Access: Phishing con adjunto malicioso
T1059.001 - Execution: Command and Scripting Interpreter (PowerShell)
T1036 - Defense Evasion: Masquerading (PDF engañoso + NSIS wrapper)
T1018 - Discovery: Remote System Discovery
T1057 - Discovery: Process Discovery
T1082 - Discovery: System Information Discovery
T1053.005 - Persistence: Scheduled Task

## Telemetría Detectada

Sysmon Event 1 (Process Create):
- Documento_Setup.exe lanzado por explorer.exe
- PowerShell lanzado por documento.exe
- Patrón anómalo: .exe desde AppData spawneando PowerShell

Sysmon Event 3 (Network Connection):
- documento.exe conectando a 192.168.1.132:4444
- Conexión TCP sostenida (reverse shell interactivo)
- Puerto 4444 (no estándar)

Sysmon Event 11 (File Create):
- documento.exe creado en C:\Users\analista\AppData\Roaming\.cache
- Ubicación inusual (oculta)

Defender Event 1116:
- Threat: Trojan:Win32/Meterpreter!rfn
- Action: Bloqueó la ejecución de persistencia en logon

## Cabos Sueltos

MOTW (Mark of the Web): El archivo sigue generando warning "Editor desconocido" al ejecutarse. Se requiere un certificado Authenticode válido para eliminar esto completamente. Documentado como assumption del lab.

Persistencia bloqueada por Defender: Aunque la tarea programada se creó exitosamente, Defender bloqueó la ejecución cuando se activó Real-time Protection. En un escenario real, se requeriría ofuscación del PE (packing con UPX, code signing válido) o el uso de binarios legítimos del sistema (living-off-the-land).

Credential Dumping: No se realizó. Queda como técnica para futuro (LSASS dump, Mimikatz).

Lateral Movement: Se identificó que la red 192.168.1.0/24 tiene otras máquinas, pero no se enumeró ni se intentó movimiento lateral. Queda para futuro.

## Lecciones para SOC

1. SmartScreen y Real-time Protection son dos capas distintas. SmartScreen bloquea por reputación y firma digital; RTP bloquea por análisis heurístico. Ambas pueden eludirse o desactivarse en laboratorio, pero la combinación es poderosa.

2. Las tareas programadas son persistencia invisible. Sin herramientas de forensics o monitoreo activo, un usuario normal no detectaría "WindowsUpdate" ejecutándose en cada logon.

3. Los permisos peligrosos (SeDebugPrivilege, SeImpersonatePrivilege) en usuarios non-admin crean vectores claros de escalación. En una máquina corporativa, estos deberían estar restringidos.

4. El reverse shell interactivo sobre netcat plano es funcional pero ruidoso. Cada comando genera tráfico TCP visible. Un SOC con monitoring de red lo detectaría en minutos.

5. El masquerading (PDF engañoso + NSIS installer) es efectivo socialmente, pero técnicamente deja rastro claro en los logs de Sysmon. La detección requiere correlacionar: documento abierto + PowerShell spawneado + conexión outbound.

## Resumen

Se completó una cadena de ataque completa desde phishing inicial hasta persistencia. Seis de nueve eslabones MITRE fueron implementados exitosamente. La persistencia se bloqueó por Defender, pero el concepto se demostró. El reporte detalla cada paso, la telemetría generada, y cómo un SOC hubiera detectado el ataque en tiempo real.

Próximo: Día 3 con máquina Ubuntu (SSRF/RCE en aplicación web).
