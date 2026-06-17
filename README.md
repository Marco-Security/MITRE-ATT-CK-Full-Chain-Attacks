# MITRE ATT&CK Full Chain Attacks

Operación **Eslabón** — diez cadenas de ataque completas siguiendo el framework MITRE ATT&CK, ejecutadas día a día sobre un laboratorio aislado con dos VMs víctima (Ubuntu y FLARE-VM) y Kali como atacante.

Cada día sigue el mismo esqueleto:

> Recon → Initial Access → Execution → Discovery → Privilege Escalation → Persistence → Credential Access → Defense Evasion → Collection → Exfiltration → *(Impact opcional)*

El objetivo es practicar la cadena completa de un compromiso real, documentar cada técnica MITRE empleada, y dejar un trazo verificable de qué huellas quedan en el sistema —lo que mañana será mi superficie de detección como SOC analyst.

## Laboratorio

| VM | Rol | IP |
|---|---|---|
| Kali Linux | Atacante | `192.168.1.132` |
| Ubuntu Server | Víctima Linux | `192.168.1.96` |
| FLARE-VM (Windows) | Víctima Windows | LAN local |

Las tres máquinas viven en la misma red local `192.168.1.0/24`. Kali es la máquina-operador; las dos víctimas alternan como objetivo del día.

## Rotación de 10 días

| Día | Víctima | Vector de Initial Access | MITRE |
|----|---------|---------------------------|-------|
| **1** | Ubuntu | Exploit de aplicación web pública (DVWA) | `T1190`, `T1078` |
| 2 | FLARE-VM | Phishing con adjunto malicioso | `T1566.001` |
| 3 | Ubuntu | Fuerza bruta SSH | `T1110`, `T1133` |
| 4 | FLARE-VM | Phishing por enlace / ClickFix / AiTM de sesión | `T1566.002`, `T1557` |
| 5 | Ubuntu | Servicio vulnerable (Samba/FTP) | `T1190` |
| 6 | FLARE-VM | Fuerza bruta RDP | `T1110`, `T1133` |
| 7 | Ubuntu | Inyección en API → privesc por capabilities | `T1190` |
| 8 | FLARE-VM | Scheduled task → credential dumping | `T1053.005`, `T1003` |
| 9 | Ubuntu | Misconfig de Docker → escape al host | `T1611` |
| 10 | FLARE-VM | Cadena completa con Impact (ransomware simulado) | `T1486` |

---

## Día 1 · Ubuntu — DVWA: de visitante anónimo a botín en mano

**Vector de Initial Access:** *Exploit de aplicación web pública* (`T1190`) combinado con *credenciales por defecto* (`T1078`).

El objetivo fue un contenedor Docker exponiendo DVWA en el puerto `8080` del host Ubuntu. Sin tocar exploits sofisticados, el camino fue el de menor esfuerzo: descubrir la app oculta tras un Apache "default page", autenticarse con `admin/password`, y aprovechar el módulo de Command Injection (con `security=low`) para conseguir RCE como `www-data` dentro del contenedor.

A partir de ese pie de playa la cadena progresó hasta extraer credenciales hardcodeadas, romper hashes MD5 sin salt y exfiltrar todo el botín por HTTP simulando un archivo de actualización legítimo. La fase de Defense Evasion se intentó pero quedó bloqueada por permisos Unix —un hallazgo intencionalmente documentado, no oculto— evidenciando que la limpieza de logs en Linux casi siempre requiere PrivEsc previa.

### Resumen de la cadena

| # | Eslabón | Técnica MITRE | Resultado |
|---|---------|---------------|-----------|
| 1 | Reconnaissance | `T1595`, `T1595.003` | DVWA identificada en `:8080`; Juice Shop en `:3000` registrado como cabo suelto |
| 2 | Initial Access | `T1078` — Valid Accounts | Login con credenciales por defecto `admin / password` |
| 3 | Execution | `T1059.004` — Unix Shell | RCE como `www-data` vía Command Injection en DVWA |
| 4 | C2 Channel | `T1071.001` — Web Protocols | Reverse shell + upgrade a TTY interactivo (`script` + `stty raw`) |
| 5 | Discovery | `T1083`, `T1057`, `T1018`, `T1046` | Enclave Docker `172.18.0.0/16` mapeado; SSH del host visible solo desde dentro |
| 6 | Persistence | `T1505.003` — Web Shell | `dvwa-helper.php` plantado en `/hackable/uploads/` |
| 7 | Credential Access | `T1552.001` + `T1110.002` | MySQL creds en `config.inc.php`; 5 hashes MD5 crackeados con John |
| 8 | Defense Evasion | `T1070` — Indicator Removal | **Bloqueado por permisos Unix** — declarado como cabo suelto hasta tener root |
| 9 | Collection | `T1560.001` — Archive Collected Data | Botín empaquetado en `/tmp/.loot/` y comprimido con `tar` |
| 10 | Exfiltration | `T1041` + `T1036` | Archivo disfrazado como `system_update.tar.gz` y descargado vía HTTP |

### Cabos sueltos documentados

- **Juice Shop** alcanzable internamente en `172.18.0.2` — pivote intra-Docker pendiente.
- **SSH del host Ubuntu** visible desde el contenedor (`172.18.0.1:22`), con credenciales reutilizables del cracking de DVWA — vector candidato para el **Día 9** (escape de contenedor).
- **Defense Evasion completo** queda postergado al post-escape (requiere root para tocar `/var/log/apache2/`).
- **Webshell viva** en `dvwa-helper.php` — punto de re-entrada disponible para días futuros sin repetir la cadena.

### Lecciones clave (perspectiva SOC)

- La **superficie pública** de un host casi nunca refleja su superficie real. El SSH y la base de datos del host estaban invisibles desde la LAN externa pero perfectamente alcanzables desde un contenedor comprometido. *Compromiso de un servicio expuesto = visibilidad nueva sobre todo lo interno.*
- **Borrar logs como usuario no privilegiado en Linux es prácticamente imposible.** Si un SIEM detecta intento de limpieza de logs, significa que el atacante ya escaló a root *o* está fallando — ambos casos son señal valiosa.
- Cada paso ofensivo deja un rastro inevitable en algún log del sistema. La defensa moderna se basa en **enviar esos logs fuera del host en tiempo real**, antes de que un atacante con root pueda destruirlos.

---

📂 **Journal completo del día:** [`day-01-ubuntu-dvwa.md`](./day-01-ubuntu-dvwa.md)
