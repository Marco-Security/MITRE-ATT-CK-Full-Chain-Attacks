# MITRE ATT&CK Full Chain Attacks

Operación **Eslabón** — trece cadenas de ataque completas siguiendo el framework MITRE ATT&CK, ejecutadas día a día sobre un laboratorio aislado con víctimas en tres plataformas: Linux (Ubuntu), Windows (Win10), y Android, atacadas desde Kali Linux.

Cada día sigue el mismo esqueleto:

> Recon → Initial Access → Execution → Discovery → Privilege Escalation → Persistence → Credential Access → Defense Evasion → Collection → Exfiltration → *(Impact opcional)*

El objetivo es practicar la cadena completa de un compromiso real, documentar cada técnica MITRE empleada, y dejar un trazo verificable de qué huellas quedan en el sistema —lo que mañana será mi superficie de detección como SOC analyst.

## Laboratorio

| VM / Dispositivo | Rol | IP / Identificador |
|---|---|---|
| Kali Linux | Atacante | `192.168.1.132` |
| Ubuntu Server | Víctima Linux (Días impares 1-9) | `192.168.1.96` |
| Win10-Victim | Víctima Windows (Días pares 2-10) | `192.168.1.183` (`DESKTOP-ALSOF1R`) |
| Samsung Galaxy A21s | Víctima Android (Días 11-12) | LAN local |
| Celular secundario | Víctima/cliente para AiTM (Día 13) | Wi-Fi controlado |
| Antena Alfa | Hardware para AiTM (Día 13) | Modo monitor/AP |

Las tres VMs y el dispositivo Android principal viven en la misma red local `192.168.1.0/24`. Kali es la máquina-operador; las víctimas rotan según la rotación. Para el Día 13, se monta un Wi-Fi aislado con la antena Alfa y los dos celulares como únicos clientes.

## Rotación de 13 días

Cada día tiene un **vector de Initial Access realista** (algo que un atacante encontraría desde internet o vía proximidad sin presuponer acceso interno previo) y un **objetivo**: una máquina/servicio expuesto, un humano que ejecuta algo, o un dispositivo móvil.

### Días 1-10 · Matriz MITRE ATT&CK Enterprise

| Día | Víctima | Vector de Initial Access | MITRE | Objetivo |
|----|---------|---------------------------|-------|----------|
| **1** | Ubuntu | Exploit de aplicación web pública (DVWA) | `T1190`, `T1078` | Máquina |
| 2 | Win10 | Phishing con adjunto malicioso (EXE disfrazado de PDF) | `T1566.001` | Humano |
| 3 | Ubuntu | API vulnerable — SSRF / RCE | `T1190` | Máquina |
| 4 | Win10 | Phishing por enlace / ClickFix / AiTM de sesión | `T1566.002`, `T1557` | Humano |
| 5 | Ubuntu | WordPress / CMS con plugin vulnerable | `T1190` | Máquina |
| 6 | Win10 | Drive-by compromise / HTML smuggling | `T1189`, `T1566.002` | Humano |
| 7 | Ubuntu | Inyección en API (auth bypass + RCE) | `T1190` | Máquina |
| 8 | Win10 | Phishing con archivo ISO / HTML smuggling | `T1566.001` | Humano |
| 9 | Ubuntu | Servicio DevOps expuesto con CVE conocido (Gitea / Jenkins / MinIO) | `T1190` | Máquina |
| 10 | Win10 | Cadena completa con Impact (ransomware simulado) | `T1486` | Humano |

### Días 11-13 · Matriz MITRE ATT&CK Mobile + Wireless

Los días 11 y 12 usan **MITRE ATT&CK for Mobile**, una matriz separada con técnicas específicas para Android/iOS. El día 13 usa la matriz Enterprise pero centrada en ataques de proximidad/Wi-Fi.

| Día | Víctima | Vector de Initial Access | MITRE | Objetivo |
|----|---------|---------------------------|-------|----------|
| **11** | Android (Samsung A21s) | ADB expuesto en Wi-Fi / servicio embebido en app | `T1428` (Exploitation of Remote Services - Mobile) | Red local |
| 12 | Android (Samsung A21s) | Smishing + sideload de APK maliciosa | `T1660` (Phishing - Mobile), `T1456` | Humano |
| 13 | Celulares en Wi-Fi controlado | Rogue AP / Evil Twin + AiTM de sesión con reverse-proxy | `T1557`, `T1539`, `T1550.004` | Humano (vía red) |

### Patrón humano vs. máquina

La rotación alterna no solo víctima sino tipo de vector:

- **Días "máquina" (impares 1-9 + Día 11) — objetivo servicio.** El atacante envía payloads contra servicios expuestos. Nadie hace clic. La telemetría útil son patrones de exploit en logs, spikes de error, procesos hijo inesperados del web/app server, y conexiones salientes hacia IPs nuevas.
- **Días "humano" (pares 2-10 + Días 12-13) — objetivo persona.** La víctima ejecuta algo (clic, sideload, conexión a Wi-Fi). La telemetría útil son árboles de procesos post-clic, descargas seguidas de ejecución, instalación de apps fuera de stores oficiales, y reuso de sesiones desde geos/dispositivos nuevos.

Esta dicotomía es la base del 80% de las detecciones en SC-200 — Defender for Endpoint, Defender for Cloud Apps, y Defender for Mobile están construidos sobre exactamente este principio.

### Técnicas que NO son vector de entrada (eslabones intermedios)

Algunas técnicas comunes no aparecen como Initial Access porque, en un escenario realista, **el atacante no las usa para entrar desde internet** — las usa una vez dentro. Quedan integradas en su capa MITRE correcta:

- **Fuerza bruta SSH/RDP** (`T1110`) → como *Lateral Movement* después del foothold, cuando el atacante ya descubrió servicios internos.
- **Escape de Docker** (`T1611`) → como *Privilege Escalation* o *Lateral Movement* en días donde se compromete un contenedor.
- **Scheduled Task** (`T1053.005`) → como *Persistence* en días Windows.
- **Cred dumping / LSASS / Mimikatz** (`T1003`) → como *Credential Access* en días Win10.
- **Robo de cookie de sesión Android** → como *Credential Access* en días móviles.
