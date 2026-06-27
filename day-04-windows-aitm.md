# Día 4 - Windows: AiTM Session Hijacking contra Microsoft 365

Operación Eslabón, 26-27 de junio de 2026.

## Objetivo

Ejecutar un ataque Adversary-in-the-Middle (AiTM) usando Evilginx como reverse proxy para interceptar una sesión autenticada de Microsoft 365, incluyendo el bypass de MFA, sin necesidad de conocer las credenciales de antemano.

## Infraestructura

Atacante: Kali Linux (192.168.1.132)
VPS C2: Ubuntu 24.04 en Azure (74.249.72.234, VM C2-Lab-Marco)
Dominio: anclalab.com (Cloudflare DNS)
Víctima: Win11 host (marco.eros@labmx.ai, cuenta Azure for Students)
Herramienta: Evilginx v3.3.0 (compilado desde fuente)

## Cómo funciona el ataque

Evilginx actúa como un reverse proxy entre la víctima y Microsoft 365. Cuando la víctima visita el link de phishing, Evilginx reenvía todas las peticiones al sitio real de Microsoft y devuelve las respuestas a la víctima. La víctima se autentica normalmente (usuario, contraseña, MFA), pero Evilginx intercepta las cookies de sesión que Microsoft genera después de la autenticación exitosa. Con esas cookies, el atacante puede acceder a la cuenta sin repetir el proceso de autenticación.

La diferencia con un phishing tradicional es que este ataque no necesita que la víctima escriba sus credenciales en una página falsa. La página es el sitio real de Microsoft, solo que el tráfico pasa por el proxy del atacante.

## Preparación

Se configuró la VPS en Azure con los puertos 22, 80, 443 y 53 abiertos en el Network Security Group.

En Cloudflare se crearon dos registros A con proxy desactivado (DNS only):

```
login.anclalab.com → 74.249.72.234
www.anclalab.com   → 74.249.72.234
```

El proxy de Cloudflare debe estar desactivado porque Evilginx necesita recibir el tráfico directamente para gestionar sus propios certificados TLS con Let's Encrypt.

En la VPS se instaló Go y se compiló Evilginx desde el repositorio oficial. Se detuvo systemd-resolved para liberar el puerto 53, que Evilginx usa para su servidor DNS interno.

Se descargó un phishlet de Microsoft 365 (o365.yaml) que define cómo proxear microsoftonline.com y office.com, y qué cookies capturar.

## Configuración de Evilginx

Al iniciar Evilginx se configuró el dominio y la IP pública:

```
config domain anclalab.com
config ipv4 external 74.249.72.234
```

Se asignó el hostname al phishlet y se activó:

```
phishlets hostname o365 anclalab.com
phishlets enable o365
```

Evilginx obtuvo automáticamente certificados TLS válidos de Let's Encrypt para login.anclalab.com y www.anclalab.com. Con certificados válidos, la víctima ve el candado verde en el navegador sin advertencias.

Se generó el lure (link de phishing):

```
lures create o365
lures get-url 0
```

URL generada: https://login.anclalab.com/DOPMRpXD

## Ejecución del ataque

La víctima abrió el link en su navegador. La página mostrada era visualmente idéntica al login real de Microsoft, con la diferencia de que la URL era login.anclalab.com en lugar de login.microsoftonline.com.

La víctima introdujo sus credenciales y completó el proceso de MFA normalmente. Evilginx capturó todo en tiempo real:

```
[+++] [0] Password: [Triceratops@1993]
[+++] [0] Username: [marco.eros@labmx.ai]
[+++] [0] all authorization tokens intercepted!
```

El detalle de la sesión capturada:

```
id           : 1
phishlet     : o365
username     : marco.eros@labmx.ai
password     : Triceratops@1993
tokens       : captured
landing url  : https://login.anclalab.com/DOPMRpXD
remote ip    : 189.183.3.84
```

Se capturaron tres cookies de sesión:
- ESTSAUTH
- ESTSAUTHPERSISTENT
- SignInStateCookie

Todas pertenecientes al dominio .login.microsoftonline.com y con expiración de aproximadamente un año.

## Session Hijacking

Con las cookies capturadas se importaron en Chrome usando la extensión StorageAce. El JSON de cookies requirió modificar httpOnly:true a httpOnly:false para permitir la importación desde la extensión.

Al navegar a https://portal.office.com con las cookies importadas, el navegador quedó autenticado directamente en la cuenta de marco.eros@labmx.ai sin escribir contraseña ni aprobar MFA.

El session hijacking fue exitoso.

## Por qué bypasea MFA

MFA protege el proceso de autenticación inicial. Una vez que la autenticación termina, Microsoft genera cookies de sesión que representan una sesión ya validada. Evilginx roba esas cookies post-autenticación, no las credenciales en sí. Microsoft no puede distinguir entre la víctima usando su cookie legítima y el atacante usando esa misma cookie desde otra máquina.

Este ataque funciona contra cualquier implementación de MFA basada en sesiones web (TOTP, push notifications, SMS). No funciona contra FIDO2/passkeys porque esas implementaciones vinculan la autenticación al hardware del dispositivo, no a una cookie.

## Técnicas MITRE ATT&CK utilizadas

T1566.002 - Phishing: Spearphishing Link: Link enviado a la víctima que apunta al proxy de Evilginx.
T1557 - Adversary-in-the-Middle: Evilginx como reverse proxy entre víctima y Microsoft 365.
T1539 - Steal Web Session Cookie: Captura de cookies ESTSAUTH y ESTSAUTHPERSISTENT post-autenticación.
T1550.004 - Use Alternate Authentication Material: Web Session Cookies: Uso de las cookies robadas para acceder a la cuenta sin credenciales.

## Hallazgos de seguridad

MFA bypasseado via AiTM: El MFA basado en push/TOTP no protege contra ataques de sesión intermediaria. La única protección efectiva contra AiTM es FIDO2/passkeys con verificación de origen.

Credenciales también expuestas: Aunque el objetivo era la cookie, Evilginx también capturó usuario y contraseña en texto plano. Esto expone la cuenta incluso si las cookies expiran.

Certificado TLS válido en dominio atacante: La víctima vio un certificado válido en login.anclalab.com. Let's Encrypt emite certificados para cualquier dominio sin verificar intención. El candado verde no garantiza que el sitio sea legítimo.

Actividad de bots en IP pública: En los primeros segundos de levantar Evilginx, múltiples IPs de escáneres automáticos intentaron acceder al servidor buscando archivos expuestos (.env, wp-config.php). Evilginx los bloqueó automáticamente.

## Cabos sueltos

No se ejecutaron eslabones post-acceso como lectura de correos, descarga de archivos, o persistencia en la cuenta (reglas de inbox, OAuth apps maliciosas). Eso corresponde a días posteriores cuando se cubran técnicas de Collection y Impact en contexto de Microsoft 365.

## Conclusión

Se completó una cadena AiTM completa desde la generación del link de phishing hasta el acceso autenticado a Microsoft 365 sin contraseña ni MFA. El ataque es realista, reproducible, y representa una de las técnicas más efectivas contra organizaciones que dependen únicamente de MFA basado en TOTP o push notifications.

Próximo: Día 5 - Ubuntu, WordPress con plugin vulnerable.
