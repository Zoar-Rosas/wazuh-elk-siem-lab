## Active Response

Al dispararse la regla **100002** (fuerza bruta Windows, ≥2 eventos en 120 segundos), Wazuh ejecuta automáticamente **dos respuestas simultáneas**:

### 1. `kill-powershell.cmd`
Termina los procesos PowerShell y CMD. Sin timeout — los procesos se matan inmediatamente.

### 2. `netsh-block-ip`
Bloquea la IP atacante vía `netsh advfirewall` con timeout de **300 segundos** (5 minutos). Después del timeout, Wazuh revierte el bloqueo automáticamente.

---
>Número de veces en el que se activo la respuesta automática.

![](/.assets/active_response.jpg)

---