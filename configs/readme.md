# Configuraciones

Esta carpeta contiene los archivos de configuración listos para usar. Los valores sensibles (IPs, API keys) están reemplazados por variables de entorno, revisa los archivos para definirlos con tus valores.

---
## Dashboard Kibana

El archivo `configs/dashboard.ndjson` contiene el dashboard personalizado exportado. Para importarlo:

1. Kibana → **Stack Management** → **Saved Objects**
2. Click en **Import**
3. Selecciona `dashboard.ndjson`
4. Confirma overwrite si se pide

**El dashboard incluye:**

- **Panel de Active Response**: contabiliza las acciones automáticas disparadas por el SIEM. 

- **Tabla de auditoría**: Lista y ennumera procesos o comandos ejecutados en el endpoint.

- **Grafica de alertas**: Clasifica las alertas en baja, media, alta y critica.

- **Linea del tiempo**: Refleja la cantidad de alertas altas y criticas registradas a lo largo del tiempo.

- **Grafica de pastel**: Muestra la distribución de malware registradas.

- **Grafica de actividad**: Muestra los picos diarios de archivos FIM creados, modificados y eliminados.

- **Grafica de movimientos**: Organiza que archivos FIM fueron manipulados un mayor numero de veces. 
 

![ ](/.assets/dashboard_1.jpg)
![ ](/.assets/dashboard_2.jpg)
![ ](/.assets/dashboard_3.jpg)

---
## Reglas de deteccion personalizadas

Todas las reglas están en `configs/local_rules.xml`. Estas son las amenazas que detecta el SIEM:

| Rule ID | Nivel | Técnica | MITRE ATT&CK | Descripción |
|---|---|---|---|---|
| 100001 | 5 | Auth Failure | T1110 | SSH — intentos fallidos desde IP específica |
| 100002 | 10 | Brute Force | T1110.001 | Fuerza bruta Windows (EventID 4625) → **Active Response** |
| 100003 | 6 | Execution | T1059.001 | Proceso iniciado desde PowerShell (Sysmon) |
| 100004 | 8 | Auth Failure | T1110 | Autenticación fallida Windows (EventID 4625) |
| 100005 | 9 | Persistence | T1053.005 | Tarea programada creada (EventID 4698) |
| 100006 | 10 | Lateral Movement | T1569.002 | PsExec detectado (EventID 7045) |
| 100007 | 7 | FIM | T1565 | Modificación de archivo crítico |
| 100008 | 7 | FIM | T1105 | Archivo nuevo detectado — posible dropper |
| 100009 | 8 | Remote Access | T1021.001 | Conexión RDP exitosa (logon type 10) |
| 100100 | 0 | Whitelist | — | Falso positivo: cleanmgr.exe |
| 100101 | 0 | Whitelist | — | Falso positivo: Microsoft Copilot DCOM |
| 100200 | 10 | Threat Intel | T1566 | AlienVault OTX — IOC detectado |

---