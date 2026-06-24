# Wazuh Custom SIEM

![Wazuh](https://img.shields.io/badge/Wazuh-4.10.4-blue?style=flat-square&logo=wazuh)
![Elastic](https://img.shields.io/badge/ELK-Stack-005571?style=flat-square&logo=elastic)
![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?style=flat-square&logo=docker)

---

## Descripción

Este repositorio tiene un entorno SIEM personalizado construido sobre **Wazuh + ELK Stack** desplegado con Docker Compose, orientado a la detección y respuesta de amenazas en tiempo real sobre endpoints Windows, desde un servidor Linux.

El proyecto implementa:
- Detección de **fuerza bruta SSH y Windows** (EventID 4625)
- Detección de **movimiento lateral** vía PsExec (EventID 7045)
- Detección de **persistencia** mediante tareas programadas (EventID 4698)
- Monitorización de **PowerShell y Sysmon** (procesos sospechosos)
- **Active Response** automático: bloqueo de IP + kill de proceso al detectar ataque
- Integración con **AlienVault OTX** para correlación de IOCs en tiempo real
- **FIM** (File Integrity Monitoring) en rutas críticas de Windows y Linux
- **Dashboard personalizado** en Kibana con visualización de eventos por categoría

---

##  Arquitectura

```
[Agente Wazuh]  ──logs──▶  [Wazuh Manager]  ──eventos──▶  [Elasticsearch]
  (Windows)                    (Docker)                        (Índices)
                                  │                                │   
                           [AlienVault OTX]                [Kibana Dashboard]
                          Correlación de IOC                 Alertas / IOCs
                                  │
                           [Active Response]    
                            kill-powershell                
                             netsh-block-ip
```

---

## Especificaciones del laboratorio

| Componente | Versión |
|---|---|
| Docker | 26.1.5 |
| Docker Compose | 2.26.1 |
| OS host | Linux 6.19.10+parrot7 / Windows WSL2 |
| Python (agente) | 3.13.5 |

---

## Instalación y despliegue

### 1. Clonar el repositorio oficial de Wazuh dentro del servidor linux

```bash
git clone https://github.com/wazuh/wazuh-docker.git
cd wazuh-docker/single-node
```

### 2. Generar certificados SSL

```bash
docker-compose -f generate-indexer-certs.yml run --rm generator
```

### 3. Configurar variables de entorno

Copia el archivo de ejemplo y remplaza con tus valores:

```
WAZUH_CLUSTER_KEY=genera_con_openssl_rand_hex_16
WAZUH_SERVER_IP=192.168.x.x
WAZUH_MANAGER_IP=192.168.x.x
ALIENVAULT_API_KEY=tu_api_key_de_otx
```

### 4. Levantar el stack

```bash
docker-compose up -d
docker-compose ps   # verifica que todos los servicios estén "healthy"
```

### 5. Acceder a Kibana

```
URL:      https://localhost
Usuario:  admin
Password: (docker-compose.yml)
```

---

## Instalación del agente (Windows)

En el endpoint Windows a monitorizar, ejecuta en PowerShell como administrador:

```powershell
Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.x.x-1.msi `
  -OutFile wazuh-agent.msi

msiexec.exe /i wazuh-agent.msi /q `
  WAZUH_MANAGER="${WAZUH_MANAGER_IP}" `
  WAZUH_AGENT_NAME="windows-agent-01"

NET START WazuhSvc
```

Luego copia los archivos de configuración de este repo:

```
configs/ossec.conf  →  C:\Program Files (x86)\ossec-agent\ossec.conf
```

---


## Configuraciones, integración y respuesta activa

Estas carpetas contienen los archivos de configuración y las integraciones personalizadas del laboratorio.

- Configs → reglas personalizadas (local_rules.xml), whitelists y parámetros de detección.

- Integrations → scripts y conectores externos (ej. AlienVault OTX, respuestas activas).

- Active response → scripts creados para ejecutarse bajo ciertas condiciones.

Para ver en detalle qué hace cada archivo, revisa los README.md dentro de cada carpeta. Allí encontrarás especificaciones, ejemplos y notas de uso.

---
## Estructura del repositorio
```
wazuh-custom-siem-project/
├── README.md
├── configs/
│   ├── readme.md               
│   ├── ossec.conf              # Configuración del agente Windows
│   ├── wazuh_manager.conf      # Configuración del manager + active response
│   ├── local_rules.xml         # Reglas de detección personalizadas
│   └── dashboard.ndjson        # Dashboard Kibana exportado
├── integrations/
│   ├── readme.md
│   ├── custom-alienvault.py    # Integración OTX con cache y filtros
│   └── custom-alienvault.sh    # Bash wrapper (launcher Wazuh estándar)
└── active-response/
    ├── readme.md
    ├── kill-powershell.cmd     # Script de respuesta automática
    └── netsh.exe               # Bloqueo de IP atacante
```
---

## Seguridad del repositorio

Este repo **no contiene** información sensible:

-  API keys reemplazadas por variables de entorno
-  IPs de red local reemplazadas por placeholders
-  Cluster key reemplazada por placeholders
-  Nombres de usuario/paths personales neutralizados
-  Certificados SSL excluidos (`certs/`, `*.pem`, `*.key`)

---

## Licencia

MIT License — libre para usar, modificar y distribuir con atribución.
