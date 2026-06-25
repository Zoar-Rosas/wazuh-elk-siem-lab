## Integración AlienVault OTX

La integración consulta la API de OTX para correlacionar hashes e IPs detectados por FIM contra la base de datos de amenazas de AlienVault.

**Características del script (`integrations/custom-alienvault.py`):**

- Consulta en orden de prioridad: `sha256` → `md5` → `sha1` → `IPv4`
- **Cache local de 24h** en `/var/ossec/logs/.alienvault_cache.json` para no quemar el rate limit de la API gratuita
- **Filtro de rutas ruidosas** — excluye carpetas de logs para evitar consultas innecesarias
- **Write** del cache (tmp + rename) para ejecuciones concurrentes
- Curaduría de tags OTX: prioriza `ransomware`, `apt`, `backdoor`, `exploit`, `trojan`
- Filtra tags genéricos sin valor (`hostname`, `url`, `md5`, etc.)

**Configurar la API key:**

1. Crea cuenta gratuita en [otx.alienvault.com](https://otx.alienvault.com)
2. Ve a tu perfil → API Key
3. Colocala dentro de **wazuh_manager.conf** en el servidor:

```env
<api_key>ALIENVAULT_API_KEY</api_key>
```

4. En `configs/wazuh_manager.conf`, la integración ya está configurada para leerla.

![](/.assets/otx.jpg)