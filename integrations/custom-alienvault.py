#!/usr/bin/env python3
# Integracion Wazuh - AlienVault OTX
# Incluye: cache local de 24h (evita quemar el rate limit de OTX) y
# filtro de rutas excluidas (evita disparar consultas por ruido operativo, ej. logs)

import sys
import json
import os
import time
import requests
from urllib.parse import urljoin

alert_file = sys.argv[1]
api_key = sys.argv[2]
hook_url = "https://otx.alienvault.com/api/v1/"

# --- Configuracion de cache ---
CACHE_FILE = "/var/ossec/logs/.alienvault_cache.json"
CACHE_TTL = 86400  # 24 horas en segundos

# --- Rutas que NO disparan consulta a OTX (ruido operativo, no malware) ---
EXCLUDED_PATH_KEYWORDS = ['\\logs\\', '/logs/']


def query_otx(indicator_type, indicator):
    """Devuelve (data_dict_or_None, status_str)"""
    headers = {'X-OTX-API-KEY': api_key}
    url = urljoin(hook_url, f"indicators/{indicator_type}/{indicator}/general")
    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            return response.json(), "Connected"
        else:
            return None, f"Error HTTP {response.status_code}"
    except requests.exceptions.RequestException as e:
        return None, f"Connection error: {e}"


# ---------------------------------------------------------------------------
# CACHE: guarda resultados de OTX por hash, con TTL, para no repetir consultas
# cuando el mismo indicador se ve varias veces en poco tiempo (ej. mismo
# archivo modificado varias veces, o el mismo malware en varios agentes).
# ---------------------------------------------------------------------------

def load_cache():
    """Lee el archivo de cache. Si no existe o esta corrupto, devuelve vacio."""
    if not os.path.exists(CACHE_FILE):
        return {}
    try:
        with open(CACHE_FILE, 'r') as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError):
        return {}


def save_cache(cache):
    """Escribe el cache de forma atomica (archivo temporal + rename) para
    evitar corromperlo si dos ejecuciones escriben al mismo tiempo."""
    try:
        tmp_file = CACHE_FILE + ".tmp"
        with open(tmp_file, 'w') as f:
            json.dump(cache, f)
        os.replace(tmp_file, CACHE_FILE)
    except IOError:
        pass


def get_cached_result(indicator):
    """Devuelve el resultado guardado si existe y no ha expirado (< 24h)."""
    cache = load_cache()
    entry = cache.get(indicator)
    if entry and (time.time() - entry.get('ts', 0)) < CACHE_TTL:
        return entry.get('data')
    return None


def store_cached_result(indicator, data):
    """Guarda un resultado nuevo en el cache con su timestamp actual."""
    if data is None:
        return
    cache = load_cache()
    cache[indicator] = {'ts': time.time(), 'data': data}
    save_cache(cache)


def extract_threat_info(otx_data):
    """
    Recorre los pulses devueltos por OTX y extrae informacion curada y util para SOC.
    """
    malware_name = "Unknown"
    tags = set()
    pulse_names = []

    # 1. LISTA NEGRA: Palabras inutiles que OTX mete por defecto
    garbage_words = {
        'ascii', 'alienvault', 'automated', 'body', 'campaign', 'click', 'cname',
        'com dla', 'compatibility', 'config', 'configure', 'contained', 'data',
        'date', 'detects', 'domain', 'error', 'file', 'files', 'hostname', 'html',
        'https', 'ip', 'ip address', 'json', 'link', 'location', 'md5', 'sha256',
        'sha1', 'exe', 'dll', 'zip', 'otx assengment', 'assignment', 'assigment',
        'subdomains', 'url', 'urls', 'whitelist', 'yara', 'target', 'text'
    }

    # 2. LISTA BLANCA DE PRIORIDAD
    priority_keywords = ['ransomware', 'trojan', 'lazarus', 'apt', 'backdoor', 'infostealer', 'exploit', 'worm']

    pulses = otx_data.get('pulse_info', {}).get('pulses', [])

    for pulse in pulses:
        families = pulse.get('malware_families', [])
        if families and malware_name == "Unknown":
            if isinstance(families[0], dict):
                malware_name = families[0].get('display_name', families[0].get('id', 'Unknown'))
            else:
                malware_name = str(families[0])

        for t in pulse.get('tags', []):
            t_clean = t.strip().lower()
            if 2 < len(t_clean) < 25 and t_clean.replace('-', '').replace('_', '').isalnum():
                if t_clean in garbage_words:
                    continue
                tags.add(t_clean)

        name = pulse.get('name')
        if name and len(pulse_names) < 5:
            pulse_names.append(name)

    sorted_tags = sorted(list(tags))
    priority_tags = [tag for tag in sorted_tags if any(key in tag for key in priority_keywords)]
    other_tags = [tag for tag in sorted_tags if tag not in priority_tags]
    final_tags = (priority_tags + other_tags)[:15]

    if malware_name == "Unknown" and priority_tags:
        malware_name = priority_tags[0].upper()

    return malware_name, final_tags, pulse_names


def process_alert(alert_json):
    """Procesa un solo alert: consulta OTX (o cache) y escribe el resultado en el log."""
    alert_id = alert_json.get('id')
    agent_id = alert_json.get('agent', {}).get('id')

    syscheck = alert_json.get('data', {}).get('syscheck', {})
    srcip = alert_json.get('data', {}).get('srcip')

    # --- Filtro de rutas excluidas: corta antes de gastar cuota de OTX ---
    syscheck_path = syscheck.get('path', '')
    if any(keyword in syscheck_path for keyword in EXCLUDED_PATH_KEYWORDS):
        return  # ruta excluida (ej. logs ruidosos), no se consulta OTX

    indicator = None
    indicator_type = None

    if 'sha256_after' in syscheck:
        indicator = syscheck['sha256_after']
        indicator_type = 'file'
    elif 'md5_after' in syscheck:
        indicator = syscheck['md5_after']
        indicator_type = 'file'
    elif 'sha1_after' in syscheck:
        indicator = syscheck['sha1_after']
        indicator_type = 'file'
    elif srcip:
        indicator = srcip
        indicator_type = 'IPv4'

    otx_result = None

    if indicator and indicator_type:
        # --- Primero revisa cache; si no hay hit valido, consulta OTX de verdad ---
        cached_data = get_cached_result(indicator)
        if cached_data is not None:
            otx_data, status = cached_data, "Cached"
        else:
            otx_data, status = query_otx(indicator_type, indicator)
            if otx_data:
                store_cached_result(indicator, otx_data)

        pulses_count = 0
        malware_name = "Unknown"
        tags = []
        pulse_names = []

        if otx_data:
            pulses_count = otx_data.get('pulse_info', {}).get('count', 0)
            malware_name, tags, pulse_names = extract_threat_info(otx_data)

        otx_result = {
            "alienvault": {
                "integration": "alienvault",
                "indicator": indicator,
                "type": indicator_type,
                "api_status": status,
                "pulses_found": pulses_count,
                "malware_name": malware_name,
                "tags": tags,
                "pulse_names": pulse_names
            }
        }

    if otx_result:
        # Nota: la clave de nivel superior es "alienvault", NUNCA "data" -
        # Wazuh ya reserva "data" como su propio contenedor interno.
        msg = {
            "integration": "alienvault",
            "alert_id": alert_id,
            "agent_id": agent_id,
            "alienvault": otx_result["alienvault"]
        }
        with open("/var/ossec/logs/integrations.log", "a") as log_file:
            log_file.write(json.dumps(msg) + "\n")
            print(json.dumps(msg))


# Punto de entrada
# encoding='utf-8' + errors='replace': algunos eventos de Windows (rutas/usuarios
# con acentos o ñ) llegan con bytes que no son UTF-8 valido y rompian json.load()
with open(alert_file, 'r', encoding='utf-8', errors='replace') as f:
    alerts = json.load(f)

if isinstance(alerts, list):
    for alert in alerts:
        process_alert(alert)
else:
    process_alert(alerts)

sys.exit(0)