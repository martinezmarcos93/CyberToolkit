"""
threat_intel.py — Herramienta 34: Consultas a fuentes de Threat Intelligence
Integración con APIs públicas (VirusTotal, AbuseIPDB, AlienVault OTX, Shodan, HIBP).
"""

import sys
import os
import json
import time

# Asegura que el directorio raíz esté en el path al ejecutar directamente
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils import (
    ok, error, warn, info, result,
    section_title, separator, dim, cyan, green, yellow, white, red, magenta,
    prompt, pause, validate_ip, export_results
)
from config import SETTINGS

try:
    import requests
    _HAS_REQUESTS = True
except ImportError:
    _HAS_REQUESTS = False

# ──────────────────────────────────────────────
#  API Keys (El usuario debe rellenarlas luego)
# ──────────────────────────────────────────────
API_KEYS = {
    "virustotal": "",
    "abuseipdb": "",
    "shodan": "",
    "otx": "",
    "hibp": ""
}

# Permitir sobrescribir las keys desde .cybertoolkitrc si existen
for k in API_KEYS:
    if f"api_key_{k}" in SETTINGS:
        API_KEYS[k] = SETTINGS[f"api_key_{k}"]


# ──────────────────────────────────────────────
#  Consultas a APIs
# ──────────────────────────────────────────────
def _query_virustotal(target: str, type_: str) -> dict:
    if not API_KEYS["virustotal"]:
        return {"error": "API Key de VirusTotal no configurada."}
    
    headers = {"x-apikey": API_KEYS["virustotal"]}
    try:
        if type_ == "ip":
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{target}"
        elif type_ == "domain":
            url = f"https://www.virustotal.com/api/v3/domains/{target}"
        elif type_ == "hash":
            url = f"https://www.virustotal.com/api/v3/files/{target}"
        else:
            return {"error": "Tipo no soportado"}
            
        resp = requests.get(url, headers=headers, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            return {"malicious": stats.get("malicious", 0), "suspicious": stats.get("suspicious", 0), "harmless": stats.get("harmless", 0)}
        else:
            return {"error": f"Error HTTP {resp.status_code}"}
    except Exception as e:
        return {"error": str(e)}


def _query_abuseipdb(ip: str) -> dict:
    if not API_KEYS["abuseipdb"]:
        return {"error": "API Key de AbuseIPDB no configurada."}
    
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": API_KEYS["abuseipdb"], "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    try:
        resp = requests.get(url, headers=headers, params=params, timeout=10)
        if resp.status_code == 200:
            data = resp.json().get("data", {})
            return {
                "abuseConfidenceScore": data.get("abuseConfidenceScore", 0),
                "totalReports": data.get("totalReports", 0),
                "countryCode": data.get("countryCode", "Unknown")
            }
        else:
            return {"error": f"Error HTTP {resp.status_code}"}
    except Exception as e:
        return {"error": str(e)}


def _query_shodan(ip: str) -> dict:
    if not API_KEYS["shodan"]:
        return {"error": "API Key de Shodan no configurada."}
    
    url = f"https://api.shodan.io/shodan/host/{ip}?key={API_KEYS['shodan']}"
    try:
        resp = requests.get(url, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            return {
                "os": data.get("os", "Unknown"),
                "ports": data.get("ports", []),
                "vulns": data.get("vulns", [])
            }
        else:
            return {"error": f"Error HTTP {resp.status_code}"}
    except Exception as e:
        return {"error": str(e)}


def _mode_analyze_ip() -> None:
    section_title("THREAT INTEL: ANÁLISIS DE IP")
    
    if not _HAS_REQUESTS:
        error("El módulo 'requests' no está instalado.")
        return

    ip = prompt("Ingresá la IP a investigar").strip()
    if not validate_ip(ip):
        error("IP inválida.")
        return
        
    info(f"Iniciando recolección de inteligencia para {cyan(ip)}...")
    print()
    results = {"target": ip, "type": "ip", "timestamp": time.time()}
    
    # VirusTotal
    info("Consultando VirusTotal...")
    vt = _query_virustotal(ip, "ip")
    results["virustotal"] = vt
    if "error" in vt:
        result("VirusTotal", dim(vt["error"]))
    else:
        mal = vt.get('malicious', 0)
        color = red if mal > 0 else green
        result("VirusTotal", color(f"{mal} motores lo marcan como malicioso."))
        
    # AbuseIPDB
    info("Consultando AbuseIPDB...")
    ab = _query_abuseipdb(ip)
    results["abuseipdb"] = ab
    if "error" in ab:
        result("AbuseIPDB", dim(ab["error"]))
    else:
        score = ab.get("abuseConfidenceScore", 0)
        color = red if score > 50 else (yellow if score > 0 else green)
        result("AbuseIPDB Score", color(f"{score}% (Reportes: {ab.get('totalReports')})"))
        
    # Shodan
    info("Consultando Shodan...")
    sh = _query_shodan(ip)
    results["shodan"] = sh
    if "error" in sh:
        result("Shodan", dim(sh["error"]))
    else:
        ports = sh.get("ports", [])
        vulns = sh.get("vulns", [])
        result("Shodan Ports", white(str(ports)))
        if vulns:
            result("Shodan Vulns", red(", ".join(vulns)))
            
    print()
    export = prompt("¿Deseas exportar estos resultados? [s/N]", default="n").lower()
    if export in ("s", "si", "y", "yes"):
        export_results("threat_intel_ip", results)


def _mode_explain() -> None:
    section_title("¿QUÉ ES THREAT INTELLIGENCE (CTI)?")

    print(f"""
  {white('CTI (Cyber Threat Intelligence)')}
  {dim('─' * 56)}
  Es información basada en evidencias sobre amenazas que pueden dañar a una 
  organización. Se usa para tomar decisiones de defensa o investigar incidentes.

  {cyan('VirusTotal:')}
  Agrega decenas de motores antivirus y escáneres web. Un archivo o URL marcado
  como malicioso por muchos motores es un fuerte Indicador de Compromiso (IoC).

  {cyan('AbuseIPDB:')}
  Base de datos colaborativa donde los administradores reportan IPs que han
  estado involucradas en escaneos, fuerza bruta o spam.

  {cyan('Shodan:')}
  Buscador de dispositivos conectados a Internet. Muestra qué puertos están 
  expuestos, banners de servicios e incluso vulnerabilidades conocidas (CVEs).
  
  {dim('Nota: Necesitas agregar tus API Keys en el código o en .cybertoolkitrc')}
    """)


# ──────────────────────────────────────────────
#  Submenú
# ──────────────────────────────────────────────
_SUBMENU = [
    ("1", "Analizar IP (VT, AbuseIPDB, Shodan)", _mode_analyze_ip),
    ("2", "¿Qué es Threat Intelligence?",        _mode_explain),
]

def _print_submenu() -> None:
    print()
    info("Opciones de Threat Intelligence")
    separator("─", 58)
    for key, label, _ in _SUBMENU:
        print(f"  {cyan(f'[{key}]')} {white(label)}")
    print(f"  {red('[0]')} {dim('Volver al menú principal')}")
    separator("─", 58)


# ──────────────────────────────────────────────
#  Punto de entrada
# ──────────────────────────────────────────────
def run() -> None:
    while True:
        section_title("HERRAMIENTA 34 — THREAT INTELLIGENCE")
        _print_submenu()

        choice = prompt("Opción", default="0")

        if choice == "0":
            break

        matched = False
        for key, _, func in _SUBMENU:
            if choice == key:
                matched = True
                try:
                    func()
                except KeyboardInterrupt:
                    print()
                    warn("Operación cancelada.")
                break

        if not matched:
            error("Opción no válida. Ingresá un número de la lista.")

        pause()


if __name__ == "__main__":
    run()
