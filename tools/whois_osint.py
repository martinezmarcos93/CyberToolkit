"""
whois_osint.py — Herramienta 13: OSINT sobre dominios e IPs
Consultas WHOIS, geolocalización de IPs, ASN lookup y tecnologías web básicas.
"""

import socket
import sys
import os
import json

# Asegura que el directorio raíz esté en el path al ejecutar directamente
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils import (
    ok, error, warn, info, result,
    section_title, separator, dim, cyan, green, yellow, white, red, magenta,
    prompt, pause, validate_ip
)

try:
    import requests
    _HAS_REQUESTS = True
except ImportError:
    _HAS_REQUESTS = False


def _get_ip_info(ip: str) -> dict:
    """Obtiene geolocalización y ASN usando ip-api.com (gratuito, sin API key)."""
    if not _HAS_REQUESTS:
        return {}
    try:
        resp = requests.get(f"http://ip-api.com/json/{ip}?fields=status,country,city,isp,org,as,query", timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            if data.get("status") == "success":
                return data
    except Exception:
        pass
    return {}


def _get_rdap_info(domain: str) -> dict:
    """Obtiene información WHOIS (básica) usando RDAP."""
    if not _HAS_REQUESTS:
        return {}
    try:
        resp = requests.get(f"https://rdap.org/domain/{domain}", timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            
            entities = data.get("entities", [])
            registrar = "Desconocido"
            for ent in entities:
                if "registrar" in ent.get("roles", []):
                    if ent.get("vcardArray"):
                        for item in ent["vcardArray"][1]:
                            if item[0] == "fn":
                                registrar = item[3]
            
            events = data.get("events", [])
            creation = "Desconocido"
            expiration = "Desconocido"
            for ev in events:
                if ev.get("eventAction") == "registration":
                    creation = ev.get("eventDate", "Desconocido")
                elif ev.get("eventAction") == "expiration":
                    expiration = ev.get("eventDate", "Desconocido")
                    
            return {
                "registrar": registrar,
                "creation": creation,
                "expiration": expiration
            }
    except Exception:
        pass
    return {}


def _detect_web_tech(url: str) -> list[str]:
    """Análisis muy básico de cabeceras HTTP para adivinar tecnologías (estilo Wappalyzer)."""
    if not _HAS_REQUESTS:
        return []
    
    techs = set()
    try:
        resp = requests.get(url, timeout=5, verify=False)
        headers = {k.lower(): v for k, v in resp.headers.items()}
        text = resp.text.lower()
        
        # Cabeceras
        server = headers.get("server", "").lower()
        if "nginx" in server: techs.add("Nginx")
        elif "apache" in server: techs.add("Apache HTTP Server")
        elif "cloudflare" in server: techs.add("Cloudflare CDN")
        elif "litespeed" in server: techs.add("LiteSpeed")
        
        powered_by = headers.get("x-powered-by", "").lower()
        if "php" in powered_by: techs.add("PHP")
        elif "express" in powered_by: techs.add("Express.js (Node)")
        elif "asp.net" in powered_by: techs.add("ASP.NET")
        
        # HTML básico
        if "wp-content" in text: techs.add("WordPress")
        if "react" in text and "data-reactroot" in text: techs.add("React")
        if "next/router" in text or "__next_data__" in text: techs.add("Next.js")
        if "vue" in text: techs.add("Vue.js")
        
    except Exception:
        pass
    
    return list(techs)


def _mode_osint() -> None:
    section_title("OSINT: RECONOCIMIENTO PASIVO")

    if not _HAS_REQUESTS:
        error("El módulo 'requests' no está instalado. Instálalo con: pip install requests")
        return

    target = prompt("IP o Dominio a investigar").strip().lower()
    if not target:
        warn("No se ingresó objetivo.")
        return

    is_ip = validate_ip(target)
    ip = target if is_ip else None
    domain = target if not is_ip else None

    # Si es dominio, resolver a IP
    if domain:
        try:
            ip = socket.gethostbyname(domain)
        except socket.gaierror:
            warn(f"No se pudo resolver el dominio '{domain}'.")
    
    print()
    separator("═", 60)
    print(f"  {white('RESULTADOS DEL ANÁLISIS OSINT')}")
    separator("─", 60)

    # 1. Información del Dominio (WHOIS/RDAP)
    if domain:
        info("Consultando registros de dominio (RDAP)...")
        rdap = _get_rdap_info(domain)
        if rdap:
            result("Registrador", yellow(rdap.get("registrar", "Desconocido")))
            result("Creación",    dim(rdap.get("creation", "Desconocido")))
            result("Expiración",  dim(rdap.get("expiration", "Desconocido")))
        else:
            result("WHOIS", dim("Información no disponible o falló la consulta"))
        separator("─", 60)

    # 2. Geolocalización y ASN
    if ip:
        info(f"Consultando información de red para la IP {cyan(ip)}...")
        ip_data = _get_ip_info(ip)
        if ip_data:
            loc = f"{ip_data.get('city')}, {ip_data.get('country')}"
            isp = ip_data.get('isp')
            org = ip_data.get('org')
            asn = ip_data.get('as')
            
            result("Ubicación", loc)
            result("ISP",       isp)
            result("Org",       org)
            result("ASN",       dim(asn))
        else:
            result("Red", dim("Información no disponible (IP privada o sin red)"))
        separator("─", 60)

    # 3. Tecnologías Web
    info("Buscando tecnologías web activas...")
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    urls_to_try = []
    if domain:
        urls_to_try = [f"https://{domain}", f"http://{domain}"]
    elif ip:
        urls_to_try = [f"http://{ip}"]
        
    techs = []
    for url in urls_to_try:
        techs = _detect_web_tech(url)
        if techs:
            break
            
    if techs:
        result("Tecnologías", green(", ".join(techs)))
    else:
        result("Tecnologías", dim("No se pudo detectar (o no es un servidor web)"))
        
    separator("─", 60)
    print()


def _mode_explain() -> None:
    section_title("¿QUÉ ES OSINT?")

    print(f"""
  {white('OSINT (Open-Source Intelligence)')}
  {dim('─' * 56)}
  Es la recolección y análisis de información recopilada de fuentes públicas y
  abiertas para ser utilizada en un contexto de inteligencia.
  En ciberseguridad, es la fase 1 (Reconocimiento) de cualquier ataque o auditoría.

  {cyan('WHOIS / RDAP:')}
  Revela a quién pertenece un dominio, dónde se registró y cuándo expira.
  Útil para encontrar dominios a punto de caducar o contactos de la organización.

  {cyan('Geolocalización IP y ASN:')}
  Identifica en qué país y bajo qué proveedor de internet (ISP) o nube 
  está alojado el servidor (AWS, Cloudflare, un ISP residencial, etc.).

  {cyan('Detección de tecnologías web:')}
  Identificar que un sitio usa WordPress 5.2 o PHP 7.0 le permite al atacante
  buscar vulnerabilidades (CVEs) específicas para ese software.
    """)


# ──────────────────────────────────────────────
#  Submenú
# ──────────────────────────────────────────────
_SUBMENU = [
    ("1", "Investigar IP o Dominio",              _mode_osint),
    ("2", "¿Qué es OSINT?",                       _mode_explain),
]

def _print_submenu() -> None:
    print()
    info("¿Qué querés hacer?")
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
        section_title("HERRAMIENTA 13 — OSINT Y RECONOCIMIENTO")
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
            error("Opción no válida. Ingresá un número del 0 al 2.")

        pause()


if __name__ == "__main__":
    run()
