"""
banner_grabber.py — Herramienta 12: Grabber de banners de servicios
Conecta a puertos abiertos para extraer la identificación del servicio (SSH, HTTP, FTP, etc.)
y realiza una correlación básica de versiones con posibles vulnerabilidades.
"""

import socket
import sys
import os
import time

# Asegura que el directorio raíz esté en el path al ejecutar directamente
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils import (
    ok, error, warn, info, result,
    section_title, separator, dim, cyan, green, yellow, white, red,
    prompt, ask_yes_no, pause, validate_ip
)
from config import get_service, SOCKET_TIMEOUT

try:
    import requests
    _HAS_REQUESTS = True
except ImportError:
    _HAS_REQUESTS = False


# Base de datos simplificada de CVEs conocidos por versión
# (Solo para fines educativos, no es exhaustiva)
CVE_DATABASE = {
    "OpenSSH 7.2p2": [("CVE-2016-6210", "User enumeration vulnerabity")],
    "OpenSSH 4.7p1": [("CVE-2008-1483", "X11 Hijacking")],
    "ProFTPD 1.3.5": [("CVE-2015-3306", "ProFTPD 1.3.5 mod_copy Command Execution")],
    "vsftpd 2.3.4":  [("CVE-2011-2523", "vsftpd 2.3.4 Backdoor Command Execution")],
    "Apache/2.4.49":[("CVE-2021-41773", "Path Traversal / RCE en Apache HTTP Server")],
    "Apache/2.4.50":[("CVE-2021-42013", "Path Traversal / RCE en Apache HTTP Server")],
    "nginx/1.20.0": [("CVE-2021-23017", "Off-by-one en dns resolver")],
}

def _correlate_cves(banner: str) -> list[tuple[str, str]]:
    """Busca substrings del banner en la base de datos local de CVEs."""
    vulns = []
    for soft_ver, cves in CVE_DATABASE.items():
        if soft_ver.lower() in banner.lower():
            vulns.extend(cves)
    return vulns


def _grab_raw_banner(ip: str, port: int, timeout: float = 2.0) -> str | None:
    """Intenta conectar por socket y leer el banner inicial."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))
        
        # Enviar sondas comunes para forzar una respuesta en protocolos que esperan al cliente
        if port in (80, 443, 8080, 8443):
            sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
        else:
            # Enviar una secuencia vacía o un Enter suele provocar que el server responda
            sock.sendall(b"\r\n")
            
        banner_raw = sock.recv(1024)
        sock.close()
        
        if banner_raw:
            return banner_raw.decode("utf-8", errors="replace").strip()
    except (socket.timeout, OSError, ConnectionRefusedError):
        pass
    return None


def _grab_http_headers(ip: str, port: int) -> dict[str, str]:
    """Usa requests para extraer el Server header y otros interesantes."""
    if not _HAS_REQUESTS:
        return {}
    
    headers_found = {}
    scheme = "https" if port in (443, 8443) else "http"
    url = f"{scheme}://{ip}:{port}/"
    
    try:
        resp = requests.head(url, timeout=3.0, verify=False, allow_redirects=True)
        headers = {k.lower(): v for k, v in resp.headers.items()}
        
        if "server" in headers:
            headers_found["Server"] = headers["server"]
        if "x-powered-by" in headers:
            headers_found["X-Powered-By"] = headers["x-powered-by"]
            
    except requests.RequestException:
        pass
        
    return headers_found


def _mode_grab() -> None:
    section_title("GRABBER DE BANNERS")

    host_raw = prompt("IP o hostname objetivo").strip()
    if not host_raw:
        warn("No se ingresó objetivo.")
        return

    # Intentar resolver
    try:
        ip = socket.gethostbyname(host_raw)
    except socket.gaierror:
        error(f"No se pudo resolver '{host_raw}'")
        return

    raw_ports = prompt("Puertos (ej. 21,22,80,443)", default="21,22,25,80,110,443,3306,8080")
    try:
        ports = [int(p.strip()) for p in raw_ports.split(",")]
    except ValueError:
        error("Formato de puertos inválido.")
        return

    print()
    info(f"Escaneando {white(ip)} buscando banners...")
    separator("─", 70)
    print(f"  {'Puerto':<10} {'Servicio':<12} {'Banner / Identificación'}")
    separator("─", 70)

    found_any = False

    for port in ports:
        service = get_service(port)
        banner = None
        
        # Estrategia HTTP primero para puertos web
        if port in (80, 443, 8080, 8443) and _HAS_REQUESTS:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            headers = _grab_http_headers(ip, port)
            if headers:
                banner = " | ".join(f"{k}: {v}" for k, v in headers.items())
        
        # Fallback a raw socket
        if not banner:
            raw_banner = _grab_raw_banner(ip, port)
            if raw_banner:
                # Limpiar saltos de línea para mostrar
                banner = raw_banner.replace("\r", "").replace("\n", " ")[:60]
                
        if banner:
            found_any = True
            print(f"  {cyan(str(port)):<10} {white(service):<12} {green(banner)}")
            
            # Correlación de CVEs
            vulns = _correlate_cves(banner)
            for cve, desc in vulns:
                print(f"  {'':<23} {red('↳ ⚠')} {yellow(cve)}: {dim(desc)}")
        else:
            print(f"  {dim(str(port)):<10} {dim(service):<12} {dim('Sin respuesta o cerrado')}")

    separator("─", 70)
    
    if not found_any:
        warn("No se pudo obtener el banner de ninguno de los puertos.")
    print()


def _mode_explain() -> None:
    section_title("¿QUÉ ES EL BANNER GRABBING Y FINGERPRINTING?")

    print(f"""
  {white('1. Banner Grabbing (Extracción de Banner)')}
  {dim('─' * 56)}
  Es el proceso de enviar solicitudes a un puerto abierto para descubrir 
  información sobre el servicio que se está ejecutando. 
  Muchos servicios envían un mensaje de bienvenida o "banner" al conectarse.
  Ejemplo (SSH): {cyan('SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.1')}

  {white('2. Fingerprinting (Huella Digital)')}
  {dim('─' * 56)}
  Una vez obtenido el banner, se usa para hacer un "fingerprint" o huella 
  del servicio y sistema operativo. Esto permite identificar la versión exacta.

  {white('3. Correlación con CVEs')}
  {dim('─' * 56)}
  CVE (Common Vulnerabilities and Exposures) es una lista de vulnerabilidades 
  públicamente conocidas. Si sabemos que el servidor corre {yellow('Apache 2.4.49')}, 
  podemos buscar en la base de datos y saber que es vulnerable a un ataque de 
  Path Traversal ({red('CVE-2021-41773')}).

  {white('4. Cabeceras HTTP (Info Leaks)')}
  {dim('─' * 56)}
  En servidores web, el banner a menudo viene en las cabeceras HTTP:
  {dim('·')} {green('Server:')} nginx/1.18.0
  {dim('·')} {green('X-Powered-By:')} PHP/7.4.3
  
  Estas cabeceras deben {yellow('ocultarse')} en producción para evitar dar 
  pistas a los atacantes.
    """)


# ──────────────────────────────────────────────
#  Submenú
# ──────────────────────────────────────────────
_SUBMENU = [
    ("1", "Ejecutar grabber de banners",          _mode_grab),
    ("2", "¿Qué es el fingerprinting?",           _mode_explain),
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
        section_title("HERRAMIENTA 12 — GRABBER DE BANNERS")
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
