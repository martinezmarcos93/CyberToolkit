"""
vuln_scanner.py — Herramienta 25: Escáner de Vulnerabilidades Básico
Combina descubrimiento de puertos, banner grabbing y verificación de configuraciones
inseguras conocidas en base a una pequeña base de firmas locales.
"""

import sys
import os
import socket
import concurrent.futures

# Asegura que el directorio raíz esté en el path al ejecutar directamente
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils import (
    ok, error, warn, info, result,
    section_title, separator, dim, cyan, green, yellow, white, red, magenta,
    prompt, pause, validate_ip, validate_hostname
)


# Base de datos simplificada de firmas de vulnerabilidades
_VULN_DB = [
    # FTP
    {"port": 21, "banner": "vsFTPd 2.3.4", "cve": "CVE-2011-2523", "desc": "Backdoor de ejecución de código (RCE)."},
    {"port": 21, "banner": "ProFTPD 1.3.5", "cve": "CVE-2015-3306", "desc": "Ejecución de código a través de mod_copy."},
    
    # SSH
    {"port": 22, "banner": "OpenSSH_4.7", "cve": "Multiple", "desc": "Versión muy antigua, altamente vulnerable."},
    {"port": 22, "banner": "OpenSSH_7.2p2", "cve": "CVE-2016-6210", "desc": "Enumeración de usuarios posible."},
    
    # Web
    {"port": 80, "banner": "Apache/2.2.8", "cve": "Multiple", "desc": "Versión deprecada, posibles RCE y DoS."},
    {"port": 80, "banner": "IIS/6.0", "cve": "CVE-2017-7269", "desc": "RCE en servicio WebDAV (Exploited by NSA/ShadowBrokers)."},
    {"port": 80, "banner": "Apache/2.4.49", "cve": "CVE-2021-41773", "desc": "Path Traversal & RCE crítico."},
    
    # Misconfigs Comunes (Sin banner específico, solo el puerto abierto es un riesgo si está expuesto a internet)
    {"port": 23, "banner": "", "cve": "Misconfig", "desc": "Servicio Telnet detectado. El tráfico (incluyendo contraseñas) viaja en texto plano."},
    {"port": 6379, "banner": "", "cve": "Misconfig", "desc": "Servicio Redis expuesto. Frecuentemente sin autenticación, permite toma de control."},
    {"port": 27017, "banner": "", "cve": "Misconfig", "desc": "Servicio MongoDB expuesto. Riesgo crítico si no tiene autenticación habilitada."},
    {"port": 3389, "banner": "", "cve": "Riesgo", "desc": "Escritorio Remoto (RDP) expuesto al exterior. Blanco frecuente de ransomware y fuerza bruta."},
    {"port": 445, "banner": "", "cve": "Riesgo / CVE-2017-0144", "desc": "Servicio SMB expuesto. Peligro de EternalBlue (WannaCry) si no está parcheado."},
]

_COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3306, 3389, 5432, 6379, 8080, 27017]


def _grab_banner(ip: str, port: int) -> str:
    """Intenta conectar y leer el banner inicial del servicio."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(2.0)
            s.connect((ip, port))
            
            # Para HTTP enviamos algo para que responda el banner
            if port in [80, 8080, 443]:
                s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
            
            banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
            
            # Limpiar un poco el banner HTTP para extraer solo el Server
            if "HTTP" in banner and "Server:" in banner:
                for line in banner.split("\n"):
                    if line.lower().startswith("server:"):
                        return line.split(":", 1)[1].strip()
            return banner[:50] # Recortar a 50 chars
    except Exception:
        return ""


def _scan_target(target: str) -> None:
    ip = target
    if not validate_ip(target):
        try:
            ip = socket.gethostbyname(target)
            info(f"Resolución DNS: {cyan(target)} -> {cyan(ip)}")
        except socket.gaierror:
            error(f"No se pudo resolver el hostname: {target}")
            return

    info(f"Iniciando escaneo de vulnerabilidades en {cyan(ip)}...")
    separator("─", 60)
    
    open_ports = []
    
    # 1. Escaneo de Puertos Básico (Concurrent)
    def check_port(p):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1.0)
                if s.connect_ex((ip, p)) == 0:
                    return p
        except:
            pass
        return None

    print(f"  {dim('Fase 1: Escaneo de puertos comunes y críticos...')}")
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        results = executor.map(check_port, _COMMON_PORTS)
        for r in results:
            if r is not None:
                open_ports.append(r)
                
    if not open_ports:
        warn("No se encontraron puertos abiertos en la lista común.")
        return
        
    print(f"  {green('✓')} Se encontraron {len(open_ports)} puertos abiertos.")
    
    # 2. Banner Grabbing & Vulnerability Matching
    print()
    print(f"  {dim('Fase 2: Banner grabbing y correlación de firmas...')}")
    separator("-", 60)
    
    findings = []
    
    for port in open_ports:
        banner = _grab_banner(ip, port)
        
        # Guardar como hallazgo normal
        print(f"  {white(f'Puerto {port}:')} Abierto | Banner: {dim(banner if banner else 'N/A')}")
        
        # Buscar en la DB
        for vuln in _VULN_DB:
            if vuln["port"] == port:
                # Si requiere coincidencia de banner
                if vuln["banner"]:
                    if vuln["banner"].lower() in banner.lower():
                        findings.append((port, vuln))
                # Si es una misconfig general por solo estar el puerto abierto
                else:
                    findings.append((port, vuln))
                    
    # 3. Reporte de Vulnerabilidades
    if findings:
        print()
        separator("═", 75)
        print(f"  {red('⚠ ALERTAS DE VULNERABILIDAD / MISCONFIGURACIONES')}")
        separator("─", 75)
        for p, vuln in findings:
            cve_color = red if "CVE" in vuln["cve"] else yellow
            print(f"  {white('Puerto:')}     {cyan(str(p))}")
            print(f"  {white('Hallazgo:')}   {cve_color(vuln['cve'])}")
            print(f"  {white('Impacto:')}    {vuln['desc']}")
            print(f"  {dim('-'*60)}")
    else:
        print()
        print(f"  {green('✓ No se detectaron vulnerabilidades conocidas en la base local.')}")
        
    print()


def _mode_run() -> None:
    section_title("ESCÁNER DE VULNERABILIDADES")
    target = prompt("Dominio o IP objetivo (ej. 192.168.1.10)").strip().lower()
    if not target:
        warn("No se ingresó objetivo.")
        return
        
    _scan_target(target)


def _mode_explain() -> None:
    section_title("¿CÓMO FUNCIONAN LOS ESCÁNERES DE VULNERABILIDADES?")

    print(f"""
  {white('1. Escáneres de Red (Nessus, OpenVAS, Nexpose)')}
  {dim('─' * 56)}
  Estas herramientas automatizan la búsqueda de fallos. El proceso típico es:
  A) Descubrimiento de red (¿Host vivo?).
  B) Escaneo de puertos (¿Qué servicios corren?).
  C) Interrogación del servicio (Banner Grabbing y OS Fingerprinting).
  D) Correlación con CVEs (Common Vulnerabilities and Exposures).

  {white('2. Falsos Positivos y Falsos Negativos')}
  {dim('─' * 56)}
  {dim('·')} {yellow('Falso Positivo:')} El escáner detecta que el banner dice "Apache 2.2.8" y
    alerta de vulnerabilidades. Pero en realidad, el administrador de 
    sistemas parcheó el código fuente (Backporting) sin cambiar el número 
    de versión. El sistema está seguro, pero el escáner se engañó.
  {dim('·')} {red('Falso Negativo:')} Hay una vulnerabilidad real (ej. una contraseña por
    defecto en una web app), pero como el escáner no tiene la "firma" de
    esa app específica, la pasa por alto.

  {white('3. Misconfigurations (Malas configuraciones)')}
  {dim('─' * 56)}
  Muchas veces el peligro no es una vulnerabilidad de software (un CVE),
  sino un error humano. Por ejemplo: dejar una base de datos MongoDB (27017)
  expuesta a todo Internet sin requerir contraseña. Esta herramienta busca
  ese tipo de riesgos comunes.
    """)


# ──────────────────────────────────────────────
#  Submenú
# ──────────────────────────────────────────────
_SUBMENU = [
    ("1", "Ejecutar Escáner en un Host",          _mode_run),
    ("2", "¿Cómo funcionan los escáneres?",       _mode_explain),
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
        section_title("HERRAMIENTA 25 — VULN SCANNER")
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
