"""
log_analyzer.py — Herramienta 24: Analizador de Logs de Seguridad
Parseo y análisis de archivos de log (como access.log o auth.log) 
para identificar patrones de ataques (Brute force, Web Scans, Errores).
"""

import sys
import os
import re
from collections import defaultdict

# Asegura que el directorio raíz esté en el path al ejecutar directamente
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils import (
    ok, error, warn, info, result,
    section_title, separator, dim, cyan, green, yellow, white, red, magenta,
    prompt, pause
)


def _generate_sample_log() -> str:
    """Genera un archivo de log de prueba (access.log simulado) para practicar."""
    filename = "sample_access.log"
    content = """192.168.1.10 - - [10/Oct/2023:13:55:36 -0700] "GET /index.html HTTP/1.1" 200 2326
192.168.1.10 - - [10/Oct/2023:13:55:40 -0700] "GET /style.css HTTP/1.1" 200 512
10.0.0.5 - - [10/Oct/2023:14:02:11 -0700] "GET /admin/login.php HTTP/1.1" 401 128
10.0.0.5 - - [10/Oct/2023:14:02:15 -0700] "POST /admin/login.php HTTP/1.1" 401 128
10.0.0.5 - - [10/Oct/2023:14:02:18 -0700] "POST /admin/login.php HTTP/1.1" 401 128
10.0.0.5 - - [10/Oct/2023:14:02:22 -0700] "POST /admin/login.php HTTP/1.1" 401 128
10.0.0.5 - - [10/Oct/2023:14:02:25 -0700] "POST /admin/login.php HTTP/1.1" 200 1024
203.0.113.42 - - [10/Oct/2023:15:10:05 -0700] "GET /index.php?id=1' OR '1'='1 HTTP/1.1" 500 221
203.0.113.42 - - [10/Oct/2023:15:10:06 -0700] "GET /index.php?id=1 UNION SELECT 1,2,3 HTTP/1.1" 500 221
198.51.100.7 - - [10/Oct/2023:16:45:12 -0700] "GET /.git/config HTTP/1.1" 404 153
198.51.100.7 - - [10/Oct/2023:16:45:13 -0700] "GET /.env HTTP/1.1" 404 153
198.51.100.7 - - [10/Oct/2023:16:45:14 -0700] "GET /wp-config.php.bak HTTP/1.1" 404 153
"""
    try:
        with open(filename, "w", encoding="utf-8") as f:
            f.write(content)
        ok(f"Archivo de prueba creado: {filename}")
        return filename
    except Exception as e:
        error(f"Error creando log de prueba: {e}")
        return ""


def _analyze_log(filepath: str) -> None:
    if not os.path.exists(filepath):
        error("Archivo no encontrado.")
        return

    info(f"Analizando {white(os.path.basename(filepath))}...")

    # Estadísticas
    total_lines = 0
    ip_requests = defaultdict(int)
    status_codes = defaultdict(int)
    
    # Detecciones
    brute_force_ips = defaultdict(int)  # IPs con muchos 401
    sqli_detects = []
    enum_detects = defaultdict(int)     # IPs con muchos 404

    # Regex común para logs web (Apache/Nginx)
    # 192.168.1.10 - - [10/Oct/2023:13:55:36 -0700] "GET /index.html HTTP/1.1" 200 2326
    log_pattern = re.compile(
        r'^(?P<ip>[\d\.]+) \S+ \S+ \[(?P<date>[^\]]+)\] "(?P<request>[^"]+)" (?P<status>\d{3}) (?P<size>\d+|-)'
    )
    
    # Regex para firmas de ataque en la URL
    sqli_pattern = re.compile(r"(?i)(UNION.*SELECT|SELECT.*FROM|OR.*=|\%27|\')")
    sensitive_files = [".env", ".git", "wp-config", "passwd", "shadow"]

    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                total_lines += 1
                match = log_pattern.match(line)
                
                if match:
                    ip = match.group("ip")
                    status = match.group("status")
                    request = match.group("request")
                    
                    ip_requests[ip] += 1
                    status_codes[status] += 1
                    
                    # Análisis heurístico
                    
                    # 1. Fuerza Bruta (Muchos 401 Unauthorized o 403 Forbidden)
                    if status in ["401", "403"]:
                        brute_force_ips[ip] += 1
                        
                    # 2. Enumeración / Escaneo de vulnerabilidades (Muchos 404 Not Found)
                    if status == "404":
                        enum_detects[ip] += 1
                        
                    # 3. SQLi en la URL
                    if sqli_pattern.search(request):
                        sqli_detects.append((ip, request))
                        
                    # 4. Archivos sensibles
                    if any(s in request.lower() for s in sensitive_files):
                        sqli_detects.append((ip, f"Búsqueda de archivo sensible: {request}"))

    except Exception as e:
        error(f"Error procesando el archivo: {e}")
        return

    print()
    separator("═", 75)
    print(f"  {white('RESUMEN DE SEGURIDAD (LOG ANALYSIS)')}")
    separator("─", 75)
    
    result("Total de líneas analizadas", str(total_lines))
    
    if not ip_requests:
        warn("No se detectó el formato de Apache/Nginx (Access Log) en este archivo.")
        return

    print()
    print(f"  {white('1. Direcciones IP más activas (Top 3):')}")
    for ip, count in sorted(ip_requests.items(), key=lambda x: x[1], reverse=True)[:3]:
        print(f"  {cyan(ip):<20} {count} peticiones")

    print()
    print(f"  {white('2. Distribución de Códigos HTTP:')}")
    for status, count in sorted(status_codes.items(), key=lambda x: x[1], reverse=True)[:5]:
        color = green if status.startswith("2") else yellow if status.startswith("3") else red if status.startswith("5") else magenta
        print(f"  {color(status):<20} {count} veces")

    print()
    separator("-", 75)
    print(f"  {red('⚠ ALERTAS DE SEGURIDAD DETECTADAS')}")
    separator("-", 75)
    
    alerts_found = False

    # Alerta Fuerza Bruta
    for ip, count in brute_force_ips.items():
        if count >= 3: # Umbral bajo para demostración
            print(f"  {red('[!] Posible Fuerza Bruta:')} {cyan(ip)} generó {count} errores de autenticación (401/403).")
            alerts_found = True

    # Alerta Enumeración / Escaneo
    for ip, count in enum_detects.items():
        if count >= 3:
            print(f"  {yellow('[!] Posible Escaneo Web:')} {cyan(ip)} generó {count} errores de no encontrado (404).")
            alerts_found = True

    # Alerta Inyección / Archivos Sensibles
    if sqli_detects:
        print(f"  {magenta('[!] Posibles Inyecciones o Búsqueda Sensible:')}")
        # Mostrar max 5
        for ip, req in sqli_detects[:5]:
            print(f"      IP: {cyan(ip)} -> {dim(req[:60])}")
        if len(sqli_detects) > 5:
            print(f"      ... y {len(sqli_detects) - 5} más.")
        alerts_found = True

    if not alerts_found:
        print(f"  {green('✓ No se detectaron patrones anómalos o ataques evidentes.')}")
        
    separator("─", 75)
    print()


def _mode_run() -> None:
    section_title("ANALIZADOR DE LOGS")
    
    info("Soporta formato combinado Apache / Nginx (access.log)")
    
    filepath = prompt("Ruta del archivo .log (Enter para generar uno de prueba)", default="")
    
    if not filepath:
        filepath = _generate_sample_log()
        if not filepath:
            return
            
    _analyze_log(filepath)


def _mode_explain() -> None:
    section_title("¿CÓMO ANALIZAR LOGS PARA DETECTAR ATAQUES?")

    print(f"""
  {white('1. Logs de Accesos Web (access.log)')}
  {dim('─' * 56)}
  Los servidores web como Apache y Nginx guardan un registro de CADA
  petición que reciben. Este registro incluye la IP, la fecha, la URL 
  solicitada y el código de respuesta HTTP.

  {white('2. Detección por Códigos de Estado (HTTP Status)')}
  {dim('─' * 56)}
  {dim('·')} {green('200 OK')}: Todo salió bien.
  {dim('·')} {red('401 Unauthorized')}: Contraseña incorrecta. Si una IP tiene muchos 
    de estos en poco tiempo, está haciendo {red('Fuerza Bruta')}.
  {dim('·')} {yellow('404 Not Found')}: Archivo no existe. Si una IP pide cientos de 
    archivos que no existen (/.env, /admin.php, /backup.zip), está 
    usando un {yellow('Escáner de Vulnerabilidades')} (Dirb, Gobuster).

  {white('3. Detección por Firmas en la URL')}
  {dim('─' * 56)}
  Los ataques de SQL Injection o XSS suelen dejar un rastro evidente 
  en la URL, especialmente en peticiones GET.
  Ej: {cyan('/search.php?q=1 UNION SELECT username, password FROM users')}

  {white('4. Correlación de Eventos (SIEM)')}
  {dim('─' * 56)}
  En redes grandes, en lugar de analizar archivos a mano con scripts, 
  se envían todos los logs a un SIEM (Splunk, Elastic, Wazuh), que 
  hace esta correlación automáticamente en tiempo real.
    """)


# ──────────────────────────────────────────────
#  Submenú
# ──────────────────────────────────────────────
_SUBMENU = [
    ("1", "Analizar Archivo de Log",              _mode_run),
    ("2", "¿Cómo detectar ataques en Logs?",      _mode_explain),
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
        section_title("HERRAMIENTA 24 — ANALIZADOR DE LOGS")
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
