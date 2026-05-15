"""
firewall_tester.py — Herramienta 26: Tester de Reglas de Firewall
Envía paquetes TCP con flags anómalos (NULL, FIN, XMAS) y Source Port Spoofing
para evaluar la efectividad de las reglas de filtrado de un firewall/IDS.
"""

import sys
import os
import time

# Asegura que el directorio raíz esté en el path al ejecutar directamente
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils import (
    ok, error, warn, info, result,
    section_title, separator, dim, cyan, green, yellow, white, red, magenta,
    prompt, pause, validate_ip, validate_hostname
)

try:
    from scapy.all import IP, TCP, ICMP, sr1, conf
    _HAS_SCAPY = True
except ImportError:
    _HAS_SCAPY = False


def _send_probe(ip: str, port: int, scan_type: str, flags: str = "S", sport: int = None) -> str:
    """Envía un paquete forjado y analiza la respuesta."""
    try:
        # Configurar puerto de origen si hay spoofing
        src_port = sport if sport else conf.color_theme.rand() # rand() no es de puerto pero scapy usa random port por defecto
        
        # Scapy RandShort() para puerto origen
        from scapy.all import RandShort
        src_port = sport if sport else RandShort()

        pkt = IP(dst=ip) / TCP(sport=src_port, dport=port, flags=flags)
        
        # Timeout corto (1.5s)
        resp = sr1(pkt, timeout=1.5, verbose=0)
        
        if resp is None:
            return "Filtrado (Timeout / Drop)"
        
        if resp.haslayer(TCP):
            if resp.getlayer(TCP).flags == 0x12: # SYN-ACK
                # Para evitar dejar la conexión a medio abrir (Half-Open), enviamos RST
                rst = IP(dst=ip) / TCP(sport=src_port, dport=port, flags="R")
                # sr1(rst, timeout=0.5, verbose=0) -> Enviamos asincrono para no trabar
                from scapy.all import send
                send(rst, verbose=0)
                return "Abierto"
            elif resp.getlayer(TCP).flags == 0x14: # RST-ACK
                return "Cerrado (RST)"
        elif resp.haslayer(ICMP):
            if int(resp.getlayer(ICMP).type) == 3:
                return "Filtrado (ICMP Unreachable)"
                
        return f"Respuesta desconocida: {resp.summary()}"
        
    except Exception as e:
        return f"Error de red: {e}"


def _run_tests(target: str, port: int) -> None:
    ip = target
    if not validate_ip(target):
        try:
            ip = socket.gethostbyname(target)
        except:
            error(f"No se pudo resolver el hostname: {target}")
            return

    info(f"Iniciando pruebas de evasión de firewall contra {cyan(ip)}:{cyan(str(port))}")
    if os.name == 'nt':
        warn("En Windows, el propio firewall o antivirus puede bloquear la inyección de paquetes Scapy.")
        
    separator("─", 65)
    
    tests = [
        {"name": "SYN Scan (Estándar)", "flags": "S", "sport": None},
        {"name": "NULL Scan", "flags": "", "sport": None},
        {"name": "FIN Scan", "flags": "F", "sport": None},
        {"name": "XMAS Scan", "flags": "FPU", "sport": None},
        {"name": "Source Port Spoofing (DNS 53)", "flags": "S", "sport": 53},
        {"name": "Source Port Spoofing (HTTP 80)", "flags": "S", "sport": 80},
    ]

    for t in tests:
        print(f"  {dim('Enviando Probe:')} {white(t['name']):<32} ", end="", flush=True)
        res = _send_probe(ip, port, t['name'], t['flags'], t['sport'])
        
        # Coloreado dinámico
        if "Abierto" in res:
            print(f"-> {green(res)}")
        elif "Cerrado" in res:
            print(f"-> {yellow(res)}")
        elif "Filtrado" in res:
            print(f"-> {red(res)}")
        else:
            print(f"-> {magenta(res)}")
            
        time.sleep(0.5) # Pausa entre escaneos para no saturar

    print()
    info("Pruebas finalizadas. Si todos los scans furtivos devuelven 'Abierto' o 'Timeout',")
    print("  el firewall podría estar mal configurado. Un buen firewall responde igual")
    print("  (ej. Drop) a todo el tráfico que no sea un inicio de conexión legítimo.")
    print()


def _mode_run() -> None:
    section_title("TESTER DE FIREWALL")
    
    if not _HAS_SCAPY:
        error("La librería 'scapy' no está instalada (pip install scapy).")
        return

    target = prompt("Dominio o IP objetivo (ej. 192.168.1.10)").strip().lower()
    if not target:
        return
        
    try:
        port = int(prompt("Puerto objetivo a evaluar", default="80").strip())
    except ValueError:
        error("El puerto debe ser un número entero.")
        return

    _run_tests(target, port)


def _mode_explain() -> None:
    section_title("¿CÓMO FUNCIONA LA EVASIÓN DE FIREWALLS?")

    print(f"""
  {white('1. Manipulación de Banderas TCP (TCP Flags)')}
  {dim('─' * 56)}
  Una conexión TCP normal empieza con un SYN. Los firewalls están diseñados
  para vigilar esto de cerca. ¿Qué pasa si enviamos un paquete con las 
  banderas FIN, PSH y URG activadas al mismo tiempo ({cyan('XMAS Scan')})?
  Un firewall antiguo (stateless) puede confundirse y dejarlo pasar, 
  mientras que un sistema moderno (stateful) lo descartará inmediatamente.

  {white('2. Source Port Spoofing')}
  {dim('─' * 56)}
  Algunos administradores configuran reglas perezosas: 
  {dim('"Permitir TODO el tráfico que provenga del puerto 53 (DNS)"')}
  El atacante simplemente configura su propio tráfico para que salga desde
  su puerto 53, y mágicamente atraviesa el firewall de la víctima.

  {white('3. Resultados Esperados')}
  {dim('─' * 56)}
  {dim('·')} {green('Abierto')}: El servicio responde positivamente.
  {dim('·')} {yellow('Cerrado')}: El host rechaza explícitamente la conexión (RST).
  {dim('·')} {red('Filtrado')}: El firewall devora el paquete (Drop/Timeout) o responde
    con un mensaje de red inalcanzable.
    """)


# ──────────────────────────────────────────────
#  Submenú
# ──────────────────────────────────────────────
_SUBMENU = [
    ("1", "Ejecutar Pruebas de Firewall",         _mode_run),
    ("2", "¿Qué es TCP Flags & Port Spoofing?",   _mode_explain),
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
        section_title("HERRAMIENTA 26 — FIREWALL TESTER")
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
