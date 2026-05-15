"""
c2_detector.py — Herramienta 35: Detector de comunicaciones C2
Análisis de tráfico de red para identificar patrones de Command & Control (beaconing).
"""

import sys
import os
import time
from collections import defaultdict

# Asegura que el directorio raíz esté en el path al ejecutar directamente
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils import (
    ok, error, warn, info, result,
    section_title, separator, dim, cyan, green, yellow, white, red, magenta,
    prompt, pause, export_results
)
from config import SETTINGS

try:
    from scapy.all import sniff, IP, TCP, UDP, DNS
    _HAS_SCAPY = True
except ImportError:
    _HAS_SCAPY = False

# ──────────────────────────────────────────────
#  Lógica de Detección
# ──────────────────────────────────────────────
class C2Detector:
    def __init__(self):
        self.connections = defaultdict(list)
        self.alerts = []
        self.start_time = time.time()
        
    def process_packet(self, pkt):
        if IP in pkt:
            src = pkt[IP].src
            dst = pkt[IP].dst
            proto = "OTHER"
            sport = dport = 0
            
            if TCP in pkt:
                proto = "TCP"
                sport = pkt[TCP].sport
                dport = pkt[TCP].dport
            elif UDP in pkt:
                proto = "UDP"
                sport = pkt[UDP].sport
                dport = pkt[UDP].dport
                
            # Identificador único de conexión (unidireccional o bidireccional)
            conn_id = f"{src}:{sport} -> {dst}:{dport} [{proto}]"
            self.connections[conn_id].append(time.time())
            
            # Simple beaconing check: si hay más de 5 paquetes con intervalos muy regulares
            timestamps = self.connections[conn_id]
            if len(timestamps) > 5:
                intervals = [timestamps[i] - timestamps[i-1] for i in range(1, len(timestamps))]
                avg_interval = sum(intervals) / len(intervals)
                variance = sum((x - avg_interval) ** 2 for x in intervals) / len(intervals)
                
                # Si la varianza es muy pequeña, es beaconing
                if variance < 0.05 and avg_interval > 1.0:
                    alert_msg = f"Posible Beaconing C2 detectado: {conn_id} (Intervalo: {avg_interval:.2f}s)"
                    if alert_msg not in self.alerts:
                        self.alerts.append(alert_msg)
                        warn(alert_msg)

# ──────────────────────────────────────────────
#  Modos
# ──────────────────────────────────────────────
def _mode_sniff() -> None:
    section_title("DETECTOR C2: MONITOREO DE RED")
    
    if not _HAS_SCAPY:
        error("El módulo 'scapy' no está instalado. Instálalo con: pip install scapy")
        return
        
    # Validar permisos root en Linux/macOS
    if os.name != 'nt' and os.geteuid() != 0:
        error("El sniffing requiere privilegios de root (ejecutar con sudo).")
        return

    limit = prompt("Cantidad de paquetes a capturar (ej. 100)", default="100")
    try:
        limit = int(limit)
    except ValueError:
        limit = 100
        
    info(f"Iniciando captura de {limit} paquetes... (Presioná Ctrl+C para detener)")
    detector = C2Detector()
    
    try:
        sniff(prn=detector.process_packet, store=False, count=limit)
    except Exception as e:
        error(f"Error al capturar tráfico: {e}")
        return
        
    print()
    separator("─", 60)
    info("Análisis completado.")
    
    if detector.alerts:
        result("Alertas C2", red(f"{len(detector.alerts)} detectadas"))
        for a in detector.alerts:
            print(f"  {dim('›')} {yellow(a)}")
    else:
        result("Alertas C2", green("No se detectaron patrones anómalos."))
        
    export = prompt("¿Deseas exportar estos resultados? [s/N]", default="n").lower()
    if export in ("s", "si", "y", "yes"):
        export_results("c2_detector", {"alerts": detector.alerts, "total_packets": limit})

def _mode_explain() -> None:
    section_title("¿QUÉ ES UN C2 (COMMAND & CONTROL)?")

    print(f"""
  {white('Command & Control (C2 o C&C)')}
  {dim('─' * 56)}
  Es la infraestructura que los atacantes usan para comunicarse con sistemas 
  comprometidos dentro de una red objetivo.

  {cyan('Beaconing:')}
  Es el comportamiento donde el malware "llama a casa" periódicamente 
  (ej. cada 5 minutos) para pedir instrucciones. Crea un patrón rítmico 
  en el tráfico de red.

  {cyan('Túneles (DNS/ICMP):')}
  Para evadir firewalls, el malware puede esconder sus comandos dentro de 
  consultas DNS aparentemente normales o pings ICMP.
  
  {dim('Nota: Esta herramienta requiere privilegios de root/administrador')}
    """)

# ──────────────────────────────────────────────
#  Submenú
# ──────────────────────────────────────────────
_SUBMENU = [
    ("1", "Iniciar monitoreo de tráfico C2",     _mode_sniff),
    ("2", "¿Qué es un C2 (Command & Control)?", _mode_explain),
]

def _print_submenu() -> None:
    print()
    info("Opciones de Detección C2")
    separator("─", 58)
    for key, label, _ in _SUBMENU:
        print(f"  {cyan(f'[{key}]')} {white(label)}")
    print(f"  {red('[0]')} {dim('Volver al menú principal')}")
    separator("─", 58)

def run() -> None:
    while True:
        section_title("HERRAMIENTA 35 — DETECTOR C2")
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
