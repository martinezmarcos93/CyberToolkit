"""
dns_analyzer.py — Herramienta 21: Analizador Avanzado de DNS
Sniffer de red para detectar anomalías en consultas DNS (DNS Tunneling,
exfiltración de datos, dominios sospechosos/DGA).
"""

import sys
import os
import re
import math
from collections import defaultdict

# Asegura que el directorio raíz esté en el path al ejecutar directamente
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils import (
    ok, error, warn, info, result,
    section_title, separator, dim, cyan, green, yellow, white, red, magenta,
    prompt, pause
)

try:
    from scapy.all import sniff, DNSQR, UDP, conf
    _HAS_SCAPY = True
except ImportError:
    _HAS_SCAPY = False


# Mantenemos un recuento de consultas por dominio base para detectar Tunneling
_domain_counter = defaultdict(int)

def _shannon_entropy(data: str) -> float:
    """Calcula la entropía de Shannon de un string para detectar aleatoriedad (DGA)."""
    if not data:
        return 0
    entropy = 0
    for x in set(data):
        p_x = float(data.count(x)) / len(data)
        entropy += - p_x * math.log2(p_x)
    return entropy

def _process_dns_packet(pkt) -> None:
    """Callback para procesar paquetes DNS capturados."""
    if pkt.haslayer(DNSQR):
        # qname viene como bytes, ej: b'www.google.com.'
        qname_bytes = pkt[DNSQR].qname
        if not qname_bytes:
            return
            
        try:
            qname = qname_bytes.decode('utf-8').rstrip('.')
        except Exception:
            return

        # Análisis de Anomalías
        is_alert = False
        alerts = []

        # 1. Longitud extrema del subdominio (Posible Tunneling/Exfiltración)
        # DNS permite hasta 253 caracteres en total y 63 por etiqueta.
        # Si la parte del subdominio es muy larga, es sospechoso.
        parts = qname.split('.')
        base_domain = ".".join(parts[-2:]) if len(parts) >= 2 else qname
        subdomain = ".".join(parts[:-2]) if len(parts) > 2 else ""

        if len(subdomain) > 50:
            is_alert = True
            alerts.append(red("Tunneling (Subdominio gigante)"))
            
        # 2. Entropía alta (Posible DGA - Domain Generation Algorithm)
        # Subdominios generados al azar tipo: "xkjqweu91283ncv.malware.com"
        if len(subdomain) > 10 and _shannon_entropy(subdomain) > 3.8:
            is_alert = True
            alerts.append(yellow("Entropía Alta (Posible DGA)"))

        # 3. Frecuencia de consultas al mismo dominio base
        _domain_counter[base_domain] += 1
        if _domain_counter[base_domain] > 100:
            is_alert = True
            alerts.append(magenta("Frecuencia excesiva (Exfiltración)"))
            # Reset para no floodear la pantalla eternamente
            _domain_counter[base_domain] = 0

        # Output
        if is_alert:
            ip_src = pkt[IP].src if pkt.haslayer("IP") else "Desconocido"
            print(f"\r  {dim('Alerta DNS |')} {white(ip_src):<15} {dim('->')} {cyan(qname)}")
            print(f"               {dim('└─ ')} {' '.join(alerts)}")
            print(f"  {dim('-' * 60)}")
        else:
            # Mostrar tráfico normal atenuado
            # Limitar a 50 caracteres para no romper la pantalla
            display_qname = qname[:50] + "..." if len(qname) > 50 else qname
            print(f"\r  {dim(f'[DNS] {display_qname}')}" + " " * 20, end="", flush=True)


def _mode_monitor() -> None:
    section_title("MONITOR DE ANOMALÍAS DNS")

    if not _HAS_SCAPY:
        error("La librería 'scapy' no está instalada (pip install scapy).")
        return

    # Advertencia para Windows
    if os.name == 'nt':
        info("En Windows, Scapy requiere Npcap o WinPcap instalado para capturar tráfico.")
        print()

    iface = prompt("Interfaz a escuchar (Dejar vacío para TODAS)", default="").strip()
    
    _domain_counter.clear()
    
    print()
    info(f"Iniciando sniffer DNS en puerto 53... (Presioná {yellow('Ctrl+C')} para detener)")
    separator("─", 60)
    
    try:
        # Filtramos por UDP puerto 53
        filter_str = "udp port 53"
        if iface:
            sniff(iface=iface, filter=filter_str, prn=_process_dns_packet, store=False)
        else:
            sniff(filter=filter_str, prn=_process_dns_packet, store=False)
    except KeyboardInterrupt:
        print("\r" + " "*60 + "\r", end="")
        warn("Monitor detenido por el usuario.")
    except Exception as e:
        error(f"Error al iniciar captura: {e}")


def _mode_explain() -> None:
    section_title("¿CÓMO FUNCIONAN LOS ATAQUES POR DNS?")

    print(f"""
  {white('1. ¿Qué es DNS?')}
  {dim('─' * 56)}
  DNS convierte nombres de dominio (google.com) en direcciones IP.
  Como es vital para el funcionamiento de Internet, los firewalls casi 
  siempre permiten el tráfico DNS (Puerto 53) hacia el exterior sin 
  inspeccionarlo profundamente.

  {white('2. DNS Tunneling (Exfiltración de Datos)')}
  {dim('─' * 56)}
  Los atacantes abusan de esta regla del firewall. Si logran infectar una
  máquina, pueden "sacar" (exfiltrar) archivos robados enviándolos como si 
  fueran consultas de subdominios hacia un servidor que ellos controlan:
  Ej: {cyan('M1wzS2V5UGFzc3dvcmRzLnhsc3g.hacker.com')}
  El atacante recibe la consulta DNS, lee el subdominio y recupera los datos.

  {white('3. DGA (Algoritmo de Generación de Dominios)')}
  {dim('─' * 56)}
  El malware suele usar DGA para evadir bloqueos. En lugar de conectarse
  siempre a "c2.malware.com" (que un antivirus bloquearía rápido), genera
  miles de dominios aleatorios al día (Ej: {cyan('a9x2b1.com')}).
  El atacante solo necesita registrar uno de esos miles para tomar control.

  {white('4. ¿Qué detecta esta herramienta?')}
  {dim('─' * 56)}
  {dim('·')} Subdominios extremadamente largos (típico de Tunneling).
  {dim('·')} Alta entropía / aleatoriedad en el nombre (típico de DGA).
  {dim('·')} Demasiadas consultas al mismo dominio en poco tiempo.
    """)


# ──────────────────────────────────────────────
#  Submenú
# ──────────────────────────────────────────────
_SUBMENU = [
    ("1", "Iniciar Monitor de Anomalías DNS",     _mode_monitor),
    ("2", "¿Qué es DNS Tunneling y DGA?",         _mode_explain),
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
        section_title("HERRAMIENTA 21 — ANALIZADOR DNS")
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
