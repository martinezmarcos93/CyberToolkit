"""
arp_monitor.py — Herramienta 20: Detector de ARP Spoofing
Monitorea pasivamente la red en busca de paquetes ARP para 
detectar inconsistencias de IP -> MAC (Ataques MITM).
"""

import sys
import os
import time

# Asegura que el directorio raíz esté en el path al ejecutar directamente
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils import (
    ok, error, warn, info, result,
    section_title, separator, dim, cyan, green, yellow, white, red,
    prompt, pause
)

try:
    from scapy.all import sniff, ARP, conf
    _HAS_SCAPY = True
except ImportError:
    _HAS_SCAPY = False


# Base de datos en memoria para mapear IP -> MAC
_arp_table = {}


def _process_arp_packet(pkt) -> None:
    """Procesa cada paquete ARP capturado."""
    if ARP in pkt and pkt[ARP].op in (1, 2):  # 1: who-has (request), 2: is-at (reply)
        ip = pkt[ARP].psrc
        mac = pkt[ARP].hwsrc

        # Ignorar si es IP de origen 0.0.0.0 (ARP Probe / DHCP DORA)
        if ip == "0.0.0.0":
            return

        if ip in _arp_table:
            # Si la IP ya fue vista, comprobamos si la MAC cambió
            if _arp_table[ip] != mac:
                old_mac = _arp_table[ip]
                print(f"\r  {red('⚠ ALERTA DE ARP SPOOFING / MITM DETECTADO')} " + " "*20)
                print(f"  {white('IP:')} {cyan(ip)}")
                print(f"  {white('MAC Anterior:')} {yellow(old_mac)}")
                print(f"  {white('MAC Nueva:')}    {red(mac)}  <-- ¡Posible Atacante!")
                print(f"  {dim(time.strftime('%Y-%m-%d %H:%M:%S'))}")
                separator("─", 60)
                
                # Actualizar la tabla a la nueva MAC para evitar flood de la misma alerta
                _arp_table[ip] = mac
        else:
            # Nueva entrada
            _arp_table[ip] = mac
            print(f"\r  {dim('Nuevo Host:')} {cyan(ip):<15} -> {green(mac)}")


def _mode_monitor() -> None:
    section_title("MONITOR DE ARP SPOOFING")
    
    if not _HAS_SCAPY:
        error("La librería 'scapy' no está instalada (pip install scapy).")
        return

    # Advertencia para Windows
    if os.name == 'nt':
        info("En Windows, Scapy requiere Npcap o WinPcap instalado para capturar tráfico.")
        print(dim("Si la captura falla silenciosamente, instalá Npcap desde nmap.org/npcap/"))
        print()

    # Interfaz
    iface = prompt("Interfaz a escuchar (Dejar vacío para TODAS)", default="").strip()
    
    _arp_table.clear()
    
    print()
    info(f"Iniciando sniffer ARP pasivo... (Presioná {yellow('Ctrl+C')} para detener)")
    separator("─", 60)
    
    try:
        if iface:
            sniff(iface=iface, filter="arp", prn=_process_arp_packet, store=False)
        else:
            sniff(filter="arp", prn=_process_arp_packet, store=False)
    except KeyboardInterrupt:
        print("\r" + " "*40 + "\r", end="")
        warn("Monitor detenido por el usuario.")
    except Exception as e:
        error(f"Error al iniciar captura: {e}")
        
    print()
    result("Hosts únicos detectados", str(len(_arp_table)))
    print()


def _mode_explain() -> None:
    section_title("¿CÓMO FUNCIONA EL ARP SPOOFING?")

    print(f"""
  {white('1. ¿Qué es ARP?')}
  {dim('─' * 56)}
  El protocolo Address Resolution Protocol (ARP) traduce direcciones IP 
  a direcciones físicas MAC en la red local.

  {white('2. El problema (Confianza Ciega)')}
  {dim('─' * 56)}
  ARP fue diseñado sin seguridad. Cuando una computadora recibe un 
  mensaje ARP Reply ("Yo soy la IP 192.168.1.1 y mi MAC es AA:BB:CC"), 
  {red('lo cree ciegamente')}, incluso si no lo había preguntado.

  {white('3. El Ataque (Spoofing / Poisoning)')}
  {dim('─' * 56)}
  El atacante envía mensajes ARP falsos a la Víctima diciéndole: 
  "Yo soy el Router". Luego le envía mensajes al Router diciéndole: 
  "Yo soy la Víctima". 
  
  Consecuencia: Todo el tráfico pasa por el Atacante antes de ir a 
  Internet ({yellow('Ataque Man-In-The-Middle')}).

  {white('4. ¿Cómo lo detectamos?')}
  {dim('─' * 56)}
  Esta herramienta escucha todo el tráfico ARP. Si vemos que una IP 
  (ej. la del router) de repente cambia su dirección MAC por otra, es 
  casi seguro que estamos bajo un ataque de envenenamiento ARP.
    """)


# ──────────────────────────────────────────────
#  Submenú
# ──────────────────────────────────────────────
_SUBMENU = [
    ("1", "Iniciar Monitor ARP",                  _mode_monitor),
    ("2", "¿Qué es el ARP Spoofing (MITM)?",      _mode_explain),
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
        section_title("HERRAMIENTA 20 — DETECTOR DE ARP SPOOFING")
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
