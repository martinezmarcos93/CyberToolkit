"""
ids_lite.py — Herramienta 22: Sistema de Detección de Intrusiones (IDS) Ligero
Sniffer de red que compara el payload de los paquetes contra un conjunto
de reglas en formato JSON para detectar tráfico malicioso.
"""

import sys
import os
import json
import re
import time
from collections import defaultdict

# Asegura que el directorio raíz esté en el path al ejecutar directamente
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils import (
    ok, error, warn, info, result,
    section_title, separator, dim, cyan, green, yellow, white, red, magenta,
    prompt, pause
)

try:
    from scapy.all import sniff, IP, TCP, UDP, Raw
    _HAS_SCAPY = True
except ImportError:
    _HAS_SCAPY = False


_RULES_FILE = os.path.join(os.path.dirname(__file__), "ids_rules.json")
_rules = []
_alerts_log = []

# Evitar flood de alertas para la misma IP
_last_alert_time = defaultdict(float)
_ALERT_COOLDOWN = 5.0  # Segundos


def _load_rules() -> bool:
    global _rules
    if not os.path.exists(_RULES_FILE):
        error(f"Archivo de reglas no encontrado: {_RULES_FILE}")
        return False
        
    try:
        with open(_RULES_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            _rules = data.get("rules", [])
            info(f"Cargadas {cyan(str(len(_rules)))} reglas del motor IDS.")
            return True
    except Exception as e:
        error(f"Error al leer ids_rules.json: {e}")
        return False


def _evaluate_packet(pkt) -> None:
    """Evalúa un paquete contra todas las reglas cargadas."""
    if not pkt.haslayer(IP) or not pkt.haslayer(Raw):
        return

    ip_src = pkt[IP].src
    ip_dst = pkt[IP].dst
    
    # Decodificamos el payload ignorando errores
    try:
        payload = pkt[Raw].load.decode('utf-8', errors='ignore')
    except Exception:
        return

    # Comprobación de reglas
    for rule in _rules:
        matched = False
        
        # Filtro por protocolo
        if rule["protocol"] == "TCP" and not pkt.haslayer(TCP):
            continue
        if rule["protocol"] == "UDP" and not pkt.haslayer(UDP):
            continue
            
        condition = rule.get("condition")
        value = rule.get("value", "")
        
        if condition == "payload_contains":
            if value.lower() in payload.lower():
                matched = True
        elif condition == "payload_regex":
            try:
                if re.search(value, payload):
                    matched = True
            except re.error:
                pass # Ignorar regex malformados
                
        if matched:
            _trigger_alert(rule, ip_src, ip_dst)
            break # Evitamos múltiples alertas para el mismo paquete


def _trigger_alert(rule: dict, ip_src: str, ip_dst: str) -> None:
    # Cooldown para no spamear la consola
    alert_key = f"{ip_src}_{rule['id']}"
    current_time = time.time()
    
    if current_time - _last_alert_time[alert_key] < _ALERT_COOLDOWN:
        return
        
    _last_alert_time[alert_key] = current_time
    
    sev = rule.get("severity", "LOW").upper()
    sev_color = red if sev == "CRITICAL" else magenta if sev == "HIGH" else yellow if sev == "MEDIUM" else cyan
    
    alert_msg = f"{sev_color(f'[{sev}]')} {white(rule['name'])}"
    print(f"\r  {alert_msg}" + " "*20)
    print(f"  {dim('Origen:')} {cyan(ip_src):<15} {dim('Destino:')} {cyan(ip_dst)}")
    print(f"  {dim('Detalle:')} {rule['description']}")
    print(f"  {dim('-' * 60)}")
    
    _alerts_log.append({
        "time": time.strftime("%Y-%m-%d %H:%M:%S"),
        "rule_id": rule["id"],
        "name": rule["name"],
        "severity": sev,
        "src": ip_src,
        "dst": ip_dst
    })


def _mode_monitor() -> None:
    section_title("SISTEMA DE DETECCIÓN DE INTRUSIONES (IDS)")
    
    if not _HAS_SCAPY:
        error("La librería 'scapy' no está instalada (pip install scapy).")
        return

    if not _load_rules():
        return

    # Advertencia para Windows
    if os.name == 'nt':
        print(dim("  Nota: En Windows, Scapy requiere Npcap o WinPcap instalado."))
        print()

    iface = prompt("Interfaz a escuchar (Dejar vacío para TODAS)", default="").strip()
    
    _alerts_log.clear()
    _last_alert_time.clear()
    
    print()
    info(f"Iniciando IDS en modo detección... (Presioná {yellow('Ctrl+C')} para detener)")
    separator("─", 60)
    
    try:
        # Filtramos solo TCP y UDP ya que nuestras reglas buscan payloads
        filter_str = "tcp or udp"
        if iface:
            sniff(iface=iface, filter=filter_str, prn=_evaluate_packet, store=False)
        else:
            sniff(filter=filter_str, prn=_evaluate_packet, store=False)
    except KeyboardInterrupt:
        print("\r" + " "*60 + "\r", end="")
        warn("Monitor detenido por el usuario.")
    except Exception as e:
        error(f"Error al iniciar captura: {e}")
        
    print()
    result("Alertas generadas", str(len(_alerts_log)))
    print()


def _mode_explain() -> None:
    section_title("¿CÓMO FUNCIONA UN IDS?")

    print(f"""
  {white('1. IDS vs IPS')}
  {dim('─' * 56)}
  Un IDS (Intrusion Detection System) actúa como un alarma de seguridad: 
  "escucha" el tráfico de red, busca firmas conocidas de ataques y te {cyan('avisa')}.
  Un IPS (Intrusion Prevention System) da un paso más: si detecta el 
  ataque, lo {red('bloquea')} activamente tirando la conexión.

  {white('2. Motores basados en Firmas (Signatures)')}
  {dim('─' * 56)}
  Herramientas como Snort o Suricata usan reglas. Por ejemplo:
  Si un paquete va al puerto 80 y contiene el texto "UNION SELECT",
  genera una alerta de SQL Injection. Esta herramienta incluye un motor 
  ligero usando un archivo JSON.

  {white('3. Evasión de IDS')}
  {dim('─' * 56)}
  Los atacantes evaden los IDS alterando el payload para que no coincida 
  con la firma. Por ejemplo, en lugar de enviar "UNION SELECT", envían 
  "UNiOn/**/sElEcT" o codifican el payload en Base64 o URL Encode.

  {white('4. El problema de TLS/HTTPS')}
  {dim('─' * 56)}
  El IDS de red no puede leer dentro de los paquetes HTTPS porque están 
  cifrados. Para que funcione en una red real, se necesita hacer "SSL Inspection" 
  (actuando como un proxy MITM legítimo) o instalar el IDS en el servidor 
  (HIDS) donde el tráfico ya fue descifrado.
    """)


# ──────────────────────────────────────────────
#  Submenú
# ──────────────────────────────────────────────
_SUBMENU = [
    ("1", "Iniciar Monitor IDS",                  _mode_monitor),
    ("2", "¿Qué es un IDS/IPS?",                  _mode_explain),
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
        section_title("HERRAMIENTA 22 — IDS LIGERO")
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
