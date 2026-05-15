"""
pcap_analyzer.py — Herramienta 19: Analizador de capturas PCAP/PCAPNG
Parseo de archivos .pcap para extraer estadísticas, reconstruir flujos
básicos y buscar tráfico en texto plano (HTTP/Credenciales).
"""

import sys
import os
from collections import Counter

# Asegura que el directorio raíz esté en el path al ejecutar directamente
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils import (
    ok, error, warn, info, result,
    section_title, separator, dim, cyan, green, yellow, white, red,
    prompt, pause
)

try:
    from scapy.all import rdpcap, PcapReader, IP, TCP, UDP, Raw
    _HAS_SCAPY = True
except ImportError:
    _HAS_SCAPY = False


def _analyze_pcap(filepath: str) -> None:
    if not os.path.exists(filepath):
        error("Archivo PCAP no encontrado.")
        return

    info(f"Analizando {white(os.path.basename(filepath))} (esto puede demorar en archivos grandes)...")
    
    total_packets = 0
    ip_counter = Counter()
    port_counter = Counter()
    
    plaintext_creds = []
    
    try:
        # Usamos PcapReader en lugar de rdpcap para no cargar todo en RAM de golpe
        with PcapReader(filepath) as pcap_reader:
            for pkt in pcap_reader:
                total_packets += 1
                
                # Estadísticas IP
                if IP in pkt:
                    ip_src = pkt[IP].src
                    ip_dst = pkt[IP].dst
                    ip_counter[ip_src] += 1
                    ip_counter[ip_dst] += 1
                    
                    # Estadísticas Puertos TCP/UDP
                    if TCP in pkt:
                        port_counter[pkt[TCP].sport] += 1
                        port_counter[pkt[TCP].dport] += 1
                        
                        # Buscar credenciales en texto plano (HTTP, FTP, Telnet)
                        if Raw in pkt:
                            payload = pkt[Raw].load
                            try:
                                text = payload.decode('utf-8', errors='ignore')
                                # Buscar palabras clave comunes en HTTP POST o FTP
                                lower_text = text.lower()
                                if "user=" in lower_text or "password=" in lower_text or "pass=" in lower_text:
                                    if "HTTP" in text:
                                        # Extraer línea
                                        lines = text.split('\n')
                                        for line in lines:
                                            if "user" in line.lower() or "pass" in line.lower():
                                                plaintext_creds.append((ip_src, ip_dst, "HTTP", line.strip()[:80]))
                                elif text.startswith("USER ") or text.startswith("PASS "):
                                    plaintext_creds.append((ip_src, ip_dst, "FTP/Telnet", text.strip()[:80]))
                            except Exception:
                                pass
                                
                    elif UDP in pkt:
                        port_counter[pkt[UDP].sport] += 1
                        port_counter[pkt[UDP].dport] += 1
    except Exception as e:
        error(f"Error procesando el archivo pcap: {e}")
        return

    print()
    separator("═", 75)
    print(f"  {white('RESULTADOS DEL ANÁLISIS PCAP')}")
    separator("─", 75)
    result("Total de paquetes", str(total_packets))
    
    # IPs más activas
    print()
    print(f"  {white('Top 5 IPs con más tráfico:')}")
    for ip, count in ip_counter.most_common(5):
        print(f"  {cyan(ip):<20} {count} paquetes")
        
    # Puertos más activos
    print()
    print(f"  {white('Top 5 Puertos más activos:')}")
    for port, count in port_counter.most_common(5):
        # Mapeo rápido de puertos conocidos
        service = "HTTP" if port == 80 else "HTTPS" if port == 443 else "DNS" if port == 53 else "SSH" if port == 22 else "Otro"
        print(f"  {cyan(str(port)):<10} {dim(service):<10} {count} paquetes")
        
    # Credenciales en texto plano
    print()
    if plaintext_creds:
        print(f"  {red('⚠ ALERTA: Se detectaron posibles credenciales en texto plano')}")
        separator("-", 75)
        for src, dst, proto, data in plaintext_creds[:10]: # Mostrar máx 10
            print(f"  {dim(f'{src} -> {dst}')} [{yellow(proto)}]: {red(data)}")
        if len(plaintext_creds) > 10:
            print(f"  {dim('... y ' + str(len(plaintext_creds) - 10) + ' más.')}")
    else:
        print(f"  {green('✓ No se detectaron credenciales en texto plano explícitas (User/Pass).')}")
        
    separator("─", 75)
    print()


def _mode_analyze() -> None:
    section_title("ANALIZADOR DE CAPTURAS PCAP")
    
    if not _HAS_SCAPY:
        error("La librería 'scapy' no está instalada (pip install scapy).")
        return

    filepath = prompt("Ruta del archivo .pcap o .pcapng")
    _analyze_pcap(filepath)


def _mode_explain() -> None:
    section_title("¿QUÉ ES EL ANÁLISIS PCAP?")

    print(f"""
  {white('1. Formato PCAP (Packet Capture)')}
  {dim('─' * 56)}
  Es el estándar para almacenar tráfico de red interceptado. Herramientas 
  como Wireshark, tcpdump y TShark guardan en este formato. 

  {white('2. Análisis Forense de Red')}
  {dim('─' * 56)}
  Durante un incidente, el "Network Forensics" consiste en analizar el .pcap 
  buscando:
  {dim('·')} {yellow('Flujos TCP/UDP')} anómalos (exfiltración).
  {dim('·')} Conexiones a {red('IPs maliciosas')} (C2, malware).
  {dim('·')} {red('Credenciales')} viajando en protocolos inseguros (HTTP, FTP, Telnet).

  {white('3. Detección de Plaintext')}
  {dim('─' * 56)}
  Si un usuario inicia sesión en una web sin HTTPS (solo HTTP), su usuario
  y contraseña viajan legibles ("plaintext") dentro del payload del paquete TCP.
  Cualquiera que esté "sniffando" la red (ARP Spoofing, WiFi abierta) puede 
  leer esa información directamente del archivo PCAP.
    """)


# ──────────────────────────────────────────────
#  Submenú
# ──────────────────────────────────────────────
_SUBMENU = [
    ("1", "Analizar archivo PCAP",                _mode_analyze),
    ("2", "¿Qué es el Forense de Red (PCAP)?",    _mode_explain),
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
        section_title("HERRAMIENTA 19 — ANALIZADOR PCAP")
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
