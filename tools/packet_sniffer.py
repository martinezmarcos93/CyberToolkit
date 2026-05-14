"""
packet_sniffer.py — Herramienta 6: Sniffer básico de paquetes
Captura y analiza paquetes de red en tiempo real.

Conceptos didácticos:
  · Promiscuous mode: captura todo el tráfico de la red, no solo el propio
  · Pila TCP/IP: capas Ethernet → IP → TCP/UDP → Aplicación
  · Socket raw: acceso de bajo nivel a la red, requiere privilegios root
  · Payload: datos de la capa de aplicación (puede contener texto plano)
  · Filtros BPF: Berkeley Packet Filter — sintaxis para filtrar capturas
"""

import os
import sys
import socket
import struct
import time
import threading
from collections import Counter, defaultdict
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils import (
    ok, error, warn, info, result,
    section_title, separator, dim, cyan, green, yellow, white, red, magenta,
    prompt, ask_yes_no, pause, format_size,
)
from config import SNIFFER_PKT_LIMIT, get_service

# ── Dependencia: scapy ──────────────────────
try:
    from scapy.all import (
        sniff, IP, TCP, UDP, ICMP, DNS, DNSQR, DNSRR,
        ARP, Ether, Raw, get_if_list, conf
    )
    from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
    _HAS_SCAPY = True
except ImportError:
    _HAS_SCAPY = False


# ──────────────────────────────────────────────
#  Constantes
# ──────────────────────────────────────────────
PROTO_NAMES = {
    1:  "ICMP",
    6:  "TCP",
    17: "UDP",
    41: "IPv6",
    89: "OSPF",
}

# Puertos que pueden revelar credenciales en texto plano
CLEARTEXT_PORTS = {21, 23, 25, 80, 110, 143, 8080, 8888}

# Palabras clave que sugieren credenciales en el payload
CREDENTIAL_KEYWORDS = [
    b"password", b"passwd", b"pass=", b"pwd=",
    b"login", b"user=", b"username=", b"Authorization:",
    b"Bearer ", b"Basic ", b"credential",
]

MAX_PAYLOAD_DISPLAY = 200  # chars máximos del payload a mostrar


# ──────────────────────────────────────────────
#  Verificación de privilegios
# ──────────────────────────────────────────────
def _check_privileges() -> bool:
    """Verifica si el proceso tiene privilegios de root/admin."""
    try:
        return os.geteuid() == 0
    except AttributeError:
        # Windows
        import ctypes
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False


# ──────────────────────────────────────────────
#  Clasificación de paquetes
# ──────────────────────────────────────────────
def _classify_packet(pkt) -> dict | None:
    """
    Analiza un paquete scapy y extrae los campos relevantes.
    Devuelve un dict con la info, o None si no es IP.
    """
    if not pkt.haslayer(IP):
        return None

    ip_layer = pkt[IP]
    proto_num = ip_layer.proto
    proto = PROTO_NAMES.get(proto_num, f"Proto-{proto_num}")

    data = {
        "timestamp": datetime.now().strftime("%H:%M:%S.%f")[:-3],
        "src_ip":    ip_layer.src,
        "dst_ip":    ip_layer.dst,
        "proto":     proto,
        "src_port":  None,
        "dst_port":  None,
        "flags":     "",
        "size":      len(pkt),
        "payload":   b"",
        "has_creds": False,
        "service":   "",
    }

    # TCP
    if pkt.haslayer(TCP):
        tcp = pkt[TCP]
        data["src_port"] = tcp.sport
        data["dst_port"] = tcp.dport
        data["service"]  = get_service(tcp.dport) or get_service(tcp.sport)

        # Flags TCP
        flags = []
        if tcp.flags.S: flags.append("SYN")
        if tcp.flags.A: flags.append("ACK")
        if tcp.flags.F: flags.append("FIN")
        if tcp.flags.R: flags.append("RST")
        if tcp.flags.P: flags.append("PSH")
        data["flags"] = "|".join(flags) if flags else ""

        # Payload
        if pkt.haslayer(Raw):
            data["payload"] = bytes(pkt[Raw])

    # UDP
    elif pkt.haslayer(UDP):
        udp = pkt[UDP]
        data["src_port"] = udp.sport
        data["dst_port"] = udp.dport
        data["service"]  = get_service(udp.dport) or get_service(udp.sport)
        if pkt.haslayer(Raw):
            data["payload"] = bytes(pkt[Raw])

    # ICMP
    elif pkt.haslayer(ICMP):
        icmp = pkt[ICMP]
        icmp_types = {0: "Echo-Reply", 3: "Unreachable", 8: "Echo-Request", 11: "TTL-Exceeded"}
        data["flags"] = icmp_types.get(icmp.type, f"type={icmp.type}")

    # Detección de credenciales en texto plano
    payload = data["payload"]
    if payload:
        pl_lower = payload.lower()
        for kw in CREDENTIAL_KEYWORDS:
            if kw.lower() in pl_lower:
                data["has_creds"] = True
                break

    return data


# ──────────────────────────────────────────────
#  Formato de línea de paquete
# ──────────────────────────────────────────────
def _format_packet_line(pkt_data: dict, verbose: bool = False) -> str:
    """Formatea un paquete como línea de salida en terminal."""
    ts      = dim(pkt_data["timestamp"])
    proto   = pkt_data["proto"]
    src_ip  = pkt_data["src_ip"]
    dst_ip  = pkt_data["dst_ip"]
    sport   = pkt_data["src_port"]
    dport   = pkt_data["dst_port"]
    flags   = pkt_data["flags"]
    size    = pkt_data["size"]
    service = pkt_data["service"]

    # Color según protocolo
    proto_colored = {
        "TCP":  cyan(f"{proto:<5}"),
        "UDP":  green(f"{proto:<5}"),
        "ICMP": yellow(f"{proto:<5}"),
    }.get(proto, white(f"{proto:<5}"))

    # Endpoint format
    src = f"{src_ip}:{sport}" if sport else src_ip
    dst = f"{dst_ip}:{dport}" if dport else dst_ip

    # Servicio detectado
    svc_str = f" {dim(f'[{service}]')}" if service else ""

    # Flags TCP
    flags_str = f" {dim(flags)}" if flags else ""

    # Tamaño
    size_str = dim(f"{size}B")

    # Credenciales detectadas
    cred_str = f" {red('⚠ CREDS')}" if pkt_data["has_creds"] else ""

    line = f"  {ts} {proto_colored} {white(src):<25} → {white(dst):<25} {size_str:<6}{svc_str}{flags_str}{cred_str}"

    if verbose and pkt_data["payload"]:
        # Intentar decodificar payload como texto
        try:
            text = pkt_data["payload"][:MAX_PAYLOAD_DISPLAY].decode("utf-8", errors="replace")
            text = text.replace("\n", "↵").replace("\r", "").replace("\t", "→")
            payload_line = f"\n       {dim('payload:')} {yellow(text[:120])}"
            line += payload_line
        except Exception:
            pass

    return line


# ──────────────────────────────────────────────
#  Estadísticas de sesión
# ──────────────────────────────────────────────
class SnifferStats:
    """Acumula estadísticas durante la captura."""

    def __init__(self):
        self.total         = 0
        self.by_proto      = Counter()
        self.by_dst_port   = Counter()
        self.by_src_ip     = Counter()
        self.bytes_total   = 0
        self.cred_alerts   = []
        self._lock         = threading.Lock()

    def record(self, pkt_data: dict) -> None:
        with self._lock:
            self.total += 1
            self.bytes_total += pkt_data["size"]
            self.by_proto[pkt_data["proto"]] += 1
            if pkt_data["dst_port"]:
                self.by_dst_port[pkt_data["dst_port"]] += 1
            self.by_src_ip[pkt_data["src_ip"]] += 1
            if pkt_data["has_creds"]:
                self.cred_alerts.append(pkt_data)

    def print_summary(self) -> None:
        """Muestra el resumen estadístico de la sesión."""
        print()
        separator("═", 60)
        print(f"  {white('RESUMEN DE CAPTURA')}")
        separator("─", 60)
        result("Paquetes capturados", str(self.total))
        result("Tráfico total",       format_size(self.bytes_total))
        result("Alertas de creds",    str(len(self.cred_alerts)))

        if self.by_proto:
            print()
            print(f"  {white('Por protocolo:')}")
            for proto, count in self.by_proto.most_common():
                bar = "█" * min(count, 30)
                pct = count / self.total * 100
                print(f"    {dim(proto):<8} {cyan(bar):<32} {dim(f'{count} ({pct:.0f}%)')}")

        if self.by_dst_port:
            print()
            print(f"  {white('Top puertos destino:')}")
            for port, count in self.by_dst_port.most_common(5):
                svc = get_service(port) or "?"
                print(f"    {cyan(str(port)):<8} {dim(svc):<14} {dim(f'{count} paquetes')}")

        if self.by_src_ip:
            print()
            print(f"  {white('Top IPs origen:')}")
            for ip, count in self.by_src_ip.most_common(5):
                print(f"    {white(ip):<18} {dim(f'{count} paquetes')}")

        if self.cred_alerts:
            print()
            print(f"  {red('⚠  ALERTAS DE CREDENCIALES EN TEXTO PLANO:')}")
            separator("─", 60)
            for a in self.cred_alerts[:5]:
                sport = f":{a['src_port']}" if a['src_port'] else ""
                dport = f":{a['dst_port']}" if a['dst_port'] else ""
                print(f"  {red('►')} {a['src_ip']}{sport} → {a['dst_ip']}{dport} [{a['proto']}]")
            if len(self.cred_alerts) > 5:
                print(f"  {dim(f'... y {len(self.cred_alerts) - 5} alertas más')}")

        separator("═", 60)


# ──────────────────────────────────────────────
#  Modo 1: Captura en vivo
# ──────────────────────────────────────────────
def _mode_live_capture() -> None:
    section_title("CAPTURA DE PAQUETES EN VIVO")

    if not _HAS_SCAPY:
        error("Scapy no instalado. Ejecutá: pip install scapy")
        return

    if not _check_privileges():
        print()
        print(f"  {red('⛔ SE REQUIEREN PRIVILEGIOS DE ROOT / ADMINISTRADOR')}")
        separator("─", 60)
        info("El sniffing de paquetes necesita acceso a raw sockets.")
        print()
        print(f"  {cyan('Para ejecutar con privilegios:')}")
        print(f"    {white('sudo python3 main.py')}")
        print(f"    {dim('# o, en Linux:')}")
        print(f"    {white('sudo python3 -m tools.packet_sniffer')}")
        print()
        warn("Sin root, la captura fallará o solo verás tu propio tráfico.")

        if not ask_yes_no("¿Intentar igualmente?", default=False):
            return

    # Seleccionar interfaz
    print()
    try:
        interfaces = get_if_list()
        info("Interfaces de red disponibles:")
        separator("─", 50)
        for i, iface in enumerate(interfaces, 1):
            marker = cyan(f"[{i}]")
            print(f"  {marker} {white(iface)}")
        separator("─", 50)

        default_iface = conf.iface if hasattr(conf, 'iface') else interfaces[0] if interfaces else "eth0"
        iface = prompt("Interfaz", default=str(default_iface))
        if not iface:
            iface = str(default_iface)
    except Exception:
        iface = prompt("Interfaz de red", default="eth0")

    # Filtro BPF
    print()
    info("Ejemplos de filtros BPF:")
    print(f"  {dim('tcp port 80')}          → solo HTTP")
    print(f"  {dim('udp port 53')}          → solo DNS")
    print(f"  {dim('host 192.168.1.1')}     → solo esa IP")
    print(f"  {dim('not port 22')}          → excluir SSH")
    print(f"  {dim('(dejar vacío)')}        → capturar todo")
    bpf_filter = prompt("Filtro BPF", default="")

    # Límite de paquetes
    raw_limit = prompt(f"Máximo de paquetes a capturar", default=str(SNIFFER_PKT_LIMIT))
    try:
        pkt_limit = max(1, min(int(raw_limit), 500))
    except ValueError:
        pkt_limit = SNIFFER_PKT_LIMIT

    # Modo verbose
    verbose = ask_yes_no("¿Mostrar payload de texto plano?", default=False)

    # Iniciar captura
    print()
    separator("═", 60)
    print(f"  {green('▶ CAPTURA INICIADA')}")
    print(f"  {dim('Interfaz:')} {white(iface)}")
    if bpf_filter:
        print(f"  {dim('Filtro:')}    {white(bpf_filter)}")
    print(f"  {dim('Límite:')}    {white(str(pkt_limit))} paquetes")
    print(f"  {dim('Ctrl+C para detener antes del límite')}")
    separator("═", 60)
    print()

    stats = SnifferStats()
    captured = []

    def process_packet(pkt):
        pkt_data = _classify_packet(pkt)
        if pkt_data is None:
            return
        stats.record(pkt_data)
        captured.append(pkt_data)
        print(_format_packet_line(pkt_data, verbose=verbose))

    try:
        sniff(
            iface=iface,
            filter=bpf_filter if bpf_filter else None,
            prn=process_packet,
            count=pkt_limit,
            store=False,
        )
    except PermissionError:
        print()
        error("Permiso denegado. Necesitás ejecutar como root.")
        return
    except KeyboardInterrupt:
        pass
    except Exception as e:
        print()
        error(f"Error durante la captura: {e}")
        info("Asegurate de que la interfaz existe y tenés permisos.")
        return

    # Resumen final
    stats.print_summary()


# ──────────────────────────────────────────────
#  Modo 2: Captura rápida (sin configuración)
# ──────────────────────────────────────────────
def _mode_quick_capture() -> None:
    section_title("CAPTURA RÁPIDA")

    if not _HAS_SCAPY:
        error("Scapy no instalado. Ejecutá: pip install scapy")
        return

    if not _check_privileges():
        warn("Se requieren privilegios de root para capturar paquetes.")
        if not ask_yes_no("¿Intentar igualmente?", default=False):
            return

    print()
    info(f"Capturando {SNIFFER_PKT_LIMIT} paquetes en la interfaz por defecto...")
    info("Presioná Ctrl+C para detener antes.")
    print()

    stats = SnifferStats()

    def process_packet(pkt):
        pkt_data = _classify_packet(pkt)
        if pkt_data is None:
            return
        stats.record(pkt_data)
        count = stats.total
        print(_format_packet_line(pkt_data))
        # Indicador de progreso inline
        print(f"  {dim(f'[{count}/{SNIFFER_PKT_LIMIT}]')}", end="\r")

    try:
        sniff(prn=process_packet, count=SNIFFER_PKT_LIMIT, store=False)
    except (PermissionError, OSError):
        print()
        error("Permiso denegado. Necesitás ejecutar como root.")
        return
    except KeyboardInterrupt:
        pass
    except Exception as e:
        print()
        error(f"Error: {e}")
        return

    print()
    stats.print_summary()


# ──────────────────────────────────────────────
#  Modo 3: Monitor DNS
# ──────────────────────────────────────────────
def _mode_dns_monitor() -> None:
    section_title("MONITOR DE CONSULTAS DNS")

    if not _HAS_SCAPY:
        error("Scapy no instalado. Ejecutá: pip install scapy")
        return

    if not _check_privileges():
        warn("Se requieren privilegios de root.")
        if not ask_yes_no("¿Intentar igualmente?", default=False):
            return

    raw_limit = prompt("Máximo de consultas DNS a capturar", default="30")
    try:
        limit = max(1, min(int(raw_limit), 200))
    except ValueError:
        limit = 30

    print()
    separator("═", 60)
    print(f"  {green('▶ MONITOR DNS — Puerto 53 UDP/TCP')}")
    print(f"  {dim('Cada consulta revela qué dominios visita este equipo')}")
    print(f"  {dim('Ctrl+C para detener')}")
    separator("─", 60)
    print(f"  {'Hora':<12} {'Tipo':<8} {'Dominio consultado'}")
    separator("─", 60)

    dns_queries = []

    def process_dns(pkt):
        if not pkt.haslayer(DNS):
            return

        dns = pkt[DNS]
        ts  = datetime.now().strftime("%H:%M:%S")

        # Consulta (QR=0)
        if dns.qr == 0 and pkt.haslayer(DNSQR):
            qr = pkt[DNSQR]
            try:
                name = qr.qname.decode("utf-8", errors="replace").rstrip(".")
            except Exception:
                name = str(qr.qname)

            qtype_map = {1: "A", 28: "AAAA", 5: "CNAME", 15: "MX", 16: "TXT", 6: "SOA"}
            qtype = qtype_map.get(qr.qtype, str(qr.qtype))

            src_ip = pkt[IP].src if pkt.haslayer(IP) else "?"
            print(f"  {dim(ts):<12} {cyan(qtype):<8} {white(name):<40} {dim(f'← {src_ip}')}")
            dns_queries.append({"ts": ts, "type": qtype, "name": name, "ip": src_ip})

    try:
        sniff(
            filter="port 53",
            prn=process_dns,
            count=limit,
            store=False,
        )
    except (PermissionError, OSError):
        print()
        error("Permiso denegado. Necesitás ejecutar como root.")
        return
    except KeyboardInterrupt:
        pass
    except Exception as e:
        print()
        error(f"Error: {e}")
        return

    # Resumen
    print()
    separator("─", 60)
    result("Consultas capturadas", str(len(dns_queries)))
    if dns_queries:
        domains = Counter(q["name"] for q in dns_queries)
        print()
        print(f"  {white('Dominios más consultados:')}")
        for domain, count in domains.most_common(5):
            print(f"    {white(domain):<45} {dim(f'{count}x')}")
    separator("─", 60)


# ──────────────────────────────────────────────
#  Modo 4: Explicación didáctica
# ──────────────────────────────────────────────
def _mode_explain() -> None:
    section_title("SNIFFING DE PAQUETES — CONCEPTOS FUNDAMENTALES")

    print(f"""
  {white('¿Qué es un sniffer de paquetes?')}
  {dim('─' * 56)}

  Un sniffer captura los paquetes que viajan por la red
  y los presenta en formato legible para su análisis.

  Usos legítimos: diagnóstico de red, análisis de rendimiento,
  detección de intrusiones, aprendizaje de protocolos.
  Usos maliciosos: robo de credenciales, espionaje de tráfico.


  {white('La pila TCP/IP — capas de red')}
  {dim('─' * 56)}

  Capa 4 — Aplicación  {dim('HTTP, FTP, DNS, SMTP, SSH...')}
       ↑  Los datos que realmente ves (páginas web, emails)
  Capa 3 — Transporte  {dim('TCP, UDP')}
       ↑  Puertos, segmentación, control de flujo
  Capa 2 — Red         {dim('IP, ICMP, ARP')}
       ↑  Direccionamiento, enrutamiento
  Capa 1 — Enlace      {dim('Ethernet, Wi-Fi')}
       ↑  Tramas físicas, MACs

  El sniffer actúa en la capa 1/2 y "sube" la pila
  para interpretar cada capa.


  {white('Modo promiscuo')}
  {dim('─' * 56)}

  Normalmente, una NIC solo procesa paquetes dirigidos a su MAC.
  En modo promiscuo, acepta TODOS los paquetes que pasan
  por el segmento de red.

  {cyan('Con hub:')} {green('ve todo el tráfico del segmento')} (hubs son raros hoy)
  {cyan('Con switch:')} {yellow('solo ve broadcast + su propio tráfico')}
  {cyan('Con ARP spoofing:')} {red('puede ver tráfico ajeno en switches')}


  {white('TCP — Three-Way Handshake')}
  {dim('─' * 56)}

  Cliente              Servidor
     │──── SYN ────────►│   Quiero conectar
     │◄─── SYN+ACK ─────│   Acepto, confirmado
     │──── ACK ────────►│   Conexión establecida
     │                  │
     │══ Datos TCP ══════│   Intercambio de datos
     │                  │
     │──── FIN ────────►│   Quiero cerrar
     │◄─── FIN+ACK ─────│   Confirmado
     │──── ACK ────────►│   Cierre completado


  {white('Filtros BPF (Berkeley Packet Filter)')}
  {dim('─' * 56)}

  Sintaxis usada por tcpdump, Wireshark y Scapy:

  {cyan('Por protocolo:')}   {white('tcp')}  {white('udp')}  {white('icmp')}  {white('arp')}
  {cyan('Por puerto:')}      {white('port 80')}  {white('not port 22')}  {white('portrange 8000-9000')}
  {cyan('Por IP:')}          {white('host 10.0.0.1')}  {white('src host 192.168.1.0/24')}
  {cyan('Combinados:')}      {white('tcp and port 443')}  {white('udp and not port 53')}

  {white('Peligro del texto plano')}
  {dim('─' * 56)}

  Protocolos que envían credenciales SIN cifrar:

  {red('·')} {white('HTTP')}    (puerto 80)  → formularios de login visibles
  {red('·')} {white('FTP')}     (puerto 21)  → usuario y contraseña en claro
  {red('·')} {white('Telnet')}  (puerto 23)  → toda la sesión en claro
  {red('·')} {white('SMTP')}    (puerto 25)  → correos en texto plano
  {red('·')} {white('POP3')}    (puerto 110) → contraseñas en claro

  Solución: usar siempre versiones cifradas (HTTPS, SFTP, SSH, SMTPS)


  {white('Defensa contra sniffers')}
  {dim('─' * 56)}

  {green('·')} Usar protocolos cifrados (TLS/SSL) siempre
  {green('·')} VPN en redes públicas o no confiables
  {green('·')} 802.1X para autenticación en la red (impide rogue devices)
  {green('·')} Segmentación de red con VLANs
  {green('·')} Detección de modo promiscuo con herramientas como {white('arpwatch')}
    """)


# ──────────────────────────────────────────────
#  Submenú
# ──────────────────────────────────────────────
_SUBMENU = [
    ("1", "Captura en vivo (configurable)",          _mode_live_capture),
    ("2", "Captura rápida (configuración mínima)",   _mode_quick_capture),
    ("3", "Monitor de consultas DNS",                _mode_dns_monitor),
    ("4", "Conceptos: sniffing y TCP/IP",            _mode_explain),
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
    """Punto de entrada llamado desde main.py."""
    while True:
        section_title("HERRAMIENTA 6 — SNIFFER BÁSICO DE PAQUETES")
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
            error("Opción no válida. Ingresá un número del 0 al 4.")

        pause()


if __name__ == "__main__":
    run()
