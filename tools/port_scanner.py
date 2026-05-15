"""
port_scanner.py — Herramienta 1: Escáner de puertos TCP
Escanea rangos de puertos TCP usando sockets y ThreadPoolExecutor.
Detecta puertos abiertos, cerrados y filtrados, e identifica servicios.

Conceptos didácticos:
  · TCP three-way handshake (SYN → SYN-ACK → ACK)
  · Diferencia entre puerto abierto, cerrado y filtrado (firewall)
  · Concurrencia con hilos para acelerar el escaneo
  · Sockets en Python: connect_ex() vs connect()
"""

import ipaddress
import os
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils import (
    ok, error, warn, info, result,
    section_title, separator, dim, cyan, green, yellow, white, red, magenta,
    prompt, ask_yes_no, pause, validate_ip,
)
from config import (
    SOCKET_TIMEOUT, MAX_THREADS,
    get_service, get_service_desc, COMMON_PORTS,
)


# ──────────────────────────────────────────────
#  Tipos de resultado por puerto
# ──────────────────────────────────────────────
STATUS_OPEN     = "open"
STATUS_CLOSED   = "closed"
STATUS_FILTERED = "filtered"


# ──────────────────────────────────────────────
#  Escaneo de un puerto individual
# ──────────────────────────────────────────────
def _scan_port(host: str, port: int, timeout: float) -> tuple[int, str, str | None]:
    """
    Intenta una conexión TCP al puerto dado.

    Retorna:
        (puerto, estado, banner_opcional)

    Estados:
        · 'open'     — conexión exitosa (SYN-ACK recibido)
        · 'closed'   — rechazo inmediato (RST recibido)
        · 'filtered' — timeout (firewall silencioso)

    Nota didáctica:
        connect_ex() devuelve 0 si la conexión fue exitosa,
        o un código de error del SO en caso contrario.
        A diferencia de connect(), no lanza excepciones.
    """
    banner = None

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        code = sock.connect_ex((host, port))

        if code == 0:
            # Puerto abierto: intentar capturar banner
            try:
                sock.settimeout(0.3)
                banner_raw = sock.recv(1024)
                banner = banner_raw.decode("utf-8", errors="replace").strip()[:80]
            except Exception:
                pass
            sock.close()
            return port, STATUS_OPEN, banner

        sock.close()
        return port, STATUS_CLOSED, None

    except socket.timeout:
        return port, STATUS_FILTERED, None
    except OSError:
        return port, STATUS_FILTERED, None


# ──────────────────────────────────────────────
#  Motor de escaneo con hilos
# ──────────────────────────────────────────────
def _run_scan(
    host: str,
    ports: list[int],
    timeout: float,
    max_threads: int,
    show_closed: bool = False,
) -> list[tuple[int, str, str | None]]:
    """
    Escanea una lista de puertos de forma concurrente con ThreadPoolExecutor.
    Muestra progreso en tiempo real y devuelve la lista de resultados.
    """
    total   = len(ports)
    done    = 0
    results = []

    print()
    info(f"Escaneando {white(host)} · {total} puerto(s) · {max_threads} hilos · timeout {timeout}s")
    separator("─", 60)

    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = {
            executor.submit(_scan_port, host, port, timeout): port
            for port in ports
        }

        for future in as_completed(futures):
            done += 1
            port, status, banner = future.result()
            results.append((port, status, banner))

            # Barra de progreso inline
            pct      = done / total * 100
            bar_len  = int(pct / 5)
            bar      = green("█" * bar_len) + dim("░" * (20 - bar_len))
            print(
                f"\r  {bar} {dim(f'{pct:5.1f}%')} "
                f"{dim(f'[{done}/{total}]')} "
                f"{cyan(str(port)):<8} "
                f"{(green('OPEN') if status == STATUS_OPEN else dim(status)):<10}",
                end="",
                flush=True,
            )

    print()  # nueva línea tras la barra
    return sorted(results, key=lambda x: x[0])


# ──────────────────────────────────────────────
#  Formateo de resultados
# ──────────────────────────────────────────────
def _print_results(
    results: list[tuple[int, str, str | None]],
    show_closed: bool,
    elapsed: float,
) -> None:
    """Muestra una tabla de resultados del escaneo."""
    open_ports     = [(p, b) for p, s, b in results if s == STATUS_OPEN]
    closed_count   = sum(1 for _, s, _ in results if s == STATUS_CLOSED)
    filtered_count = sum(1 for _, s, _ in results if s == STATUS_FILTERED)

    separator("═", 60)
    print(f"  {white('RESULTADOS DEL ESCANEO')}")
    separator("─", 60)
    print(
        f"  {green(f'{len(open_ports)} abiertos')}  ·  "
        f"{dim(f'{closed_count} cerrados')}  ·  "
        f"{yellow(f'{filtered_count} filtrados')}  ·  "
        f"{dim(f'{elapsed:.2f}s')}"
    )
    separator("─", 60)

    if not open_ports:
        warn("No se encontraron puertos abiertos en el rango especificado.")
        return

    # Cabecera de la tabla
    print(f"  {'Puerto':<8} {'Servicio':<12} {'Estado':<10} {'Descripción / Banner'}")
    separator("─", 60)

    for port, banner in sorted(open_ports):
        service  = get_service(port)
        desc     = get_service_desc(port)
        display  = banner if banner else desc

        # Marcar puertos peligrosos conocidos
        danger_ports = {21, 23, 135, 137, 138, 139, 445, 3389, 5900}
        if port in danger_ports:
            port_fmt = red(f"{port}/tcp")
        else:
            port_fmt = green(f"{port}/tcp")

        service_fmt = cyan(service) if service != "unknown" else dim("unknown")
        display_fmt = dim(display[:40]) if display else ""

        print(f"  {port_fmt:<8} {service_fmt:<12} {green('OPEN'):<10} {display_fmt}")

    separator("─", 60)

    # Advertencias sobre servicios peligrosos
    open_ports_set = {p for p, _ in open_ports}
    _print_security_notes(open_ports_set)


def _print_security_notes(open_ports: set[int]) -> None:
    """Muestra notas de seguridad para servicios potencialmente peligrosos."""
    WARNINGS = {
        21:    ("FTP sin cifrado",         "Usá SFTP (puerto 22) o FTPS (990) en su lugar."),
        23:    ("Telnet sin cifrado",       "Reemplazá por SSH (puerto 22) inmediatamente."),
        80:    ("HTTP sin cifrado",         "Si es un servidor web, habilitá HTTPS (443)."),
        135:   ("MSRPC expuesto",           "Filtrálo en el firewall si no es necesario."),
        139:   ("NetBIOS expuesto",         "Riesgo de enumeración de recursos compartidos."),
        445:   ("SMB expuesto",             "Vector común de ransomware. Bloqueá en perímetro."),
        1433:  ("SQL Server expuesto",      "Base de datos expuesta. Restringí el acceso."),
        3306:  ("MySQL expuesto",           "Base de datos expuesta. No debería ser público."),
        3389:  ("RDP expuesto",             "Blanco frecuente de ataques de fuerza bruta."),
        5432:  ("PostgreSQL expuesto",      "Restringí el acceso solo a IPs de confianza."),
        5900:  ("VNC expuesto",             "Acceso de escritorio remoto sin cifrado fuerte."),
        6379:  ("Redis expuesto",           "Redis sin auth por defecto. Riesgo crítico."),
        27017: ("MongoDB expuesto",         "MongoDB sin auth por defecto en versiones viejas."),
        2375:  ("Docker API sin TLS",       "Permite control total del host. Riesgo crítico."),
    }

    notes_shown = False
    for port in sorted(open_ports):
        if port in WARNINGS:
            if not notes_shown:
                print()
                print(f"  {yellow('⚠  NOTAS DE SEGURIDAD:')}")
                separator("─", 60)
                notes_shown = True
            service_name, advice = WARNINGS[port]
            print(f"  {red(f'[{port}]')} {yellow(service_name)}")
            print(f"       {dim(advice)}")

    if notes_shown:
        separator("─", 60)


# ──────────────────────────────────────────────
#  Resolución de host
# ──────────────────────────────────────────────
def _resolve_host(host: str) -> str | None:
    """
    Resuelve un hostname a IP.
    Si ya es una IP válida, la devuelve sin cambios.
    """
    if validate_ip(host):
        return host

    try:
        ip = socket.gethostbyname(host)
        info(f"Hostname resuelto: {white(host)} → {cyan(ip)}")
        return ip
    except socket.gaierror:
        error(f"No se pudo resolver el hostname '{host}'.")
        return None


# ──────────────────────────────────────────────
#  Parseo de rango de puertos
# ──────────────────────────────────────────────
def _parse_port_input(raw: str) -> list[int] | None:
    """
    Acepta múltiples formatos de entrada:
      · "80"           → [80]
      · "80,443,8080"  → [80, 443, 8080]
      · "1-1024"       → [1, 2, ..., 1024]
      · "common"       → lista de COMMON_PORTS
      · "top100"       → top 100 puertos más comunes
    """
    raw = raw.strip().lower()

    if raw == "common":
        return sorted(COMMON_PORTS.keys())

    if raw == "top100":
        TOP_100 = [
            21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,
            1723,3306,3389,5900,8080,8443,8888,
            20,69,88,123,161,194,389,465,500,514,515,587,631,636,
            873,902,989,990,1080,1194,1433,1434,1521,2049,2181,
            2375,2376,3000,3690,4443,4505,4506,5000,5432,5985,
            5986,6379,6443,7001,9000,9090,9200,9300,11211,27017,
            27018,50000,
            7,9,13,17,19,24,79,106,119,427,464,554,593,
            1025,1026,1027,1028,1029,1110,1720,2000,2001,3128,
            5060,5061,8000,8081,10000
        ]
        return sorted(set(TOP_100))

    # Rango: "inicio-fin"
    if "-" in raw and "," not in raw:
        parts = raw.split("-")
        if len(parts) == 2:
            try:
                start, end = int(parts[0]), int(parts[1])
                if 1 <= start <= end <= 65535:
                    return list(range(start, end + 1))
                else:
                    error("Rango inválido. Los puertos deben estar entre 1 y 65535.")
                    return None
            except ValueError:
                pass

    # Lista separada por comas: "80,443,8080"
    if "," in raw or raw.isdigit():
        try:
            ports = [int(p.strip()) for p in raw.split(",")]
            invalid = [p for p in ports if not (1 <= p <= 65535)]
            if invalid:
                error(f"Puertos fuera de rango (1-65535): {invalid}")
                return None
            return sorted(set(ports))
        except ValueError:
            pass

    error(f"Formato de puertos no reconocido: '{raw}'")
    return None


# ──────────────────────────────────────────────
#  Modo 1: Escaneo interactivo
# ──────────────────────────────────────────────
def _mode_scan() -> None:
    section_title("ESCANEO DE PUERTOS TCP")

    # Target
    host_raw = prompt("IP o hostname objetivo")
    if not host_raw:
        warn("No se ingresó ningún objetivo.")
        return

    ip = _resolve_host(host_raw)
    if ip is None:
        return

    # Rango de puertos
    print()
    info("Formatos aceptados:")
    print(f"  {dim('·')} {cyan('1-1024')}       Rango de puertos")
    print(f"  {dim('·')} {cyan('80,443,8080')}  Lista separada por comas")
    print(f"  {dim('·')} {cyan('common')}        {len(COMMON_PORTS)} puertos conocidos (recomendado)")
    print(f"  {dim('·')} {cyan('top100')}         Top 100 puertos más usados")
    print()

    raw_ports = prompt("Puertos a escanear", default="common")
    ports = _parse_port_input(raw_ports)
    if ports is None:
        return

    if len(ports) > 10000:
        warn(f"Rango amplio: {len(ports)} puertos. Puede tardar varios minutos.")
        if not ask_yes_no("¿Continuar de todas formas?", default=False):
            return

    # Configuración avanzada
    print()
    use_advanced = ask_yes_no("¿Configurar opciones avanzadas (timeout, hilos)?", default=False)

    timeout     = SOCKET_TIMEOUT
    max_threads = MAX_THREADS
    show_closed = False

    if use_advanced:
        raw_timeout = prompt("Timeout por puerto (segundos)", default=str(SOCKET_TIMEOUT))
        try:
            timeout = float(raw_timeout)
            timeout = max(0.1, min(timeout, 10.0))
        except ValueError:
            warn(f"Timeout inválido. Usando {SOCKET_TIMEOUT}s por defecto.")

        raw_threads = prompt("Hilos simultáneos (1-500)", default=str(MAX_THREADS))
        try:
            max_threads = int(raw_threads)
            max_threads = max(1, min(max_threads, 500))
        except ValueError:
            warn(f"Número de hilos inválido. Usando {MAX_THREADS} por defecto.")

        show_closed = ask_yes_no("¿Mostrar también los puertos cerrados?", default=False)

    # Confirmación
    print()
    separator("─", 60)
    result("Objetivo",     f"{white(host_raw)} ({cyan(ip)})")
    result("Puertos",      f"{len(ports)} (de {min(ports)} a {max(ports)})")
    result("Timeout",      f"{timeout}s por puerto")
    result("Hilos",        str(max_threads))
    result("Inicio",       datetime.now().strftime("%H:%M:%S"))
    separator("─", 60)

    if not ask_yes_no("¿Iniciar el escaneo?", default=True):
        warn("Escaneo cancelado.")
        return

    # Ejecutar escaneo
    start_time = time.time()
    results    = _run_scan(ip, ports, timeout, max_threads, show_closed)
    elapsed    = time.time() - start_time

    # Mostrar resultados
    _print_results(results, show_closed, elapsed)

    ok(f"Escaneo completado en {elapsed:.2f} segundos.")


# ──────────────────────────────────────────────
#  Modo 2: Escaneo rápido (puertos comunes)
# ──────────────────────────────────────────────
def _mode_quick_scan() -> None:
    section_title("ESCANEO RÁPIDO — PUERTOS COMUNES")

    host_raw = prompt("IP o hostname objetivo")
    if not host_raw:
        warn("No se ingresó ningún objetivo.")
        return

    ip = _resolve_host(host_raw)
    if ip is None:
        return

    ports = sorted(COMMON_PORTS.keys())
    info(f"Usando {len(ports)} puertos comunes con configuración optimizada.")

    start_time = time.time()
    results    = _run_scan(ip, ports, timeout=0.4, max_threads=150)
    elapsed    = time.time() - start_time

    _print_results(results, show_closed=False, elapsed=elapsed)
    ok(f"Escaneo rápido completado en {elapsed:.2f} segundos.")


# ──────────────────────────────────────────────
#  Modo 3: Verificar un puerto único
# ──────────────────────────────────────────────
def _mode_single_port() -> None:
    section_title("VERIFICAR PUERTO ÚNICO")

    host_raw = prompt("IP o hostname objetivo")
    if not host_raw:
        warn("No se ingresó ningún objetivo.")
        return

    ip = _resolve_host(host_raw)
    if ip is None:
        return

    raw_port = prompt("Número de puerto (1-65535)")
    try:
        port = int(raw_port)
        if not (1 <= port <= 65535):
            error("Puerto fuera de rango.")
            return
    except ValueError:
        error("Puerto inválido.")
        return

    service = get_service(port)
    desc    = get_service_desc(port)

    info(f"Verificando {white(ip)}:{cyan(str(port))} ({service})...")

    port_result, status, banner = _scan_port(ip, port, timeout=2.0)

    print()
    separator("─", 58)
    result("Objetivo",   f"{host_raw} ({ip})")
    result("Puerto",     f"{port}/tcp")
    result("Servicio",   f"{service} — {dim(desc)}" if desc else service)

    if status == STATUS_OPEN:
        result("Estado",     green("ABIERTO ✓"))
        if banner:
            result("Banner",     dim(banner))
    elif status == STATUS_CLOSED:
        result("Estado",     red("CERRADO ✗"))
    else:
        result("Estado",     yellow("FILTRADO (timeout) ⚠"))

    separator("─", 58)

    # Nota didáctica
    print()
    if status == STATUS_OPEN:
        info("El host completó el three-way handshake: SYN → SYN-ACK → ACK.")
        info("El servicio está aceptando conexiones en este puerto.")
    elif status == STATUS_CLOSED:
        info("El host respondió con RST (Reset). El puerto no está en uso.")
        info("Esto confirma que el host está activo pero el servicio no corre.")
    else:
        info("Sin respuesta tras el timeout. Posibles causas:")
        print(f"  {dim('·')} Un firewall está bloqueando el paquete (DROP silencioso)")
        print(f"  {dim('·')} El host no está en línea")
        print(f"  {dim('·')} Timeout demasiado corto para la latencia de red")


# ──────────────────────────────────────────────
#  Modo 4: Explicación didáctica
# ──────────────────────────────────────────────
def _mode_explain() -> None:
    section_title("¿CÓMO FUNCIONA UN ESCÁNER DE PUERTOS?")

    print(f"""
  {white('El protocolo TCP y el three-way handshake')}
  {dim('─' * 56)}

  Toda conexión TCP comienza con un "apretón de manos" de 3 pasos:

    {cyan('Cliente')}                          {cyan('Servidor')}
       │                                   │
       │ ──────── SYN ──────────────────► │  "Quiero conectarme"
       │                                   │
       │ ◄──── SYN-ACK ─────────────────── │  "De acuerdo, adelante"
       │                                   │
       │ ──────── ACK ──────────────────► │  "Confirmado, conectado"
       │                                   │
                   {green('CONEXIÓN ESTABLECIDA')}

  {white('Lo que hace este escáner:')}
  {dim('·')} Intenta completar este handshake en cada puerto
  {dim('·')} Puerto {green('ABIERTO')}:    handshake exitoso → servicio escuchando
  {dim('·')} Puerto {red('CERRADO')}:   recibe RST → host activo, servicio inactivo
  {dim('·')} Puerto {yellow('FILTRADO')}:  no hay respuesta → firewall bloqueando

  {white('Concurrencia con hilos:')}
  {dim('·')} Escanear 1000 puertos de forma secuencial: ~500 segundos
  {dim('·')} Con 100 hilos simultáneos:                ~5 segundos
  {dim('·')} ThreadPoolExecutor distribuye el trabajo entre los hilos
  {dim('·')} Cada hilo maneja un puerto de forma independiente

  {white('¿Por qué connect_ex() y no connect()?')}
  {dim('·')} connect()    lanza una excepción si falla → overhead
  {dim('·')} connect_ex() devuelve un código de error → más eficiente
  {dim('·')} Código 0    → éxito (puerto abierto)
  {dim('·')} Código != 0 → fallo (cerrado o filtrado)

  {white('Ética y uso responsable:')}
  {dim('·')} Escanear una red sin permiso es {red('ilegal')} en la mayoría de países
  {dim('·')} Usá esta herramienta solo en {green('tu propio hardware')}
  {dim('·')} En pentesting profesional: siempre con {yellow('autorización escrita')}
    """)


# ──────────────────────────────────────────────
#  Submenú
# ──────────────────────────────────────────────
_SUBMENU = [
    ("1", "Escaneo interactivo (personalizable)",    _mode_scan),
    ("2", "Escaneo rápido de puertos comunes",       _mode_quick_scan),
    ("3", "Verificar un puerto único",               _mode_single_port),
    ("4", "¿Cómo funciona un escáner de puertos?",  _mode_explain),
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
        section_title("HERRAMIENTA 1 — ESCÁNER DE PUERTOS TCP")
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
                    warn("Escaneo interrumpido. Volviendo al submenú.")
                break

        if not matched:
            error("Opción no válida. Ingresá un número del 0 al 4.")

        pause()


if __name__ == "__main__":
    run()
