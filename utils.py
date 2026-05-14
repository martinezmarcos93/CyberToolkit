"""
utils.py — Funciones compartidas de CyberToolkit
Banner, colores, prefijos de mensaje y validaciones reutilizables.
"""

import os
import re
import socket

# ──────────────────────────────────────────────
#  Colores con colorama (fallback si no está)
# ──────────────────────────────────────────────
try:
    from colorama import init, Fore, Style
    init(autoreset=True)
    _COLOR = True
except ImportError:
    _COLOR = False

    class _FakeFore:
        GREEN = RED = YELLOW = CYAN = MAGENTA = WHITE = BLUE = ""

    class _FakeStyle:
        BRIGHT = RESET_ALL = DIM = ""

    Fore = _FakeFore()
    Style = _FakeStyle()


# ──────────────────────────────────────────────
#  Helpers de color
# ──────────────────────────────────────────────
def green(text: str) -> str:
    return f"{Style.BRIGHT}{Fore.GREEN}{text}{Style.RESET_ALL}"

def red(text: str) -> str:
    return f"{Style.BRIGHT}{Fore.RED}{text}{Style.RESET_ALL}"

def yellow(text: str) -> str:
    return f"{Style.BRIGHT}{Fore.YELLOW}{text}{Style.RESET_ALL}"

def cyan(text: str) -> str:
    return f"{Style.BRIGHT}{Fore.CYAN}{text}{Style.RESET_ALL}"

def magenta(text: str) -> str:
    return f"{Style.BRIGHT}{Fore.MAGENTA}{text}{Style.RESET_ALL}"

def dim(text: str) -> str:
    return f"{Style.DIM}{text}{Style.RESET_ALL}"

def white(text: str) -> str:
    return f"{Style.BRIGHT}{Fore.WHITE}{text}{Style.RESET_ALL}"


# ──────────────────────────────────────────────
#  Prefijos de mensaje con íconos
# ──────────────────────────────────────────────
def ok(msg: str) -> None:
    """[✓ OK] Operación exitosa."""
    print(f"{green('[✓ OK]')} {msg}")

def error(msg: str) -> None:
    """[✗ ERROR] Error o fallo."""
    print(f"{red('[✗ ERROR]')} {msg}")

def warn(msg: str) -> None:
    """[⚠ WARN] Advertencia."""
    print(f"{yellow('[⚠ WARN]')} {msg}")

def info(msg: str) -> None:
    """[i INFO] Información general."""
    print(f"{cyan('[i INFO]')} {msg}")

def result(label: str, value: str) -> None:
    """Muestra un par clave-valor con formato."""
    print(f"  {dim('›')} {white(label)}: {value}")


# ──────────────────────────────────────────────
#  Pantalla y separadores
# ──────────────────────────────────────────────
def clear_screen() -> None:
    """Limpia la pantalla (cross-platform)."""
    os.system("cls" if os.name == "nt" else "clear")

def separator(char: str = "─", width: int = 60) -> None:
    """Imprime una línea separadora."""
    print(dim(char * width))

def section_title(title: str) -> None:
    """Imprime un título de sección destacado."""
    separator()
    print(f"  {cyan('◆')} {white(title)}")
    separator()


# ──────────────────────────────────────────────
#  Banner principal
# ──────────────────────────────────────────────
BANNER = r"""
  ██████╗██╗   ██╗██████╗ ███████╗██████╗
 ██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗
 ██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝
 ██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗
 ╚██████╗   ██║   ██████╔╝███████╗██║  ██║
  ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝

 ████████╗ ██████╗  ██████╗ ██╗     ██╗  ██╗██╗████████╗
    ██╔══╝██╔═══██╗██╔═══██╗██║     ██║ ██╔╝██║╚══██╔══╝
    ██║   ██║   ██║██║   ██║██║     █████╔╝ ██║   ██║
    ██║   ██║   ██║██║   ██║██║     ██╔═██╗ ██║   ██║
    ██║   ╚██████╔╝╚██████╔╝███████╗██║  ██╗██║   ██║
    ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝   ╚═╝
"""

def print_banner() -> None:
    """Imprime el banner ASCII y la info de versión."""
    clear_screen()
    print(magenta(BANNER))
    print(dim("  Suite educativa de ciberseguridad · v1.0"))
    print(dim("  Solo para uso en entornos propios y controlados"))
    separator("═")


# ──────────────────────────────────────────────
#  Menú principal (renderizado)
# ──────────────────────────────────────────────
MENU_ITEMS = [
    ("1", "Escáner de puertos TCP",             "Red / Reconocimiento"),
    ("2", "Verificador de contraseñas",          "Políticas / Entropía"),
    ("3", "Generador / verificador de hashes",   "Integridad / Forense"),
    ("4", "Analizador de URLs sospechosas",      "Phishing / OSINT"),
    ("5", "Monitor de integridad de archivos",   "HIDS / Persistencia"),
    ("6", "Sniffer básico de paquetes",          "Red / TCP-IP  [root]"),
    ("7", "Cifrador / descifrador AES-256",      "Criptografía simétrica"),
    ("8", "Extractor de metadatos",              "Forense / Privacidad"),
    ("9", "Generador de contraseñas seguras",    "Aleatoriedad / Secrets"),
    ("0", "Calculadora de entropía de archivos", "Malware / Estadística"),
]

def print_menu() -> None:
    """Renderiza el menú interactivo siempre visible."""
    print()
    print(f"  {white('HERRAMIENTAS DISPONIBLES')}")
    separator("─", 60)
    print(f"  {'#':<4} {'Herramienta':<38} {'Área'}")
    separator("─", 60)
    for num, name, area in MENU_ITEMS:
        num_fmt  = cyan(f"[{num}]")
        name_fmt = white(name)
        area_fmt = dim(area)
        print(f"  {num_fmt:<4} {name_fmt:<38} {area_fmt}")
    separator("─", 60)
    print(f"  {red('[Q]')}  Salir")
    separator("═", 60)


# ──────────────────────────────────────────────
#  Entrada de datos segura
# ──────────────────────────────────────────────
def prompt(msg: str, default: str = "") -> str:
    """Pide un valor al usuario con prompt coloreado."""
    suffix = f" [{dim(default)}]" if default else ""
    try:
        value = input(f"  {cyan('❯')} {msg}{suffix}: ").strip()
        return value if value else default
    except (EOFError, KeyboardInterrupt):
        return default

def ask_yes_no(msg: str, default: bool = True) -> bool:
    """Pregunta sí/no. Devuelve bool."""
    hint = "[S/n]" if default else "[s/N]"
    raw = prompt(f"{msg} {dim(hint)}").lower()
    if raw in ("s", "si", "sí", "y", "yes"):
        return True
    if raw in ("n", "no"):
        return False
    return default

def pause() -> None:
    """Pausa hasta que el usuario presione Enter."""
    input(f"\n  {dim('Presioná Enter para volver al menú...')}")


# ──────────────────────────────────────────────
#  Validaciones
# ──────────────────────────────────────────────
def validate_ip(ip: str) -> bool:
    """Valida una dirección IPv4."""
    pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
    if not re.match(pattern, ip):
        return False
    return all(0 <= int(octet) <= 255 for octet in ip.split("."))

def validate_hostname(host: str) -> bool:
    """Valida que un hostname se pueda resolver."""
    try:
        socket.gethostbyname(host)
        return True
    except socket.gaierror:
        return False

def validate_port_range(start: int, end: int) -> bool:
    """Valida un rango de puertos (1–65535)."""
    return 1 <= start <= end <= 65535

def validate_file(path: str) -> bool:
    """Valida que un archivo exista y sea legible."""
    return os.path.isfile(path) and os.access(path, os.R_OK)

def validate_dir(path: str) -> bool:
    """Valida que un directorio exista."""
    return os.path.isdir(path)

def read_file_bytes(path: str) -> bytes | None:
    """Lee un archivo en modo binario. Devuelve None si falla."""
    try:
        with open(path, "rb") as f:
            return f.read()
    except OSError as e:
        error(f"No se pudo leer '{path}': {e}")
        return None

def format_size(num_bytes: int) -> str:
    """Convierte bytes a una cadena legible (KB, MB, GB)."""
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if num_bytes < 1024:
            return f"{num_bytes:.1f} {unit}"
        num_bytes /= 1024
    return f"{num_bytes:.1f} PB"
