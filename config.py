"""
config.py — Constantes globales de CyberToolkit
Diccionario de puertos, contraseñas débiles, velocidades de cracking y configuración general.
"""

# ──────────────────────────────────────────────
#  Info del proyecto
# ──────────────────────────────────────────────
APP_NAME    = "CyberToolkit"
APP_VERSION = "1.0"
APP_AUTHOR  = "Educativo — solo entornos controlados"

import os
import json
from pathlib import Path

# ──────────────────────────────────────────────
#  Configuración dinámica (.cybertoolkitrc)
# ──────────────────────────────────────────────
USER_HOME = Path.home()
CTK_DIR = USER_HOME / ".cybertoolkit"
CONFIG_FILE = CTK_DIR / "cybertoolkitrc.json"
SESSION_LOG_FILE = CTK_DIR / "session.log"

SETTINGS = {
    "log_level": "INFO",
    "export_format": "txt",
    "socket_timeout": 0.5,
    "max_threads": 100,
    "sniffer_pkt_limit": 50,
    "file_read_chunk": 65536
}

def load_config() -> None:
    """Carga la configuración desde ~/.cybertoolkit/cybertoolkitrc.json."""
    if not CTK_DIR.exists():
        CTK_DIR.mkdir(parents=True, exist_ok=True)
    if CONFIG_FILE.exists():
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                user_settings = json.load(f)
                SETTINGS.update(user_settings)
        except Exception:
            pass
    else:
        save_config()

def save_config() -> None:
    """Guarda la configuración actual en ~/.cybertoolkit/cybertoolkitrc.json."""
    if not CTK_DIR.exists():
        CTK_DIR.mkdir(parents=True, exist_ok=True)
    try:
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(SETTINGS, f, indent=4)
    except Exception:
        pass

# Inicializar config
load_config()

# ──────────────────────────────────────────────
#  Configuración general
# ──────────────────────────────────────────────
SOCKET_TIMEOUT      = SETTINGS.get("socket_timeout", 0.5)
MAX_THREADS         = SETTINGS.get("max_threads", 100)
SNIFFER_PKT_LIMIT   = SETTINGS.get("sniffer_pkt_limit", 50)
FILE_READ_CHUNK     = SETTINGS.get("file_read_chunk", 65536)

# ──────────────────────────────────────────────
#  Diccionario de puertos comunes
#  Formato: puerto (int) → (servicio, descripción corta)
# ──────────────────────────────────────────────
COMMON_PORTS: dict[int, tuple[str, str]] = {
    20:    ("FTP-DATA",   "Transferencia de datos FTP"),
    21:    ("FTP",        "File Transfer Protocol"),
    22:    ("SSH",        "Secure Shell"),
    23:    ("TELNET",     "Telnet — sin cifrado"),
    25:    ("SMTP",       "Envío de correo"),
    53:    ("DNS",        "Domain Name System"),
    67:    ("DHCP",       "Asignación de IPs (servidor)"),
    68:    ("DHCP",       "Asignación de IPs (cliente)"),
    69:    ("TFTP",       "Trivial File Transfer Protocol"),
    80:    ("HTTP",       "Servidor web sin cifrado"),
    88:    ("Kerberos",   "Autenticación Kerberos"),
    110:   ("POP3",       "Recepción de correo"),
    111:   ("RPC",        "Remote Procedure Call"),
    119:   ("NNTP",       "Network News Transfer Protocol"),
    123:   ("NTP",        "Sincronización de tiempo"),
    135:   ("MSRPC",      "Microsoft RPC"),
    137:   ("NetBIOS-NS", "Resolución de nombres NetBIOS"),
    138:   ("NetBIOS-DG", "Datagrama NetBIOS"),
    139:   ("NetBIOS-SS", "Sesión NetBIOS / SMB"),
    143:   ("IMAP",       "Acceso a correo remoto"),
    161:   ("SNMP",       "Gestión de red (UDP)"),
    162:   ("SNMP-TRAP",  "Traps SNMP"),
    179:   ("BGP",        "Border Gateway Protocol"),
    194:   ("IRC",        "Internet Relay Chat"),
    389:   ("LDAP",       "Directorio activo"),
    443:   ("HTTPS",      "Servidor web cifrado"),
    445:   ("SMB",        "Compartición de archivos Windows"),
    465:   ("SMTPS",      "SMTP sobre TLS"),
    500:   ("ISAKMP",     "VPN / IKE"),
    514:   ("Syslog",     "Registro de eventos (UDP)"),
    515:   ("LPD",        "Impresión en red"),
    587:   ("SMTP-SUB",   "Envío de correo autenticado"),
    631:   ("IPP",        "Protocolo de impresión"),
    636:   ("LDAPS",      "LDAP sobre TLS"),
    873:   ("Rsync",      "Sincronización de archivos"),
    902:   ("VMware",     "VMware ESXi / vSphere"),
    989:   ("FTPS-DATA",  "FTP seguro — datos"),
    990:   ("FTPS",       "FTP sobre TLS"),
    993:   ("IMAPS",      "IMAP sobre TLS"),
    995:   ("POP3S",      "POP3 sobre TLS"),
    1080:  ("SOCKS",      "Proxy SOCKS"),
    1194:  ("OpenVPN",    "VPN OpenVPN (UDP/TCP)"),
    1433:  ("MSSQL",      "Microsoft SQL Server"),
    1434:  ("MSSQL-UDP",  "MS SQL Server Browser"),
    1521:  ("Oracle",     "Oracle Database"),
    1723:  ("PPTP",       "VPN PPTP"),
    2049:  ("NFS",        "Network File System"),
    2181:  ("Zookeeper",  "Apache ZooKeeper"),
    2375:  ("Docker",     "Docker API sin TLS ⚠"),
    2376:  ("Docker-TLS", "Docker API con TLS"),
    3000:  ("Dev-HTTP",   "Servidor de desarrollo web"),
    3306:  ("MySQL",      "MySQL / MariaDB"),
    3389:  ("RDP",        "Escritorio remoto Windows"),
    3690:  ("SVN",        "Subversion"),
    4443:  ("HTTPS-ALT",  "HTTPS alternativo"),
    4505:  ("SaltStack",  "SaltStack master"),
    4506:  ("SaltStack",  "SaltStack minion"),
    5000:  ("Dev-HTTP",   "Flask / dev server"),
    5432:  ("PostgreSQL", "Base de datos PostgreSQL"),
    5900:  ("VNC",        "Virtual Network Computing"),
    5985:  ("WinRM-HTTP", "Windows Remote Management"),
    5986:  ("WinRM-HTTPS","Windows Remote Management TLS"),
    6379:  ("Redis",      "Base de datos Redis"),
    6443:  ("K8s-API",    "Kubernetes API server"),
    7001:  ("WebLogic",   "Oracle WebLogic"),
    8080:  ("HTTP-ALT",   "HTTP alternativo / proxy"),
    8443:  ("HTTPS-ALT",  "HTTPS alternativo"),
    8888:  ("Jupyter",    "Jupyter Notebook"),
    9000:  ("SonarQube",  "SonarQube / PHP-FPM"),
    9090:  ("Prometheus", "Prometheus métricas"),
    9200:  ("Elastic",    "Elasticsearch HTTP"),
    9300:  ("Elastic-T",  "Elasticsearch transporte"),
    11211: ("Memcached",  "Caché distribuida"),
    27017: ("MongoDB",    "Base de datos MongoDB"),
    27018: ("MongoDB",    "MongoDB shard"),
    50000: ("SAP",        "SAP Message Server"),
}

def get_service(port: int) -> str:
    """Devuelve el nombre del servicio para un puerto, o 'unknown'."""
    entry = COMMON_PORTS.get(port)
    return entry[0] if entry else "unknown"

def get_service_desc(port: int) -> str:
    """Devuelve la descripción del servicio para un puerto, o cadena vacía."""
    entry = COMMON_PORTS.get(port)
    return entry[1] if entry else ""


# ──────────────────────────────────────────────
#  Lista de contraseñas débiles (top 100)
#  Fuente: SecLists / HaveIBeenPwned top passwords
# ──────────────────────────────────────────────
WEAK_PASSWORDS: set[str] = {
    "123456", "password", "123456789", "12345678", "12345",
    "1234567", "1234567890", "qwerty", "abc123", "111111",
    "123123", "admin", "letmein", "welcome", "monkey",
    "dragon", "master", "sunshine", "princess", "shadow",
    "superman", "michael", "football", "baseball", "soccer",
    "iloveyou", "trustno1", "hello", "charlie", "donald",
    "password1", "password123", "passw0rd", "pa$$word", "p@ssword",
    "p@ssw0rd", "qwerty123", "1q2w3e", "1q2w3e4r", "qwertyuiop",
    "asdfghjkl", "zxcvbnm", "0987654321", "9876543210", "1234",
    "0000", "1111", "7777", "8888", "9999",
    "12341234", "00000000", "11111111", "123321", "654321",
    "666666", "696969", "123654", "159753", "789456",
    "147258369", "123qwe", "aaaaaa", "bbbbbb", "111222",
    "112233", "121212", "131313", "202020", "246810",
    "access", "secret", "login", "ninja", "mustang",
    "batman", "starwars", "matrix", "whatever", "nothing",
    "qazwsx", "123abc", "abc", "test", "guest",
    "root", "toor", "admin123", "administrator", "changeme",
    "default", "pass", "pass123", "temp", "temp123",
    "abc1234", "1234abc", "q1w2e3", "a1b2c3", "zaq12wsx",
    "thomas", "jessica", "jennifer", "1234qwer", "lovely",
    "daniel", "andrew", "joshua", "george", "hunter",
}


# ──────────────────────────────────────────────
#  Velocidades de ataque de cracking (hashes/seg)
#  Estimaciones conservadoras para hardware moderno
# ──────────────────────────────────────────────
#  Fuentes de referencia: Hashcat benchmarks, GPU mid-range 2024

CRACK_SPEEDS: dict[str, dict[str, int | str]] = {
    "MD5": {
        "offline_gpu": 60_000_000_000,   # 60 GH/s (RTX 4080)
        "offline_cpu": 500_000_000,      # 500 MH/s (CPU moderna)
        "online":      1_000,            # ~1000 intentos/min (con throttling)
        "label":       "MD5",
    },
    "SHA-1": {
        "offline_gpu": 20_000_000_000,
        "offline_cpu": 200_000_000,
        "online":      1_000,
        "label":       "SHA-1",
    },
    "SHA-256": {
        "offline_gpu": 9_000_000_000,
        "offline_cpu": 100_000_000,
        "online":      1_000,
        "label":       "SHA-256",
    },
    "bcrypt": {
        "offline_gpu": 20_000,           # bcrypt es deliberadamente lento
        "offline_cpu": 1_000,
        "online":      100,
        "label":       "bcrypt (cost=10)",
    },
}

# Referencia por defecto para el verificador de contraseñas
DEFAULT_HASH_ALGO = "SHA-256"


# ──────────────────────────────────────────────
#  Juegos de caracteres para generador de contraseñas
# ──────────────────────────────────────────────
import string

CHARSET_LOWER   = string.ascii_lowercase          # a-z
CHARSET_UPPER   = string.ascii_uppercase          # A-Z
CHARSET_DIGITS  = string.digits                   # 0-9
CHARSET_SYMBOLS = "!@#$%^&*()_+-=[]{}|;:,.<>?"   # símbolos seguros
CHARSET_FULL    = CHARSET_LOWER + CHARSET_UPPER + CHARSET_DIGITS + CHARSET_SYMBOLS

# Longitud mínima recomendada para contraseñas
MIN_PASSWORD_LENGTH = 12

# Lista de palabras básica para Diceware (200 palabras en español)
DICEWARE_WORDS: list[str] = [
    "abeja","árbol","azul","banco","barco","bello","bosque","brazo","brisa","caña",
    "campo","carta","cesta","cielo","circo","claro","cobre","color","corte","cueva",
    "datos","deber","delta","denso","dicha","dique","disco","doble","dulce","dunas",
    "época","espía","extra","fábrica","falda","fango","fénix","fibra","final","finca",
    "flama","flota","fogón","forma","freno","fruta","fuego","fuerza","gafas","gallo",
    "ganas","garza","génio","globo","golfo","gordo","grano","gruta","gusto","habla",
    "hambre","hielo","hincha","hongo","hueso","huevo","humor","ideal","igual","india",
    "índice","ingles","íntimo","isla","jaspe","jirafa","joven","juego","jueza","jugo",
    "justo","largo","latón","laúd","laurel","lecho","legua","lente","letra","libre",
    "libro","lienzo","ligero","lince","línea","listo","litro","llano","llave","lluvia",
    "lógica","lomo","loro","lucha","lugar","luna","lustre","magia","mango","manto",
    "marca","marea","mármol","masa","mayor","media","mejor","mente","metal","metro",
    "miedo","mirar","mismo","molde","monte","moral","mosca","motor","mundo","musgo",
    "néctar","negro","nervio","nicho","nimbo","nivel","noble","noche","norma","nubla",
    "océano","oferta","oliva","orden","órgano","orilla","osado","otoño","pájaro","palma",
    "papel","parque","pausa","pedal","peine","pelota","perla","peso","piloto","pinar",
    "pista","pixel","playa","plaza","pluma","poder","poema","polar","polvo","prado",
    "primo","pronto","puente","punto","queso","radio","rama","rango","rápido","rasgo",
    "ratón","rayo","razón","recto","reino","reloj","resto","retro","ritmo","roble",
    "roca","rodeo","rombo","rosca","rueda","rumbo","sabio","salto","salud","samba",
    "sauce","selva","señal","sierra","siglo","signo","silbo","silva","sólido","soplo",
    "suite","tabla","tallo","tango","tapiz","tarea","tarro","techo","tejón","telón",
    "tema","tempo","tenue","tierra","tigre","timón","tinte","toque","torno","torre",
    "tramo","trigo","trío","trozo","túnel","turno","único","vapor","vecino","vela",
    "verde","verso","viaje","viejo","villa","viola","virus","vista","vuelo","zafiro",
]


# ──────────────────────────────────────────────
#  Configuración del analizador de URLs
# ──────────────────────────────────────────────
URL_MAX_LENGTH          = 75    # URLs más largas son sospechosas
URL_SUSPICIOUS_TLDS     = {".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".click", ".loan"}
URL_REQUEST_TIMEOUT     = 5     # segundos de timeout para peticiones HTTP
URL_MAX_REDIRECTS       = 5     # máximo de redirecciones a seguir

# Caracteres usados en ataques homógrafos (look-alike unicode)
HOMOGRAPH_CHARS: set[str] = {
    "а","е","о","р","с","х",       # cirílico visualmente idéntico al latino
    "і","ӏ",                        # i con punto, l alternativa
    "ɑ","ɡ","ʟ","ᴏ",               # IPA look-alikes
}

# ──────────────────────────────────────────────
#  Diccionario de subdominios comunes (Subdomain Enum)
# ──────────────────────────────────────────────
COMMON_SUBDOMAINS: list[str] = [
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "web", "cpanel",
    "ns2", "test", "m", "blog", "dev", "server", "ns", "api", "download", "admin",
    "imap", "shop", "forum", "support", "vpn", "db", "app", "help", "secure", "portal",
    "login", "store", "intranet", "cdn", "beta", "gw", "dns", "host", "staging", "api2"
]



# ──────────────────────────────────────────────
#  Configuración del monitor de integridad
# ──────────────────────────────────────────────
INTEGRITY_DB_FILENAME   = ".integrity_baseline.json"
INTEGRITY_HASH_ALGO     = "sha256"
INTEGRITY_IGNORE_EXTS   = {".pyc", ".pyo", ".swp", ".tmp", ".log"}


# ──────────────────────────────────────────────
#  Configuración del cifrador de archivos
# ──────────────────────────────────────────────
ENCRYPTOR_PBKDF2_ITERS  = 600_000   # iteraciones PBKDF2-HMAC-SHA256 (NIST 2023)
ENCRYPTOR_SALT_SIZE     = 16        # bytes de salt aleatorio
ENCRYPTOR_NONCE_SIZE    = 12        # bytes de nonce para AES-GCM
ENCRYPTOR_KEY_SIZE      = 32        # bytes → AES-256
ENCRYPTOR_EXT           = ".enc"    # extensión de archivos cifrados


# ──────────────────────────────────────────────
#  Rangos de entropía de Shannon (bits/byte)
#  Para clasificar archivos en entropy_calc.py
# ──────────────────────────────────────────────
ENTROPY_RANGES: list[tuple[float, float, str, str]] = [
    # (min, max, etiqueta, descripción)
    (0.0, 1.0, "Muy baja",    "Datos muy repetitivos o casi vacíos"),
    (1.0, 3.0, "Baja",        "Texto plano simple o datos estructurados"),
    (3.0, 5.0, "Media",       "Texto en lenguaje natural o código fuente"),
    (5.0, 7.0, "Alta",        "Comprimido, multimedia o datos mixtos"),
    (7.0, 7.9, "Muy alta",    "Probablemente comprimido o cifrado"),
    (7.9, 8.0, "Máxima",      "Casi certeza de datos cifrados o aleatorios"),
]

def classify_entropy(entropy: float) -> tuple[str, str]:
    """Devuelve (etiqueta, descripción) para un valor de entropía."""
    for lo, hi, label, desc in ENTROPY_RANGES:
        if lo <= entropy <= hi:
            return label, desc
    return "Desconocida", ""
