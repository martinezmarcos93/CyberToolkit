"""
main.py — Punto de entrada de CyberToolkit
Menú interactivo principal con todas las herramientas disponibles.
Ctrl+C en cualquier herramienta vuelve al menú sin cerrar el programa.
"""

import os
import sys
import argparse
from config import SETTINGS


# ──────────────────────────────────────────────
#  Verificar Python 3.10+
# ──────────────────────────────────────────────
if sys.version_info < (3, 10):
    print("[✗ ERROR] CyberToolkit requiere Python 3.10 o superior.")
    print(f"          Versión detectada: {sys.version}")
    sys.exit(1)


# ──────────────────────────────────────────────
#  Imports de utilidades y herramientas
# ──────────────────────────────────────────────
from utils import (
    print_banner, print_menu,
    ok, error, warn, info,
    separator, dim, cyan, red, white, yellow,
    prompt, pause,
)


def _import_tools() -> dict[str, object]:
    """
    Importa todas las herramientas disponibles.
    Las que aún no están implementadas devuelven un placeholder.
    """
    tools = {}

    def _try_import(key: str, module_path: str, tool_name: str):
        try:
            import importlib
            mod = importlib.import_module(module_path)
            tools[key] = mod.run
        except ImportError as e:
            def _placeholder(name=tool_name, err=str(e)):
                print()
                warn(f"'{name}' aún no está disponible en esta versión.")
                info(f"Dependencia faltante: {err}")
                info("Revisá el README.md para ver el roadmap de implementación.")
            tools[key] = _placeholder

    _try_import("1", "tools.port_scanner",       "Escáner de puertos TCP")
    _try_import("2", "tools.password_checker",   "Verificador de contraseñas")
    _try_import("3", "tools.hash_tool",          "Generador / verificador de hashes")
    _try_import("4", "tools.url_analyzer",       "Analizador de URLs sospechosas")
    _try_import("5", "tools.file_integrity",     "Monitor de integridad de archivos")
    _try_import("6", "tools.packet_sniffer",     "Sniffer básico de paquetes")
    _try_import("7", "tools.file_encryptor",     "Cifrador / descifrador AES-256")
    _try_import("8", "tools.metadata_extractor", "Extractor de metadatos")
    _try_import("9", "tools.password_generator", "Generador de contraseñas seguras")
    _try_import("10", "tools.entropy_calc",       "Calculadora de entropía de archivos")
    _try_import("11", "tools.subdomain_enum",     "Enumerador de subdominios")
    _try_import("12", "tools.banner_grabber",     "Grabber de banners de servicios")
    _try_import("13", "tools.whois_osint",        "OSINT sobre dominios e IPs")
    _try_import("14", "tools.wifi_scanner",       "Escáner de redes Wi-Fi")
    _try_import("15", "tools.hash_cracker",       "Crackeador de hashes")
    _try_import("16", "tools.jwt_analyzer",       "Analizador y manipulador de JWT")
    _try_import("17", "tools.tls_auditor",        "Auditor de configuración TLS/SSL")
    _try_import("18", "tools.steganography",      "Esteganografía en imágenes (LSB)")
    _try_import("19", "tools.pcap_analyzer",      "Analizador de capturas PCAP")
    _try_import("20", "tools.arp_monitor",        "Detector de ARP Spoofing")
    _try_import("21", "tools.dns_analyzer",       "Analizador avanzado de DNS")
    _try_import("22", "tools.ids_lite",           "Sistema de detección de intrusiones ligero")
    _try_import("23", "tools.honeypot",           "Honeypot de servicios TCP")
    _try_import("24", "tools.log_analyzer",       "Analizador de logs de seguridad")
    _try_import("25", "tools.vuln_scanner",       "Escáner de vulnerabilidades básico")
    _try_import("26", "tools.firewall_tester",    "Tester de reglas de firewall")
    _try_import("27", "tools.web_crawler",        "Crawler de aplicaciones web")
    _try_import("28", "tools.sqli_detector",      "Detector de Inyección SQL")
    _try_import("29", "tools.xss_scanner",        "Escáner de Cross-Site Scripting (XSS)")
    _try_import("30", "tools.cors_auditor",       "Auditor de políticas CORS")
    _try_import("31", "tools.disk_forensics",     "Análisis forense de imágenes de disco")
    _try_import("32", "tools.memory_analyzer",    "Análisis básico de volcados de memoria (RAM)")
    _try_import("33", "tools.timeline_builder",   "Constructor de línea de tiempo forense")
    _try_import("34", "tools.threat_intel",       "Consultas a fuentes de Threat Intelligence")
    _try_import("35", "tools.c2_detector",        "Detector de comunicaciones C2")
    _try_import("36", "tools.report_generator",   "Generador de reportes de seguridad")

    return tools


# ──────────────────────────────────────────────
#  Aviso legal al arrancar
# ──────────────────────────────────────────────
def _print_legal_notice() -> None:
    """Muestra el aviso ético una sola vez al iniciar."""
    print()
    separator("═", 60)
    print(f"  {yellow('⚠  AVISO LEGAL Y ÉTICO')}")
    separator("─", 60)
    print(f"""
  Este software es {white('exclusivamente educativo')}.
  Úsalo solo en {white('entornos propios y controlados')}.

  El uso no autorizado sobre sistemas ajenos {red('es ilegal')}
  y puede acarrear consecuencias civiles y penales.

  Al continuar, aceptás usar esta herramienta de forma ética.
    """)
    separator("═", 60)
    input(f"  {dim('Presioná Enter para continuar...')}")


# ──────────────────────────────────────────────
#  Estado de las herramientas (fase de desarrollo)
# ──────────────────────────────────────────────
TOOL_STATUS = {
    "1": "✅",   # Fase 2 — implementada
    "2": "✅",   # Fase 1 — implementada
    "3": "✅",   # Fase 1 — implementada
    "4": "✅",   # Fase 2 — implementada
    "5": "✅",   # Fase 2 — implementada
    "6": "✅",   # Fase 3 — implementada
    "7": "✅",   # Fase 3 — implementada
    "8": "✅",   # Fase 2 — implementada
    "9": "✅",   # Fase 1 — implementada
    "10": "✅",  # Fase 1 — implementada
    "11": "✅",  # Fase 2 — implementada
    "12": "✅",  # Fase 2 — implementada
    "13": "✅",  # Fase 2 — implementada
    "14": "✅",  # Fase 2 — implementada
    "15": "✅",  # Fase 2.1 — implementada
    "16": "✅",  # Fase 2.1 — implementada
    "17": "✅",  # Fase 2.1 — implementada
    "18": "✅",  # Fase 2.1 — implementada
    "19": "✅",  # Fase 2.2 — implementada
    "20": "✅",  # Fase 2.2 — implementada
    "21": "✅",  # Fase 2.2 — implementada
    "22": "✅",  # Fase 3.0 — implementada
    "23": "✅",  # Fase 3.0 — implementada
    "24": "✅",  # Fase 3.0 — implementada
    "25": "✅",  # Fase 3.0 — implementada
    "26": "✅",  # Fase 3.0 — implementada
    "27": "✅",  # Fase 3.1 — implementada
    "28": "✅",  # Fase 3.1 — implementada
    "29": "✅",  # Fase 3.1 — implementada
    "30": "✅",  # Fase 3.1 — implementada
    "31": "✅",  # Fase 3.2 — implementada
    "32": "✅",  # Fase 3.2 — implementada
    "33": "✅",  # Fase 3.2 — implementada
    "34": "✅",  # Fase 4.0 — implementada
    "35": "✅",  # Fase 4.0 — implementada
    "36": "✅",  # Fase 4.0 — implementada
}

TOOL_NAMES = {
    "1": "Escáner de puertos TCP",
    "2": "Verificador de contraseñas",
    "3": "Generador / verificador de hashes",
    "4": "Analizador de URLs sospechosas",
    "5": "Monitor de integridad de archivos",
    "6": "Sniffer básico de paquetes",
    "7": "Cifrador / descifrador AES-256",
    "8": "Extractor de metadatos",
    "9": "Generador de contraseñas seguras",
    "10": "Calculadora de entropía de archivos",
    "11": "Enumerador de subdominios",
    "12": "Grabber de banners de servicios",
    "13": "OSINT sobre dominios e IPs",
    "14": "Escáner de redes Wi-Fi",
    "15": "Crackeador de hashes",
    "16": "Analizador y manipulador de JWT",
    "17": "Auditor de configuración TLS/SSL",
    "18": "Esteganografía en imágenes (LSB)",
    "19": "Analizador de capturas PCAP",
    "20": "Detector de ARP Spoofing",
    "21": "Analizador avanzado de DNS",
    "22": "Sistema de detección de intrusiones ligero",
    "23": "Honeypot de servicios TCP",
    "24": "Analizador de logs de seguridad",
    "25": "Escáner de vulnerabilidades básico",
    "26": "Tester de reglas de firewall",
    "27": "Crawler de aplicaciones web",
    "28": "Detector de Inyección SQL",
    "29": "Escáner de Cross-Site Scripting (XSS)",
    "30": "Auditor de políticas CORS",
    "31": "Análisis forense de imágenes de disco",
    "32": "Análisis básico de volcados de memoria (RAM)",
    "33": "Constructor de línea de tiempo forense",
    "34": "Consultas a fuentes de Threat Intelligence",
    "35": "Detector de comunicaciones C2",
    "36": "Generador de reportes de seguridad",
}


def _print_full_menu() -> None:
    """Menú enriquecido con estado de implementación."""
    AREAS = {
        "1": "Red / Reconocimiento",
        "2": "Políticas / Entropía",
        "3": "Integridad / Forense",
        "4": "Phishing / OSINT",
        "5": "HIDS / Persistencia",
        "6": "Red / TCP-IP  [root]",
        "7": "Criptografía simétrica",
        "8": "Forense / Privacidad",
        "9": "Aleatoriedad / Secrets",
        "10": "Malware / Estadística",
        "11": "OSINT / Reconocimiento",
        "12": "OSINT / Reconocimiento",
        "13": "Phishing / OSINT",
        "14": "Red / Reconocimiento",
        "15": "Criptoanálisis",
        "16": "Criptoanálisis",
        "17": "Red / Reconocimiento",
        "18": "Forense / Privacidad",
        "19": "Red / TCP-IP",
        "20": "Red / TCP-IP",
        "21": "Red / TCP-IP",
        "22": "Blue Team / Defensa",
        "23": "Blue Team / Defensa",
        "24": "Blue Team / Defensa",
        "25": "Blue Team / Defensa",
        "26": "Red / TCP-IP",
        "27": "Web / Aplicación",
        "28": "Web / Aplicación",
        "29": "Web / Aplicación",
        "30": "Web / Aplicación",
        "31": "Forense / DFIR",
        "32": "Forense / DFIR",
        "33": "Forense / DFIR",
        "34": "Threat Intel",
        "35": "Red / TCP-IP",
        "36": "Reporting / Gestión",
    }

    print()
    print(f"  {white('HERRAMIENTAS DISPONIBLES')}")
    separator("─", 64)
    print(f"  {'#':<5} {'Est':<4} {'Herramienta':<36} {'Área'}")
    separator("─", 64)

    for key in ["1","2","3","4","5","6","7","8","9","10","11","12","13","14","15","16","17","18","19","20","21","22","23","24","25","26","27","28","29","30","31","32","33","34","35","36"]:
        num_fmt  = cyan(f"[{key}]")
        status   = TOOL_STATUS[key]
        name_fmt = white(TOOL_NAMES[key]) if status == "✅" else dim(TOOL_NAMES[key])
        area_fmt = dim(AREAS[key])
        print(f"  {num_fmt:<5} {status:<4} {name_fmt:<36} {area_fmt}")

    separator("─", 64)
    print(f"  {red('[Q]')}       Salir de CyberToolkit")
    separator("═", 64)
    print(f"  {dim('✅ = disponible  · 🔜 = próximamente')}")
    separator("═", 64)


# ──────────────────────────────────────────────
#  Bucle principal del menú
# ──────────────────────────────────────────────
def parse_args():
    parser = argparse.ArgumentParser(description="CyberToolkit - Modo Batch")
    parser.add_argument("--tool", type=str, help="Número de herramienta para ejecutar directamente")
    parser.add_argument("--batch", type=str, help="Archivo de entrada batch (.txt) con objetivos")
    parser.add_argument("--export", type=str, choices=["txt", "json", "html"], help="Formato de exportación")
    return parser.parse_args()

def main() -> None:
    args = parse_args()
    if args.export:
        SETTINGS["export_format"] = args.export
    if args.batch:
        SETTINGS["batch_file"] = args.batch

    # Cargar herramientas
    tools = _import_tools()
    available = {k for k, v in TOOL_STATUS.items() if v == "✅"}

    # Si se pasa un tool específico por CLI, se ejecuta sin menú
    if args.tool:
        choice = str(args.tool)
        if choice in tools and choice in available:
            try:
                tools[choice]()
            except KeyboardInterrupt:
                pass
            except Exception as e:
                error(f"Error ejecutando herramienta {choice}: {e}")
        else:
            error(f"Herramienta {choice} no disponible.")
        return

    # Mostrar banner y aviso legal una sola vez (modo interactivo)
    print_banner()
    _print_legal_notice()

    while True:
        # Redibujar el menú completo en cada iteración
        print_banner()
        _print_full_menu()

        try:
            choice = prompt("Seleccioná una herramienta").strip().lower()
        except (EOFError, KeyboardInterrupt):
            choice = "q"

        # Salir
        if choice in ("q", "quit", "exit", "salir"):
            print()
            ok("Saliendo de CyberToolkit. ¡Hasta la próxima!")
            print()
            break

        # Opción válida
        if choice in tools:
            if choice not in available:
                print()
                warn(f"'{TOOL_NAMES[choice]}' aún no está implementada.")
                info("Revisá el roadmap en README.md para ver cuándo estará disponible.")
                pause()
                continue

            # Ejecutar la herramienta con protección Ctrl+C
            print_banner()
            try:
                tools[choice]()
            except KeyboardInterrupt:
                print()
                warn("Operación interrumpida. Volviendo al menú principal.")
            except Exception as e:
                print()
                error(f"Error inesperado en la herramienta: {e}")
                warn("Si el error persiste, revisá las dependencias con: pip install -r requirements.txt")

            pause()

        elif choice == "":
            # Enter en blanco: simplemente redibuja el menú
            continue

        else:
            print()
            error(f"Opción '{choice}' no válida. Ingresá un número del menú o Q para salir.")
            pause()


# ──────────────────────────────────────────────
#  Entry point
# ──────────────────────────────────────────────
if __name__ == "__main__":
    main()
