"""
subdomain_enum.py — Herramienta 11: Enumerador de Subdominios
Descubrimiento de subdominios mediante resolución DNS masiva y Certificate Transparency Logs.
"""

import socket
import sys
import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

# Asegura que el directorio raíz esté en el path al ejecutar directamente
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils import (
    ok, error, warn, info, result,
    section_title, separator, dim, cyan, green, yellow, white, red,
    prompt, ask_yes_no, pause
)
from config import COMMON_SUBDOMAINS

try:
    import requests
    _HAS_REQUESTS = True
except ImportError:
    _HAS_REQUESTS = False


def _resolve_subdomain(sub: str, domain: str) -> tuple[str, str | None, str | None]:
    """
    Intenta resolver un subdominio.
    Devuelve (subdominio_completo, IP, CNAME).
    """
    full_domain = f"{sub}.{domain}"
    try:
        # Intentar obtener la IP
        ip = socket.gethostbyname(full_domain)
        
        # Intentar obtener el CNAME (si es posible)
        # socket estándar no da cname fácilmente sin pedir el fqdn completo,
        # pero gethostbyname_ex puede dar aliases
        _, aliases, _ = socket.gethostbyname_ex(full_domain)
        cname = aliases[0] if aliases else None
        
        return full_domain, ip, cname
    except socket.gaierror:
        return full_domain, None, None


def _check_wildcard(domain: str) -> str | None:
    """Verifica si el dominio tiene un registro wildcard DNS (catch-all)."""
    random_sub = "this-sub-should-not-exist-12345"
    _, ip, _ = _resolve_subdomain(random_sub, domain)
    return ip


def _crt_sh_lookup(domain: str) -> set[str]:
    """
    Busca subdominios en Certificate Transparency Logs usando crt.sh.
    """
    subdomains = set()
    if not _HAS_REQUESTS:
        warn("Módulo 'requests' no instalado. Se omite la búsqueda en crt.sh.")
        return subdomains

    info("Consultando Certificate Transparency Logs (crt.sh)...")
    try:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        # crt.sh puede ser lento o devolver 502/504
        resp = requests.get(url, timeout=15)
        if resp.status_code == 200:
            data = resp.json()
            for entry in data:
                name_value = entry.get("name_value", "")
                # name_value puede tener saltos de línea y múltiples dominios
                for name in name_value.split('\n'):
                    name = name.strip().lower()
                    if name.endswith(domain) and name != domain and not name.startswith("*"):
                        subdomains.add(name)
        else:
            warn(f"crt.sh respondió con código {resp.status_code}")
    except Exception as e:
        warn(f"Error al consultar crt.sh: {e}")

    return subdomains


def _mode_enum() -> None:
    section_title("ENUMERADOR DE SUBDOMINIOS")

    domain = prompt("Dominio objetivo (ej. example.com)").strip().lower()
    if not domain:
        warn("Dominio no ingresado.")
        return

    # Validar formato de dominio muy básico
    if "." not in domain or " " in domain:
        error("Formato de dominio inválido.")
        return

    # Verificar Wildcard
    info("Verificando resolución wildcard...")
    wildcard_ip = _check_wildcard(domain)
    if wildcard_ip:
        warn(f"¡Atención! El dominio parece tener un registro wildcard (*.{domain} -> {wildcard_ip}).")
        warn("Los resultados de fuerza bruta pueden contener falsos positivos.")
        if not ask_yes_no("¿Continuar de todos modos?", default=False):
            return
    else:
        info(f"{green('✓')} No se detectó resolución wildcard.")

    print()
    use_brute = ask_yes_no("¿Realizar fuerza bruta con diccionario común?", default=True)
    use_crt = ask_yes_no("¿Buscar en Certificate Transparency Logs (crt.sh)?", default=True)

    found_subs = set()
    results = [] # list of (subdomain, ip, cname)

    # 1. CT Logs
    if use_crt:
        crt_subs = _crt_sh_lookup(domain)
        if crt_subs:
            info(f"crt.sh devolvió {len(crt_subs)} subdominio(s) único(s).")
            # Resolviendo los encontrados para confirmar si están vivos
            info("Resolviendo subdominios encontrados en crt.sh...")
            for sub_full in crt_subs:
                prefix = sub_full.replace(f".{domain}", "")
                if prefix not in found_subs:
                    _, ip, cname = _resolve_subdomain(prefix, domain)
                    if ip:
                        found_subs.add(prefix)
                        results.append((sub_full, ip, cname))
        else:
            info("No se encontraron subdominios en crt.sh o falló la consulta.")

    # 2. Fuerza bruta
    if use_brute:
        subs_to_check = [s for s in COMMON_SUBDOMAINS if s not in found_subs]
        total = len(subs_to_check)
        if total > 0:
            print()
            info(f"Iniciando fuerza bruta: {total} subdominios comunes...")
            done = 0
            with ThreadPoolExecutor(max_workers=20) as executor:
                futures = {executor.submit(_resolve_subdomain, sub, domain): sub for sub in subs_to_check}
                for future in as_completed(futures):
                    done += 1
                    sub_full, ip, cname = future.result()
                    # Progress bar
                    pct = done / total * 100
                    print(f"\r  {dim(f'[{done}/{total}] {pct:5.1f}%')} Analizando...", end="", flush=True)
                    
                    if ip:
                        # Limpiar línea
                        print("\r" + " " * 40 + "\r", end="", flush=True)
                        print(f"  {green('✓')} {white(sub_full):<30} {cyan(ip)}")
                        found_subs.add(sub_full)
                        results.append((sub_full, ip, cname))
            print()

    # — Resumen —
    print()
    separator("═", 70)
    print(f"  {white('RESULTADOS DE LA ENUMERACIÓN')}")
    separator("─", 70)
    
    if not results:
        warn("No se encontraron subdominios activos.")
    else:
        print(f"  {'Subdominio':<35} {'IP':<15} {'CNAME (Alias)'}")
        separator("─", 70)
        for sub_full, ip, cname in sorted(results, key=lambda x: x[0]):
            cname_str = dim(cname) if cname and cname != ip else ""
            print(f"  {white(sub_full):<35} {cyan(ip):<15} {cname_str}")
            
            # Detectar posible Subdomain Takeover básico
            if cname and any(x in cname for x in ["github.io", "herokuapp.com", "s3.amazonaws.com", "azurewebsites.net"]):
                print(f"  {red('  ↳ ⚠ Posible riesgo de Subdomain Takeover: apunta a servicio externo')}")

    separator("─", 70)
    result("Total encontrados", str(len(results)))
    print()


def _mode_explain() -> None:
    section_title("¿CÓMO FUNCIONA LA ENUMERACIÓN DE SUBDOMINIOS?")

    print(f"""
  {white('1. Certificate Transparency (CT Logs)')}
  {dim('─' * 56)}
  Es un registro público y verificable de todos los certificados TLS emitidos.
  Sitios como {cyan('crt.sh')} permiten consultar qué certificados existen para un dominio.
  {green('Ventaja:')} Es pasivo (el objetivo no detecta la consulta) y muy exhaustivo.
  {red('Desventaja:')} Puede revelar subdominios antiguos que ya no existen.

  {white('2. Fuerza Bruta DNS')}
  {dim('─' * 56)}
  Consiste en probar una lista de palabras comunes (www, mail, test, dev...)
  preguntándole al servidor DNS si existen.
  {green('Ventaja:')} Encuentra subdominios internos o sin HTTPS.
  {red('Desventaja:')} Es ruidoso, puede ser detectado y bloqueado por firewalls.

  {white('3. Registros Wildcard (*)')}
  {dim('─' * 56)}
  Algunos dominios están configurados para que CUALQUIER subdominio resuelva
  a una IP específica (ej: *.dominio.com -> 1.2.3.4).
  Esto engaña a los escáneres de fuerza bruta haciéndoles creer que todo existe.

  {white('4. Subdomain Takeover')}
  {dim('─' * 56)}
  Ocurre cuando un subdominio apunta (vía CNAME) a un servicio de terceros
  (como GitHub Pages, Heroku, AWS S3) pero la cuenta en ese servicio fue borrada.
  Un atacante puede registrar ese nombre en el servicio y {red('tomar el control')}
  del subdominio de la víctima.
    """)


# ──────────────────────────────────────────────
#  Submenú
# ──────────────────────────────────────────────
_SUBMENU = [
    ("1", "Ejecutar enumeración de subdominios",   _mode_enum),
    ("2", "¿Qué es y cómo funciona?",             _mode_explain),
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
        section_title("HERRAMIENTA 11 — ENUMERADOR DE SUBDOMINIOS")
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
