"""
tls_auditor.py — Herramienta 17: Auditor de configuración TLS/SSL
Verifica la validez del certificado, versiones soportadas, y configuraciones básicas
de seguridad (HSTS) en servidores HTTPS.
"""

import sys
import os
import socket
import ssl
import datetime
from urllib.parse import urlparse

# Asegura que el directorio raíz esté en el path al ejecutar directamente
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils import (
    ok, error, warn, info, result,
    section_title, separator, dim, cyan, green, yellow, white, red,
    prompt, pause, validate_hostname, validate_ip
)

try:
    import requests
    _HAS_REQUESTS = True
except ImportError:
    _HAS_REQUESTS = False


def _get_cert_info(hostname: str, port: int = 443) -> dict:
    """Se conecta por SSL y extrae detalles del certificado."""
    context = ssl.create_default_context()
    # Desactivar verificación estricta temporalmente para poder analizar certs auto-firmados
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    cert_data = {}
    try:
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert(binary_form=True)
                
                # Para parsear mejor, usamos ssl.getpeercert pero requiere validación.
                # Como lo desactivamos, lo volvemos a hacer con validación para ver si es de confianza
                pass
                
        # Segunda conexión: verificación estricta para ver la cadena de confianza
        strict_context = ssl.create_default_context()
        try:
            with socket.create_connection((hostname, port), timeout=5) as sock:
                with strict_context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert_dict = ssock.getpeercert()
                    cert_data["trusted"] = True
                    cert_data["dict"] = cert_dict
                    cert_data["version"] = ssock.version()
                    cert_data["cipher"] = ssock.cipher()
        except ssl.SSLError as e:
            cert_data["trusted"] = False
            cert_data["error"] = str(e)
            
            # Obtener datos de todos modos (usando el contexto inseguro)
            with socket.create_connection((hostname, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    # No getpeercert sin verify_mode=CERT_REQUIRED, hay que parsearlo a mano
                    # pero Python no lo pone fácil sin librerías externas como `cryptography`.
                    cert_data["version"] = ssock.version()
                    cert_data["cipher"] = ssock.cipher()
                    
                    # Intentaremos importar cryptography si está
                    try:
                        from cryptography import x509
                        from cryptography.hazmat.backends import default_backend
                        der_cert = ssock.getpeercert(binary_form=True)
                        cert_obj = x509.load_der_x509_certificate(der_cert, default_backend())
                        cert_data["not_after"] = cert_obj.not_valid_after
                        cert_data["not_before"] = cert_obj.not_valid_before
                        cert_data["issuer"] = cert_obj.issuer.rfc4514_string()
                        cert_data["subject"] = cert_obj.subject.rfc4514_string()
                    except ImportError:
                        cert_data["crypto_missing"] = True
                    
    except Exception as e:
        cert_data["fatal"] = str(e)
        
    return cert_data


def _check_hsts(hostname: str) -> bool:
    """Verifica si el servidor envía la cabecera Strict-Transport-Security."""
    if not _HAS_REQUESTS:
        return False
    try:
        url = f"https://{hostname}"
        resp = requests.head(url, timeout=5, verify=False)
        return "strict-transport-security" in (k.lower() for k in resp.headers.keys())
    except Exception:
        return False


def _mode_audit() -> None:
    section_title("AUDITOR TLS / SSL")

    target = prompt("Dominio o IP objetivo (ej. example.com)").strip().lower()
    if not target:
        warn("No se ingresó objetivo.")
        return

    # Limpiar URL si el usuario pegó http://...
    if target.startswith("http"):
        parsed = urlparse(target)
        target = parsed.netloc or parsed.path

    # Quitar puerto si lo puso
    port = 443
    if ":" in target:
        parts = target.split(":")
        target = parts[0]
        try:
            port = int(parts[1])
        except ValueError:
            pass

    if not validate_hostname(target) and not validate_ip(target):
        error("Formato de host inválido.")
        return

    info(f"Conectando a {cyan(target)} en el puerto {port}...")
    
    cert_info = _get_cert_info(target, port)
    
    if "fatal" in cert_info:
        error(f"No se pudo conectar o negociar SSL/TLS: {cert_info['fatal']}")
        return

    print()
    separator("═", 70)
    print(f"  {white('RESULTADOS DE LA AUDITORÍA TLS')}")
    separator("─", 70)

    # 1. Protocolo y Cipher
    version = cert_info.get("version", "Desconocida")
    cipher = cert_info.get("cipher", ("Desconocido",))
    
    # Análisis de versión
    if version in ["SSLv2", "SSLv3", "TLSv1", "TLSv1.1"]:
        ver_color = red
        ver_warn = " ⚠ OBSOLETO / INSEGURO"
    elif version == "TLSv1.2":
        ver_color = yellow
        ver_warn = " (Aceptable)"
    else:
        ver_color = green
        ver_warn = " ✓ Seguro"
        
    result("Protocolo negociado", ver_color(version) + ver_warn)
    if cipher:
        result("Cipher Suite", cyan(cipher[0]))
    separator("─", 70)

    # 2. Confianza del Certificado
    trusted = cert_info.get("trusted", False)
    if trusted:
        result("Confianza", green("✓ Válido y confiable (Firmado por CA)"))
    else:
        err = cert_info.get("error", "Error desconocido")
        result("Confianza", red(f"⚠ NO CONFIABLE: {err}"))
        
    # 3. Fechas y Subject
    if "dict" in cert_info:
        c_dict = cert_info["dict"]
        # Python ssl parsing
        not_after_str = c_dict.get("notAfter", "")
        # Formato: 'May  3 23:59:59 2024 GMT'
        try:
            expiry = datetime.datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
            days_left = (expiry - datetime.datetime.utcnow()).days
            
            if days_left < 0:
                result("Vencimiento", red(f"CADUCADO hace {abs(days_left)} días"))
            elif days_left < 30:
                result("Vencimiento", yellow(f"Expira pronto ({days_left} días)"))
            else:
                result("Vencimiento", green(f"Válido por {days_left} días más"))
        except:
            result("Vencimiento", dim(not_after_str))
            
        subject = dict(x[0] for x in c_dict.get('subject', []))
        issuer = dict(x[0] for x in c_dict.get('issuer', []))
        
        result("Emitido para", subject.get('commonName', 'Desconocido'))
        result("Emitido por (CA)", issuer.get('commonName', issuer.get('organizationName', 'Desconocido')))
        
    elif "crypto_missing" not in cert_info and "not_after" in cert_info:
        # Extraído vía cryptography
        expiry = cert_info["not_after"]
        days_left = (expiry - datetime.datetime.utcnow()).days
        
        if days_left < 0:
            result("Vencimiento", red(f"CADUCADO hace {abs(days_left)} días"))
        elif days_left < 30:
            result("Vencimiento", yellow(f"Expira pronto ({days_left} días)"))
        else:
            result("Vencimiento", green(f"Válido por {days_left} días más"))
            
        result("Emitido para", dim(cert_info.get("subject", "")))
        result("Emitido por (CA)", dim(cert_info.get("issuer", "")))

    separator("─", 70)

    # 4. HSTS
    import urllib3
    urllib3.disable_warnings()
    hsts = _check_hsts(target)
    if hsts:
        result("Seguridad Web", green("✓ HSTS Activo (Strict-Transport-Security)"))
    else:
        result("Seguridad Web", yellow("⚠ HSTS No detectado (Susceptible a SSL Stripping)"))

    separator("─", 70)
    print()


def _mode_explain() -> None:
    section_title("¿CÓMO FUNCIONA EL PROTOCOLO TLS/SSL?")

    print(f"""
  {white('1. ¿Qué es TLS?')}
  {dim('─' * 56)}
  Transport Layer Security (TLS), antes llamado SSL, es el protocolo criptográfico
  que proporciona comunicaciones seguras por una red (el "s" en HTTPS).

  {white('2. Versiones Obsoletas')}
  {dim('─' * 56)}
  SSLv2, SSLv3, TLS 1.0 y TLS 1.1 están {red('oficialmente deprecados')} y son 
  vulnerables a ataques (POODLE, BEAST). Hoy en día solo deben usarse 
  {green('TLS 1.2 o TLS 1.3')}.

  {white('3. Cipher Suites Débiles')}
  {dim('─' * 56)}
  El "Cipher" es el conjunto de algoritmos negociados (Ej: AES_256_GCM).
  Si el servidor acepta cifrados basados en RC4, 3DES o nulo, los atacantes
  pueden romper el cifrado y leer el tráfico.

  {white('4. Cadena de Confianza y CA')}
  {dim('─' * 56)}
  Tu navegador confía en un certificado si está firmado por una 
  Autoridad Certificadora (CA) de confianza (como Let's Encrypt o DigiCert).
  Si el atacante intercepta tu conexión y presenta su propio certificado 
  (Auto-firmado), verás un {red('error de advertencia')} en el navegador.

  {white('5. HSTS (Strict-Transport-Security)')}
  {dim('─' * 56)}
  Es una cabecera que obliga al navegador a usar siempre HTTPS.
  Previene el ataque {yellow('SSL Stripping')}, donde el atacante te fuerza a 
  navegar por HTTP (sin cifrar).
    """)


# ──────────────────────────────────────────────
#  Submenú
# ──────────────────────────────────────────────
_SUBMENU = [
    ("1", "Ejecutar auditoría TLS",               _mode_audit),
    ("2", "¿Qué es TLS y qué ataques existen?",   _mode_explain),
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
        section_title("HERRAMIENTA 17 — AUDITOR TLS/SSL")
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
