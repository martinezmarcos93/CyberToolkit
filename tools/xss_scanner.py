"""
xss_scanner.py — Herramienta 29: Escáner de Cross-Site Scripting (XSS)
Inyecta payloads XSS en parámetros GET para detectar si la entrada
del usuario se refleja de forma insegura (Reflected XSS).
"""

import sys
import os
import urllib.parse

# Asegura que el directorio raíz esté en el path al ejecutar directamente
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils import (
    ok, error, warn, info, result,
    section_title, separator, dim, cyan, green, yellow, white, red, magenta,
    prompt, pause
)

try:
    import requests
    _HAS_REQ = True
except ImportError:
    _HAS_REQ = False


# Payloads básicos para pruebas de reflexión
_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "\"><script>prompt(1)</script>",
    "<img src=x onerror=alert(1)>",
    "javascript:alert(1)//"
]


def _check_security_headers(headers: dict) -> list:
    """Revisa si existen cabeceras que mitigan XSS."""
    missing = []
    
    # CSP es la defensa principal moderna contra XSS
    if "Content-Security-Policy" not in headers:
        missing.append("Falta Content-Security-Policy (CSP)")
        
    # X-XSS-Protection (Legacy pero a veces útil)
    if "X-XSS-Protection" not in headers:
        pass # Es legacy, no alertamos muy fuerte
        
    # HttpOnly en cookies (Mitiga robo de sesión si hay XSS)
    # Solo lo marcamos si vemos Set-Cookie sin HttpOnly
    if "Set-Cookie" in headers:
        if "HttpOnly" not in headers["Set-Cookie"]:
            missing.append("Cookie sin flag HttpOnly")
            
    return missing


def _scan_xss(target_url: str) -> None:
    if not target_url.startswith(("http://", "https://")):
        target_url = "http://" + target_url

    parsed_url = urllib.parse.urlparse(target_url)
    base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
    
    query_params = urllib.parse.parse_qs(parsed_url.query)
    params = {k: v[0] for k, v in query_params.items()}

    if not params:
        error("La URL no contiene parámetros GET (ej: ?q=buscar).")
        warn("XSS Reflejado se prueba inyectando en parámetros de entrada.")
        return

    info(f"Escaneando objetivo: {cyan(base_url)}")
    info(f"Parámetros detectados: {white(str(list(params.keys())))}")
    separator("─", 60)

    req_headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) CyberToolkit XSS/1.0"
    }

    # 1. Chequeo rápido de cabeceras de seguridad
    print(f"  {dim('Analizando cabeceras HTTP de seguridad...')}")
    try:
        res_head = requests.get(base_url, headers=req_headers, timeout=5)
        missing_headers = _check_security_headers(res_head.headers)
        for h in missing_headers:
            print(f"  {yellow('⚠ Advertencia:')} {h}")
    except requests.RequestException:
        error("No se pudo conectar al servidor.")
        return

    print()
    print(f"  {dim('Probando inyección de payloads...')}")
    separator("-", 60)

    findings = []

    # 2. Inyección y comprobación de reflexión
    for param_name in params.keys():
        for payload in _PAYLOADS:
            test_params = params.copy()
            # Reemplazamos el valor original por el payload
            test_params[param_name] = payload
            
            try:
                print(f"\r  {dim('Inyectando en')} {param_name}: {payload[:20]}..." + " "*20, end="")
                
                # Deshabilitamos la redirección automática para ver qué pasa en el primer paso
                res = requests.get(base_url, params=test_params, headers=req_headers, timeout=5, allow_redirects=True)
                
                # Verificamos si el payload está exactamente igual en la respuesta (Reflejado)
                # Si estuviera sanitizado sería &lt;script&gt;
                if payload in res.text:
                    findings.append((param_name, payload))
                    break # Si ya es vulnerable con uno, saltamos al siguiente parámetro
                    
            except requests.RequestException:
                continue

    # Limpiar consola
    print("\r" + " "*70 + "\r", end="")
    print()
    
    separator("═", 75)
    print(f"  {white('RESULTADOS DEL ESCÁNER XSS')}")
    separator("─", 75)

    if findings:
        for param, payload in findings:
            print(f"  {red('⚠ VULNERABLE:')} Parámetro {yellow(param)}")
            print(f"  {white('Reflexión:')} El payload se reflejó en el HTML sin sanitizar.")
            print(f"  {white('Payload:')}   {cyan(payload)}")
            print(f"  {dim('-'*60)}")
        print()
        warn("¡XSS Reflejado detectado! Un atacante podría robar cookies o ")
        warn("ejecutar acciones en nombre de un usuario si hace clic en el enlace.")
    else:
        print(f"  {green('✓')} No se detectó Cross-Site Scripting. La entrada parece sanitizada.")
        
    print()


def _mode_run() -> None:
    section_title("ESCÁNER DE CROSS-SITE SCRIPTING (XSS)")
    
    if not _HAS_REQ:
        error("Faltan librerías. Ejecutá: pip install requests")
        return

    warn("ATENCIÓN: Realiza pruebas intrusivas. Úsalo SOLO con autorización.")
    target = prompt("URL a escanear (Ej. http://site.com/search?q=test)").strip()
    
    if target:
        _scan_xss(target)


def _mode_explain() -> None:
    section_title("¿QUÉ ES CROSS-SITE SCRIPTING (XSS)?")

    print(f"""
  {white('1. El problema (Confianza en el Input)')}
  {dim('─' * 56)}
  Ocurre cuando una web toma la entrada del usuario y la muestra en pantalla
  sin limpiarla. Ej: Si buscás "Zapatos", la web dice "Resultados para Zapatos".
  Pero si buscás {cyan('<script>alert(1)</script>')}, el navegador lo interpreta
  como código ejecutable.

  {white('2. Tipos de XSS')}
  {dim('─' * 56)}
  {dim('·')} {yellow('Reflejado (Reflected):')} El payload va en la URL. El atacante debe
    engañar a la víctima para que haga clic en un enlace malicioso.
  {dim('·')} {red('Almacenado (Stored):')} El payload se guarda en la DB (ej. un 
    comentario en un foro). Cualquiera que vea el comentario es atacado.
  {dim('·')} {magenta('DOM-Based:')} La inyección ocurre en el lado del cliente (JavaScript)
    sin que el servidor intervenga.

  {white('3. Mitigación')}
  {dim('─' * 56)}
  {dim('·')} {green('Sanitización/Encoding:')} Convertir `<` en `&lt;`.
  {dim('·')} {green('Content-Security-Policy (CSP):')} Una cabecera que le prohíbe al 
    navegador ejecutar scripts que no provengan del propio servidor.
    """)


# ──────────────────────────────────────────────
#  Submenú
# ──────────────────────────────────────────────
_SUBMENU = [
    ("1", "Escanear URL (XSS)",                   _mode_run),
    ("2", "¿Qué es Cross-Site Scripting?",        _mode_explain),
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
        section_title("HERRAMIENTA 29 — ESCÁNER XSS")
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
