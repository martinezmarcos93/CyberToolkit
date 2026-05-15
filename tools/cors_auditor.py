"""
cors_auditor.py — Herramienta 30: Auditor de Políticas CORS
Analiza la configuración de Cross-Origin Resource Sharing (CORS) 
para detectar misconfiguraciones que permitan acceso no autorizado.
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


def _check_cors(target_url: str) -> None:
    if not target_url.startswith(("http://", "https://")):
        target_url = "http://" + target_url

    info(f"Auditando políticas CORS en: {cyan(target_url)}")
    separator("─", 60)
    
    # Orígenes maliciosos de prueba
    test_origins = [
        "https://evil.com",          # Origen arbitrario
        "null",                      # Origen nulo (A veces permitido por error)
        target_url + ".evil.com",    # Subdominio no validado correctamente
    ]

    findings = []
    
    for origin in test_origins:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) CyberToolkit CORS/1.0",
            "Origin": origin
        }
        
        try:
            print(f"  {dim('Probando Origin:')} {white(origin):<30} ", end="", flush=True)
            res = requests.options(target_url, headers=headers, timeout=5)
            
            # Si OPTIONS no está soportado o devuelve 405, probamos con GET
            if res.status_code >= 400:
                res = requests.get(target_url, headers=headers, timeout=5)
                
            acao = res.headers.get("Access-Control-Allow-Origin", "No configurado")
            acac = res.headers.get("Access-Control-Allow-Credentials", "false")
            
            print(f"-> ACAO: {cyan(acao)}")
            
            # Análisis de vulnerabilidades
            is_vuln = False
            vuln_desc = ""
            
            if acao == "*":
                if acac.lower() == "true":
                    is_vuln = True
                    vuln_desc = "Permite origen '*' CON credenciales (Misconfig Crítica)."
                else:
                    # '*' sin credenciales es normal para APIs públicas, no es vulnerabilidad per se
                    pass 
            elif acao == origin:
                # El servidor refleja el origen que le enviamos
                if acac.lower() == "true":
                    is_vuln = True
                    vuln_desc = f"Refleja el origen ({origin}) CON credenciales. Vulnerable a robo de datos (CSRF)."
                else:
                    # Riesgo medio: permite leer datos desde evil.com, pero sin cookies
                    findings.append((origin, acao, acac, f"Refleja el origen ({origin}) SIN credenciales. Riesgo de robo de datos públicos."))
            elif acao == "null" and origin == "null":
                if acac.lower() == "true":
                    is_vuln = True
                    vuln_desc = "Permite origen 'null' CON credenciales. Ciertas técnicas (ej. iframes sandboxed) pueden explotarlo."
                    
            if is_vuln:
                findings.append((origin, acao, acac, vuln_desc))
                
        except requests.RequestException:
            print(f"-> {red('Error de conexión')}")
            continue

    print()
    separator("═", 75)
    print(f"  {white('RESULTADOS DE LA AUDITORÍA CORS')}")
    separator("─", 75)
    
    if findings:
        for orig, acao, acac, desc in findings:
            print(f"  {red('⚠ MISCONFIGURACIÓN DETECTADA')}")
            print(f"  {white('Origin inyectado:')} {orig}")
            print(f"  {white('Respuesta ACAO:')}   {yellow(acao)}")
            print(f"  {white('Respuesta ACAC:')}   {yellow(acac)}")
            print(f"  {white('Impacto:')}          {desc}")
            print(f"  {dim('-'*60)}")
            
        print()
        warn("Un atacante puede crear una web maliciosa y engañar a un usuario.")
        warn("Si el usuario visita la web atacante, el navegador enviará peticiones ")
        warn("AJAX hacia esta aplicación incluyendo sus cookies de sesión, permitiendo ")
        warn("el robo de información privada.")
    else:
        print(f"  {green('✓')} No se detectaron misconfiguraciones severas de CORS.")
        print(f"  {dim('La API o web parece estar restringiendo correctamente los orígenes.')}")
        
    print()


def _mode_run() -> None:
    section_title("AUDITOR DE POLÍTICAS CORS")
    
    if not _HAS_REQ:
        error("Faltan librerías. Ejecutá: pip install requests")
        return

    target = prompt("URL a escanear (Ej. https://api.site.com/data)").strip()
    
    if target:
        _check_cors(target)


def _mode_explain() -> None:
    section_title("¿QUÉ ES CORS Y POR QUÉ ES PELIGROSO?")

    print(f"""
  {white('1. Política del Mismo Origen (SOP)')}
  {dim('─' * 56)}
  El navegador impide que una web en {cyan('evil.com')} lea datos de {cyan('banco.com')}.
  Esto protege tu sesión. Sin embargo, a veces {cyan('banco.com')} necesita 
  compartir datos con su propia app {cyan('movil.banco.com')}.

  {white('2. Cross-Origin Resource Sharing (CORS)')}
  {dim('─' * 56)}
  Para saltarse el SOP de forma segura, se creó CORS. El servidor 
  ({cyan('banco.com')}) envía una cabecera diciendo:
  {magenta('Access-Control-Allow-Origin: https://movil.banco.com')}
  {magenta('Access-Control-Allow-Credentials: true')}
  Esto le dice al navegador: "Permití que este subdominio lea los datos".

  {white('3. Misconfiguraciones comunes')}
  {dim('─' * 56)}
  A veces los desarrolladores tienen problemas configurando CORS, se
  frustran, y hacen que el servidor devuelva:
  {red('Access-Control-Allow-Origin: [Lo mismo que pidió el cliente]')}
  Esto destruye la seguridad del navegador. Cualquier web maliciosa
  puede pedir datos en tu nombre y el servidor lo aceptará.
    """)


# ──────────────────────────────────────────────
#  Submenú
# ──────────────────────────────────────────────
_SUBMENU = [
    ("1", "Auditar URL (CORS)",                   _mode_run),
    ("2", "¿Qué es CORS?",                        _mode_explain),
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
        section_title("HERRAMIENTA 30 — AUDITOR CORS")
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
