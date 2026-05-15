"""
web_crawler.py — Herramienta 27: Crawler de aplicaciones web
Mapea una aplicación web extrayendo enlaces, formularios, y comentarios.
"""

import sys
import os
import urllib.parse
from collections import deque

# Asegura que el directorio raíz esté en el path al ejecutar directamente
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils import (
    ok, error, warn, info, result,
    section_title, separator, dim, cyan, green, yellow, white, red, magenta,
    prompt, pause
)

try:
    import requests
    from bs4 import BeautifulSoup, Comment
    _HAS_REQ = True
except ImportError:
    _HAS_REQ = False


def _crawl(base_url: str, max_depth: int = 2) -> None:
    if not base_url.startswith(("http://", "https://")):
        base_url = "http://" + base_url

    info(f"Iniciando crawling en {cyan(base_url)} (Profundidad: {max_depth})...")
    separator("─", 60)

    # Variables de estado
    visited = set()
    queue = deque([(base_url, 0)]) # (url, depth)
    
    found_urls = set()
    found_forms = []
    found_comments = []
    found_params = set() # Parámetros GET (ej. ?id=1)

    # Configuración de requests para parecer un navegador normal
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) CyberToolkit Crawler"
    }

    try:
        while queue:
            current_url, depth = queue.popleft()

            if current_url in visited or depth > max_depth:
                continue

            visited.add(current_url)
            
            # Limpiar el output para no llenar la pantalla
            print(f"\r  {dim('Scrapeando:')} {current_url[:50]:<50}", end="", flush=True)

            try:
                response = requests.get(current_url, headers=headers, timeout=5)
                # Solo procesar HTML
                if "text/html" not in response.headers.get("Content-Type", ""):
                    continue
                    
                soup = BeautifulSoup(response.text, "html.parser")
            except requests.RequestException:
                continue

            # 1. Extraer Enlaces
            for a_tag in soup.find_all("a", href=True):
                href = a_tag["href"]
                # Resolver URL relativa
                full_url = urllib.parse.urljoin(current_url, href)
                
                # Quitar fragmentos (#)
                full_url = urllib.parse.urldefrag(full_url)[0]

                # Extraer parámetros (para sqli_detector futuro)
                parsed = urllib.parse.urlparse(full_url)
                if parsed.query:
                    for param in urllib.parse.parse_qs(parsed.query).keys():
                        found_params.add(param)

                # Agregar a cola si pertenece al mismo dominio
                if urllib.parse.urlparse(full_url).netloc == urllib.parse.urlparse(base_url).netloc:
                    if full_url not in visited and full_url not in [q[0] for q in queue]:
                        queue.append((full_url, depth + 1))
                        found_urls.add(full_url)

            # 2. Extraer Formularios
            for form in soup.find_all("form"):
                action = form.get("action", "")
                method = form.get("method", "get").upper()
                inputs = [inp.get("name") for inp in form.find_all("input") if inp.get("name")]
                found_forms.append((current_url, method, action, inputs))

            # 3. Extraer Comentarios HTML
            for comment in soup.find_all(string=lambda text: isinstance(text, Comment)):
                c_text = str(comment).strip()
                if c_text and len(c_text) > 3:
                    found_comments.append((current_url, c_text))

    except KeyboardInterrupt:
        print("\r" + " "*70 + "\r", end="")
        warn("Crawling interrumpido por el usuario.")

    print("\r" + " "*70 + "\r", end="")
    print()
    
    # Mostrar resultados
    separator("═", 75)
    print(f"  {white('RESULTADOS DEL CRAWLER')}")
    separator("─", 75)
    
    result("Páginas visitadas", str(len(visited)))
    result("URLs únicas encontradas", str(len(found_urls)))
    print()

    # Parámetros interesantes
    if found_params:
        print(f"  {white('Parámetros GET descubiertos (Posibles vectores de ataque):')}")
        print(f"  {cyan(', '.join(found_params))}")
        print()

    # Formularios
    if found_forms:
        print(f"  {white('Formularios detectados:')}")
        # Mostrar max 5
        for url, method, action, inputs in found_forms[:5]:
            print(f"  {dim('URL:')} {url}")
            print(f"  {dim('└─')} {green(method)} -> {yellow(action)} | Campos: {cyan(str(inputs))}")
        if len(found_forms) > 5:
            print(f"  {dim(f'... y {len(found_forms)-5} formularios más.')}")
        print()

    # Comentarios sensibles (filtrados heurísticamente)
    sensibles = [c for c in found_comments if any(w in c[1].lower() for w in ['pass', 'user', 'admin', 'todo', 'fix', 'bug', 'test'])]
    if sensibles:
        print(f"  {white('Comentarios HTML sospechosos (Pueden contener info sensible):')}")
        for url, comment in sensibles[:5]:
            print(f"  {dim('En:')} {url}")
            # Limitar longitud del comentario
            short_c = comment[:80] + "..." if len(comment) > 80 else comment
            print(f"  {dim('└─')} {magenta('<!--')} {yellow(short_c)} {magenta('-->')}")
        print()
        
    separator("─", 75)
    print()


def _mode_run() -> None:
    section_title("CRAWLER WEB")
    
    if not _HAS_REQ:
        error("Faltan librerías. Ejecutá: pip install requests beautifulsoup4")
        return

    target = prompt("URL base a escanear (ej. http://testphp.vulnweb.com)").strip()
    if not target:
        return
        
    try:
        depth = int(prompt("Profundidad de navegación (1-5)", default="2"))
    except ValueError:
        depth = 2

    _crawl(target, depth)


def _mode_explain() -> None:
    section_title("¿QUÉ ES EL WEB CRAWLING Y RECONOCIMIENTO?")

    print(f"""
  {white('1. Superficie de Ataque (Attack Surface)')}
  {dim('─' * 56)}
  Antes de atacar una aplicación web, un pentester debe conocer 
  TODOS sus rincones. Cada página, cada formulario y cada parámetro GET 
  (?id=1) es una "puerta" potencial para inyectar código.

  {white('2. Comentarios HTML Sensibles')}
  {dim('─' * 56)}
  Los desarrolladores a veces olvidan comentarios en el código fuente:
  {magenta('<!-- TODO: Eliminar credenciales admin:admin antes de prod -->')}
  Estas notas son invisibles en el navegador, pero el crawler las lee.

  {white('3. Detección de Formularios')}
  {dim('─' * 56)}
  Los formularios (Login, Búsqueda, Contacto) son los principales vectores 
  para ataques de {cyan('SQL Injection (SQLi)')} y {cyan('Cross-Site Scripting (XSS)')}.
  Mapearlos es el paso previo a usar herramientas como sqlmap o nuestro 
  próximo sqli_detector.py.
    """)


# ──────────────────────────────────────────────
#  Submenú
# ──────────────────────────────────────────────
_SUBMENU = [
    ("1", "Ejecutar Crawler",                     _mode_run),
    ("2", "¿Para qué sirve el Crawling?",         _mode_explain),
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
        section_title("HERRAMIENTA 27 — CRAWLER WEB")
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
