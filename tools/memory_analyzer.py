"""
memory_analyzer.py — Herramienta 32: Analizador de volcados de memoria
Realiza un análisis heurístico rápido sobre volcados de RAM (.raw, .mem, .vmem)
para extraer Indicadores de Compromiso (IoCs) sin requerir Volatility.
"""

import sys
import os
import re

# Asegura que el directorio raíz esté en el path al ejecutar directamente
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils import (
    ok, error, warn, info, result,
    section_title, separator, dim, cyan, green, yellow, white, red, magenta,
    prompt, pause
)


def _scan_memory(file_path: str) -> None:
    """Escanea el volcado de memoria buscando artefactos clave."""
    if not os.path.exists(file_path):
        error("El archivo no existe.")
        return

    info(f"Analizando volcado de memoria: {cyan(os.path.basename(file_path))}")
    separator("─", 60)
    
    file_size = os.path.getsize(file_path)
    chunk_size = 1024 * 1024 * 50 # 50 MB por chunk para leer RAM rápido
    
    # Expresiones regulares para IoCs comunes
    url_pattern = re.compile(rb'https?://[a-zA-Z0-9./\-_?=]+')
    mac_pattern = re.compile(rb'(?:[0-9A-Fa-f]{2}[:-]){5}(?:[0-9A-Fa-f]{2})')
    # Patrón básico para buscar ejecuciones de CMD o PowerShell
    cmd_pattern = re.compile(rb'(cmd\.exe|powershell\.exe)\s+[^\\x00]+')
    
    found_urls = set()
    found_macs = set()
    found_cmds = set()
    
    try:
        with open(file_path, "rb") as f:
            offset = 0
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                    
                # Buscar URLs
                for u in url_pattern.findall(chunk):
                    url_str = u.decode('utf-8', errors='ignore')
                    # Filtrar falsos positivos de esquemas XML estándar de Windows
                    if "schemas.microsoft.com" not in url_str and "w3.org" not in url_str:
                        found_urls.add(url_str)
                        
                # Buscar Direcciones MAC
                for m in mac_pattern.findall(chunk):
                    found_macs.add(m.decode('utf-8', errors='ignore'))
                    
                # Buscar procesos de línea de comandos
                for c in cmd_pattern.findall(chunk):
                    found_cmds.add(c.decode('utf-8', errors='ignore'))
                        
                offset += len(chunk)
                progress = (offset / file_size) * 100
                print(f"\r  {dim('Escaneando chunk:')} {progress:.1f}% completo...", end="")
                
        print("\r" + " "*60 + "\r", end="")
        print()
        
        separator("═", 75)
        print(f"  {white('RESULTADOS DEL ANÁLISIS DE MEMORIA')}")
        separator("─", 75)
        
        # Procesos sospechosos detectados en memoria
        if found_cmds:
            print(f"  {red('⚠ Evidencias de ejecución por línea de comandos:')}")
            # Mostrar max 10
            for cmd in list(found_cmds)[:10]:
                print(f"  {dim('└─')} {yellow(cmd.strip())}")
            print()
            
        # URLs de posibles C2 o descargas
        if found_urls:
            print(f"  {white('URLs extraídas (Posibles conexiones de red / C2):')}")
            # Filtrar un poco y mostrar max 15
            clean_urls = [u for u in found_urls if len(u) > 12]
            for url in clean_urls[:15]:
                print(f"  {dim('└─')} {cyan(url)}")
            if len(clean_urls) > 15:
                print(f"  {dim(f'... y {len(clean_urls)-15} URLs adicionales ocultas.')}")
            print()
            
        # Direcciones MAC (Ayuda a identificar la máquina o red)
        if found_macs:
            print(f"  {white('Direcciones MAC descubiertas (Útiles para mapeo de red):')}")
            for mac in list(found_macs)[:5]:
                print(f"  {dim('└─')} {green(mac)}")
            print()
            
        if not any([found_cmds, found_urls, found_macs]):
            print(f"  {green('✓')} No se detectaron artefactos evidentes con las reglas básicas.")
            
    except Exception as e:
        error(f"Error durante el escaneo: {e}")


def _mode_run() -> None:
    section_title("ANALIZADOR DE MEMORIA RAM")
    warn("El análisis puede tomar tiempo dependiendo del tamaño del volcado.")
    target = prompt("Ruta del archivo de memoria (ej. memdump.raw)").strip()
    if target:
        _scan_memory(target)


def _mode_explain() -> None:
    section_title("¿QUÉ ES EL ANÁLISIS DE MEMORIA (RAM)?")

    print(f"""
  {white('1. La importancia de la Memoria Volátil')}
  {dim('─' * 56)}
  Los atacantes modernos usan malware "Fileless" (sin archivos). Nunca 
  tocan el disco duro; se ejecutan directamente en la memoria RAM 
  usando PowerShell o inyección de procesos. Si apagas la PC, la 
  evidencia desaparece.

  {white('2. Volcados de Memoria (.raw, .mem)')}
  {dim('─' * 56)}
  Un investigador primero "congela" la RAM copiando todo su contenido a 
  un archivo. Luego, analiza ese archivo buscando contraseñas en claro, 
  conexiones de red activas, y comandos ejecutados por el atacante.

  {white('3. Limitaciones de este escáner')}
  {dim('─' * 56)}
  Este módulo hace una búsqueda heurística ("fuerza bruta" de strings)
  para encontrar URLs, MACs y comandos de CMD. Para un análisis forense
  profundo (ver árboles de procesos, rootkits ocultos, extraer claves 
  de cifrado), se requiere una herramienta especializada como {cyan('Volatility')}.
    """)


# ──────────────────────────────────────────────
#  Submenú
# ──────────────────────────────────────────────
_SUBMENU = [
    ("1", "Analizar volcado de memoria (.raw)",   _mode_run),
    ("2", "¿Qué es el Memory Forensics?",         _mode_explain),
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
        section_title("HERRAMIENTA 32 — MEMORY ANALYZER")
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
