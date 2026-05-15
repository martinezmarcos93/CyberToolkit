"""
timeline_builder.py — Herramienta 33: Constructor de línea de tiempo forense
Extrae y correlaciona metadatos de archivos (MAC times) de un directorio
para reconstruir cronológicamente la actividad del sistema.
"""

import sys
import os
import time
from datetime import datetime

# Asegura que el directorio raíz esté en el path al ejecutar directamente
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils import (
    ok, error, warn, info, result,
    section_title, separator, dim, cyan, green, yellow, white, red, magenta,
    prompt, pause
)


def _format_time(timestamp: float) -> str:
    """Convierte un timestamp POSIX a un string legible ISO 8601."""
    try:
        return datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
    except:
        return "Desconocido"


def _build_timeline(target_dir: str, export_csv: bool = False) -> None:
    """Escanea el directorio y genera la línea de tiempo."""
    if not os.path.isdir(target_dir):
        error(f"El directorio '{target_dir}' no existe o no es accesible.")
        return

    info(f"Construyendo línea de tiempo para: {cyan(target_dir)}")
    separator("─", 60)
    
    events = []
    total_files = 0
    
    print(f"  {dim('Escaneando archivos y extrayendo metadatos MAC (Modified, Accessed, Created)...')}")
    
    try:
        # Recorrer recursivamente el directorio
        for root, dirs, files in os.walk(target_dir):
            for file in files:
                file_path = os.path.join(root, file)
                try:
                    # stat extrae los metadatos del sistema de archivos
                    stat = os.stat(file_path)
                    
                    # ctime en Windows es Creación. En Linux es Último cambio de metadatos.
                    # mtime es Modificación (contenido).
                    # atime es Último acceso.
                    
                    # Agregamos cada evento por separado a la lista
                    events.append((stat.st_ctime, "CREATION / CHANGE", file_path))
                    events.append((stat.st_mtime, "MODIFICATION", file_path))
                    events.append((stat.st_atime, "ACCESS", file_path))
                    
                    total_files += 1
                except PermissionError:
                    continue # Ignorar archivos sin permiso
                except FileNotFoundError:
                    continue
                    
        # Ordenar todos los eventos cronológicamente (por el timestamp)
        events.sort(key=lambda x: x[0])
        
        print(f"  {green('✓')} Análisis completado. Archivos procesados: {white(str(total_files))}")
        print()
        
        separator("═", 75)
        print(f"  {white('LÍNEA DE TIEMPO FORENSE (MAC TIMES)')}")
        separator("─", 75)
        
        # Filtrar un poco para la pantalla si hay demasiados (ej. mostrar los últimos 20)
        max_display = 20
        display_events = events[-max_display:] if len(events) > max_display else events
        
        if len(events) > max_display:
            print(f"  {dim(f'Mostrando los últimos {max_display} eventos de {len(events)} totales:')}")
            print()
            
        for ts, event_type, path in display_events:
            date_str = _format_time(ts)
            
            # Colorear según el tipo de evento
            if event_type == "MODIFICATION":
                evt_color = yellow
            elif "CREATION" in event_type:
                evt_color = green
            else:
                evt_color = cyan
                
            # Truncar path para no romper la pantalla
            short_path = path if len(path) < 45 else "..." + path[-42:]
            
            print(f"  {white(date_str)} | {evt_color(event_type[:15]:<15)} | {dim(short_path)}")
            
        print()
        
        # Exportar a CSV si se solicitó
        if export_csv and events:
            export_path = "timeline_report.csv"
            with open(export_path, "w", encoding="utf-8") as f:
                f.write("Timestamp,Date_Time,Event_Type,File_Path\n")
                for ts, event_type, path in events:
                    f.write(f"{ts},{_format_time(ts)},{event_type},\"{path}\"\n")
                    
            info(f"Línea de tiempo completa exportada a: {cyan(export_path)}")
            
    except Exception as e:
        error(f"Error durante el escaneo: {e}")


def _mode_run() -> None:
    section_title("CONSTRUCTOR DE LÍNEA DE TIEMPO")
    
    target = prompt("Directorio a analizar (ej. C:\\Users\\Public)").strip()
    if not target:
        return
        
    export = prompt("¿Exportar reporte completo a CSV? (s/N)").strip().lower() == 's'
    
    _build_timeline(target, export_csv=export)


def _mode_explain() -> None:
    section_title("¿QUÉ SON LOS MAC TIMES Y EL TIMELINING?")

    print(f"""
  {white('1. Análisis de Línea de Tiempo (Timelining)')}
  {dim('─' * 56)}
  En respuesta a incidentes, la pregunta clave es: {cyan('¿Qué hizo el atacante y cuándo?')}
  Si sabemos que el malware se ejecutó a las 14:05, construir una 
  línea de tiempo nos permite ver qué otros archivos se crearon o 
  modificaron exactamente a las 14:05.

  {white('2. Tiempos MAC (Modified, Accessed, Created)')}
  {dim('─' * 56)}
  Cada archivo guarda 3 marcas de tiempo principales:
  {dim('·')} {green('M (Modified):')} Cuándo se modificó el CONTENIDO del archivo.
  {dim('·')} {yellow('A (Accessed):')} Cuándo fue abierto/leído por un usuario o proceso.
  {dim('·')} {cyan('C (Created / Changed):')} Cuándo se creó (en Windows) o cuándo
    cambiaron sus metadatos/permisos (en Linux).

  {white('3. Evasión (Timestomping)')}
  {dim('─' * 56)}
  Los atacantes avanzados usan técnicas llamadas "Timestomping" para
  alterar estas fechas falsificando su origen (ej. poner fecha de 1999)
  para intentar ocultarse en el ruido del sistema operativo.
    """)


# ──────────────────────────────────────────────
#  Submenú
# ──────────────────────────────────────────────
_SUBMENU = [
    ("1", "Construir Línea de Tiempo (MAC Times)", _mode_run),
    ("2", "¿Qué es el Timelining forense?",       _mode_explain),
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
        section_title("HERRAMIENTA 33 — TIMELINE BUILDER")
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
