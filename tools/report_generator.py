"""
report_generator.py — Herramienta 36: Generador de reportes de seguridad
Lee salidas JSON en la carpeta outputs/ y genera un reporte HTML unificado.
"""

import sys
import os
import json
import glob
from datetime import datetime

# Asegura que el directorio raíz esté en el path al ejecutar directamente
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils import (
    ok, error, warn, info, result,
    section_title, separator, dim, cyan, green, yellow, white, red, magenta,
    prompt, pause
)

# ──────────────────────────────────────────────
#  Generador de HTML
# ──────────────────────────────────────────────
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reporte de Seguridad - CyberToolkit</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 20px; background-color: #f4f4f9; color: #333; }
        .container { max-width: 900px; margin: auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
        h1 { color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px; }
        h2 { color: #2980b9; margin-top: 30px; }
        .date { color: #7f8c8d; font-size: 0.9em; margin-bottom: 20px; }
        .card { background: #fdfdfd; border: 1px solid #e0e0e0; border-left: 5px solid #3498db; padding: 15px; margin-bottom: 15px; border-radius: 4px; }
        pre { background: #2c3e50; color: #ecf0f1; padding: 10px; border-radius: 4px; overflow-x: auto; }
        .severity-high { border-left-color: #e74c3c; }
        .severity-med { border-left-color: #f1c40f; }
        .severity-low { border-left-color: #2ecc71; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Reporte Ejecutivo de Ciberseguridad</h1>
        <div class="date">Generado el: {date}</div>
        <p>Este reporte consolida los hallazgos de las herramientas ejecutadas en CyberToolkit.</p>
        
        {content}
        
    </div>
</body>
</html>
"""

def _generate_report() -> None:
    section_title("GENERADOR DE REPORTES")
    
    outputs_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "outputs")
    if not os.path.exists(outputs_dir):
        warn(f"No existe el directorio de salidas ({outputs_dir}).")
        info("Ejecutá otras herramientas y exportá sus resultados primero.")
        return
        
    json_files = glob.glob(os.path.join(outputs_dir, "*.json"))
    if not json_files:
        warn("No se encontraron archivos .json en la carpeta outputs/.")
        return
        
    info(f"Se encontraron {len(json_files)} archivos de resultados.")
    
    content_html = ""
    for file_path in json_files:
        filename = os.path.basename(file_path)
        tool_name = filename.split('_')[0].upper()
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                
            content_html += f"<h2>Módulo: {tool_name}</h2>"
            content_html += f"<div class='card'>"
            content_html += f"<strong>Archivo fuente:</strong> {filename}<br>"
            content_html += f"<pre>{json.dumps(data, indent=4)}</pre>"
            content_html += f"</div>"
            
        except Exception as e:
            warn(f"No se pudo parsear {filename}: {e}")
            
    if content_html:
        report_filename = f"Reporte_Consolidado_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        report_path = os.path.join(outputs_dir, report_filename)
        try:
            with open(report_path, "w", encoding="utf-8") as f:
                f.write(HTML_TEMPLATE.format(date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"), content=content_html))
            ok(f"Reporte unificado generado exitosamente en: {report_path}")
        except Exception as e:
            error(f"Fallo al guardar el reporte: {e}")
    else:
        warn("No se generó contenido para el reporte.")


def _mode_explain() -> None:
    section_title("¿QUÉ ES UN REPORTE EJECUTIVO?")

    print(f"""
  {white('Reporting y Consolidación')}
  {dim('─' * 56)}
  El producto final de cualquier auditoría de seguridad o pentest es el reporte.
  Un buen reporte debe ser claro para la gerencia (Resumen Ejecutivo) y detallado
  para los técnicos (Hallazgos y Remediaciones).

  Esta herramienta toma los resultados en crudo (JSON) generados por el resto
  del toolkit y los consolida en un único documento HTML presentable.
    """)

# ──────────────────────────────────────────────
#  Submenú
# ──────────────────────────────────────────────
_SUBMENU = [
    ("1", "Generar reporte HTML desde archivos JSON", _generate_report),
    ("2", "¿Qué es el reporting en ciberseguridad?", _mode_explain),
]

def _print_submenu() -> None:
    print()
    info("Opciones de Reportes")
    separator("─", 58)
    for key, label, _ in _SUBMENU:
        print(f"  {cyan(f'[{key}]')} {white(label)}")
    print(f"  {red('[0]')} {dim('Volver al menú principal')}")
    separator("─", 58)

def run() -> None:
    while True:
        section_title("HERRAMIENTA 36 — GENERADOR DE REPORTES")
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
            error("Opción no válida. Ingresá un número de la lista.")

        pause()

if __name__ == "__main__":
    run()
