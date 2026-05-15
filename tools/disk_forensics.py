"""
disk_forensics.py — Herramienta 31: Análisis Forense de Discos
Realiza file carving básico (búsqueda por magic bytes) y extracción 
de cadenas legibles (strings) de archivos binarios/imágenes RAW de discos.
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

# Diccionario simplificado de Magic Bytes comunes
_MAGIC_BYTES = {
    b'\xFF\xD8\xFF\xE0': "JPEG Image",
    b'\xFF\xD8\xFF\xE1': "JPEG Image",
    b'\x89\x50\x4E\x47\x0D\x0A\x1A\x0A': "PNG Image",
    b'\x25\x50\x44\x46\x2D': "PDF Document",
    b'\x50\x4B\x03\x04': "ZIP Archive / Office XML",
    b'\x52\x61\x72\x21\x1A\x07': "RAR Archive",
    b'\x4D\x5A': "Windows Executable (PE)",
    b'\x7F\x45\x4C\x46': "Linux Executable (ELF)"
}


def _extract_strings(file_path: str, min_length: int = 6) -> None:
    """Extrae texto legible de un archivo binario."""
    if not os.path.exists(file_path):
        error("El archivo no existe.")
        return

    info(f"Extrayendo strings (longitud >= {min_length}) de {cyan(os.path.basename(file_path))}")
    separator("─", 60)
    
    # Expresiones regulares para buscar patrones interesantes dentro de los strings
    ip_pattern = re.compile(rb'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
    email_pattern = re.compile(rb'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+')
    
    found_ips = set()
    found_emails = set()
    total_strings = 0
    
    try:
        # Leemos en modo binario
        with open(file_path, "rb") as f:
            data = f.read()
            
            # Buscamos secuencias de caracteres ASCII imprimibles
            # \x20-\x7E es el rango ASCII estándar imprimible
            pattern = re.compile(rb'[\x20-\x7E]{' + str(min_length).encode() + rb',}')
            matches = pattern.finditer(data)
            
            for match in matches:
                total_strings += 1
                s = match.group()
                
                # Buscar IPs y Emails dentro del string descubierto
                for ip in ip_pattern.findall(s):
                    found_ips.add(ip.decode('utf-8'))
                for email in email_pattern.findall(s):
                    found_emails.add(email.decode('utf-8'))
                    
        result("Total de cadenas legibles encontradas", str(total_strings))
        print()
        
        if found_ips:
            print(f"  {white('Direcciones IP descubiertas en el archivo:')}")
            for ip in list(found_ips)[:10]:
                print(f"  {dim('└─')} {green(ip)}")
            if len(found_ips) > 10:
                print(f"  {dim(f'... y {len(found_ips)-10} IPs más.')}")
            print()
            
        if found_emails:
            print(f"  {white('Correos electrónicos descubiertos:')}")
            for email in list(found_emails)[:10]:
                print(f"  {dim('└─')} {yellow(email)}")
            if len(found_emails) > 10:
                print(f"  {dim(f'... y {len(found_emails)-10} emails más.')}")
            print()
            
        if not found_ips and not found_emails:
            info("No se detectaron IPs o Emails en el texto extraído.")
            
    except Exception as e:
        error(f"Error al leer el archivo: {e}")


def _file_carving(file_path: str) -> None:
    """Busca firmas de archivos (Magic Bytes) dentro de un archivo RAW."""
    if not os.path.exists(file_path):
        error("El archivo no existe.")
        return

    info(f"Iniciando File Carving en {cyan(os.path.basename(file_path))}")
    separator("─", 60)
    
    file_size = os.path.getsize(file_path)
    # Leemos por chunks para no saturar la RAM si el archivo es grande (ej. 1GB)
    chunk_size = 1024 * 1024 * 10 # 10 MB
    
    findings = []
    
    try:
        with open(file_path, "rb") as f:
            offset = 0
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                    
                # Buscar cada magic byte en el chunk actual
                for magic, desc in _MAGIC_BYTES.items():
                    start = 0
                    while True:
                        idx = chunk.find(magic, start)
                        if idx == -1:
                            break
                        # Guardar el offset global donde se encontró la firma
                        global_offset = offset + idx
                        findings.append((global_offset, desc))
                        start = idx + 1
                        
                offset += len(chunk)
                
                # Imprimir progreso
                progress = (offset / file_size) * 100
                print(f"\r  {dim('Progreso de escaneo:')} {progress:.1f}%", end="")
                
        print("\r" + " "*50 + "\r", end="")
        print()
        
        if findings:
            # Ordenar por offset
            findings.sort(key=lambda x: x[0])
            
            print(f"  {white('Firmas de archivos detectadas (Posibles archivos incrustados/eliminados):')}")
            # Mostrar los primeros 15 hallazgos
            for offset, desc in findings[:15]:
                print(f"  {dim(f'Offset: {offset:<12}')} | {cyan(desc)}")
            if len(findings) > 15:
                print(f"  {dim(f'... y {len(findings)-15} firmas adicionales encontradas.')}")
        else:
            print(f"  {green('✓')} No se encontraron firmas de archivos conocidos en los datos.")
            
    except Exception as e:
        error(f"Error al procesar el archivo: {e}")
        

def _mode_strings() -> None:
    section_title("EXTRACCIÓN DE STRINGS FORENSES")
    warn("Recomendado para archivos binarios (ej. .exe, .dll, o volcados pequeños).")
    target = prompt("Ruta del archivo a analizar").strip()
    if target:
        try:
            min_len = int(prompt("Longitud mínima de la cadena", default="6"))
        except ValueError:
            min_len = 6
        _extract_strings(target, min_len)


def _mode_carving() -> None:
    section_title("FILE CARVING (BÚSQUEDA DE FIRMAS)")
    warn("Escanea un archivo binario o volcado de disco en busca de archivos ocultos.")
    target = prompt("Ruta del archivo/imagen RAW a analizar").strip()
    if target:
        _file_carving(target)


def _mode_explain() -> None:
    section_title("¿QUÉ ES EL DFIR Y EL FILE CARVING?")
    magic_str = r'\xFF\xD8\xFF\xE0'

    print(f"""
  {white('1. Digital Forensics and Incident Response (DFIR)')}
  {dim('─' * 56)}
  Es la rama de la ciberseguridad dedicada a investigar "qué pasó" 
  después de un ataque. Consiste en recolectar evidencia de discos 
  y memoria RAM sin alterar los datos originales.

  {white('2. File Carving (Esculpido de archivos)')}
  {dim('─' * 56)}
  Cuando un atacante (o un usuario) elimina un archivo y vacía la papelera, 
  el sistema operativo no borra los datos, solo marca el espacio como "Libre".
  El File Carving ignora el sistema de archivos (NTFS/FAT) y lee el disco 
  byte a byte buscando "Firmas" ({cyan('Magic Bytes')}).
  Ejemplo: Si leemos {cyan(magic_str)}, sabemos que ahí empieza una 
  imagen JPEG que supuestamente estaba "borrada".

  {white('3. Extracción de Strings')}
  {dim('─' * 56)}
  Incluso si un archivo es un ejecutable compilado (un malware), a 
  menudo contiene texto legible en su interior: contraseñas hardcodeadas,
  URLs de servidores maliciosos (C2), o rutas de compilación del creador.
    """)


# ──────────────────────────────────────────────
#  Submenú
# ──────────────────────────────────────────────
_SUBMENU = [
    ("1", "Extraer Strings e IoCs de un binario", _mode_strings),
    ("2", "File Carving (Buscar firmas ocultas)", _mode_carving),
    ("3", "¿Qué es File Carving?",                _mode_explain),
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
        section_title("HERRAMIENTA 31 — DISK FORENSICS")
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
            error("Opción no válida. Ingresá un número del 0 al 3.")

        pause()


if __name__ == "__main__":
    run()
