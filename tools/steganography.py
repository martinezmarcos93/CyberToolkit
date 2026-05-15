"""
steganography.py — Herramienta 18: Esteganografía en imágenes (LSB)
Oculta y extrae mensajes de texto en los bits menos significativos (LSB) 
de los píxeles de una imagen (formato PNG preferentemente).
"""

import sys
import os

# Asegura que el directorio raíz esté en el path al ejecutar directamente
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils import (
    ok, error, warn, info, result,
    section_title, separator, dim, cyan, green, yellow, white, red, magenta,
    prompt, pause
)

try:
    from PIL import Image
    _HAS_PIL = True
except ImportError:
    _HAS_PIL = False


def _msg_to_bin(msg: str) -> str:
    """Convierte un string a una cadena de bits (8 bits por caracter)."""
    return ''.join(format(ord(c), '08b') for c in msg)


def _bin_to_msg(binary: str) -> str:
    """Convierte una cadena de bits a string ASCII."""
    chars = [binary[i:i+8] for i in range(0, len(binary), 8)]
    msg = ""
    for b in chars:
        if b == "00000000":  # Null byte, fin de string
            break
        try:
            msg += chr(int(b, 2))
        except ValueError:
            pass
    return msg


def _hide_message(img_path: str, message: str, output_path: str) -> bool:
    if not _HAS_PIL:
        error("La librería Pillow (PIL) no está instalada.")
        return False

    try:
        img = Image.open(img_path)
        img = img.convert('RGB')
    except Exception as e:
        error(f"No se pudo abrir la imagen: {e}")
        return False

    # Agregar un delimitador (null byte) al final del mensaje
    msg_bin = _msg_to_bin(message) + "00000000"
    msg_len = len(msg_bin)

    width, height = img.size
    total_pixels = width * height
    # Cada pixel almacena 3 bits (1 en R, 1 en G, 1 en B)
    if msg_len > total_pixels * 3:
        error(f"La imagen es muy pequeña ({total_pixels} píxeles). Necesita al menos {msg_len // 3 + 1} píxeles para este mensaje.")
        return False

    pixels = img.load()
    bit_idx = 0

    info("Modificando los LSB de la imagen...")
    for y in range(height):
        for x in range(width):
            if bit_idx < msg_len:
                r, g, b = pixels[x, y]

                # Modificar canal Rojo
                if bit_idx < msg_len:
                    r = (r & ~1) | int(msg_bin[bit_idx])
                    bit_idx += 1
                # Modificar canal Verde
                if bit_idx < msg_len:
                    g = (g & ~1) | int(msg_bin[bit_idx])
                    bit_idx += 1
                # Modificar canal Azul
                if bit_idx < msg_len:
                    b = (b & ~1) | int(msg_bin[bit_idx])
                    bit_idx += 1

                pixels[x, y] = (r, g, b)
            else:
                break
        if bit_idx >= msg_len:
            break

    try:
        img.save(output_path, "PNG")
        return True
    except Exception as e:
        error(f"Error al guardar imagen resultante: {e}")
        return False


def _extract_message(img_path: str) -> str | None:
    if not _HAS_PIL:
        error("La librería Pillow (PIL) no está instalada.")
        return None

    try:
        img = Image.open(img_path)
        img = img.convert('RGB')
    except Exception as e:
        error(f"No se pudo abrir la imagen: {e}")
        return None

    pixels = img.load()
    width, height = img.size

    info("Extrayendo los LSB de la imagen...")
    extracted_bin = ""

    for y in range(height):
        for x in range(width):
            r, g, b = pixels[x, y]
            extracted_bin += str(r & 1)
            extracted_bin += str(g & 1)
            extracted_bin += str(b & 1)

            # Optimización: comprobar si acabamos de leer el null byte "00000000"
            if len(extracted_bin) % 8 == 0:
                if extracted_bin[-8:] == "00000000":
                    return _bin_to_msg(extracted_bin)

    return _bin_to_msg(extracted_bin)


def _mode_hide() -> None:
    section_title("OCULTAR MENSAJE EN IMAGEN (LSB)")

    img_in = prompt("Ruta de la imagen original (ej. foto.png o foto.jpg)")
    if not os.path.exists(img_in):
        error("Archivo no encontrado.")
        return

    msg = prompt("Mensaje secreto a ocultar")
    if not msg:
        warn("Mensaje vacío.")
        return

    img_out = prompt("Ruta de salida (DEBE ser .png para no perder datos)", default="secreto.png")
    if not img_out.lower().endswith('.png'):
        warn("Guardar en JPG destruye los LSB por compresión. Forzando formato PNG.")
        img_out += ".png"

    print()
    success = _hide_message(img_in, msg, img_out)
    
    if success:
        separator("─", 60)
        print(f"  {green('✓ Mensaje oculto exitosamente!')}")
        print(f"  {white('Imagen resultante:')} {cyan(img_out)}")
        separator("─", 60)
    print()


def _mode_extract() -> None:
    section_title("EXTRAER MENSAJE DE IMAGEN (LSB)")

    img_in = prompt("Ruta de la imagen esteganográfica (ej. secreto.png)")
    if not os.path.exists(img_in):
        error("Archivo no encontrado.")
        return

    print()
    msg = _extract_message(img_in)
    
    separator("─", 60)
    if msg:
        print(f"  {green('✓ Mensaje extraído:')}")
        print(f"  {yellow(msg)}")
    else:
        warn("No se encontró ningún mensaje legible.")
    separator("─", 60)
    print()


def _mode_explain() -> None:
    section_title("¿QUÉ ES LA ESTEGANOGRAFÍA LSB?")

    print(f"""
  {white('1. Esteganografía vs Criptografía')}
  {dim('─' * 56)}
  La {cyan('criptografía')} oculta el SIGNIFICADO de un mensaje (se ve como basura).
  La {cyan('esteganografía')} oculta la EXISTENCIA del mensaje (se ve como una foto normal).
  Idealmente, ambas se combinan: se cifra el mensaje y luego se oculta.

  {white('2. LSB (Least Significant Bit)')}
  {dim('─' * 56)}
  Una imagen digital está formada por píxeles. En formato RGB, cada píxel 
  tiene 3 valores (Rojo, Verde, Azul) de 8 bits cada uno (0 a 255).
  Si cambiamos el {green('Último Bit')} de esos 8 (el menos significativo), el valor
  del color cambiará como máximo en 1 unidad (ej. de 100 a 101).

  {white('3. Imperceptible al ojo humano')}
  {dim('─' * 56)}
  El ojo humano no puede notar la diferencia entre el color (100, 150, 200) y
  el color (101, 151, 201). Por lo tanto, podemos usar ese último bit para
  almacenar nuestro mensaje binario secreto en toda la imagen.

  {white('4. Formatos Lossless vs Lossy')}
  {dim('─' * 56)}
  {green('PNG o BMP')} son formatos sin pérdida (Lossless), perfectos para LSB.
  {red('JPEG')} usa compresión con pérdida (Lossy), la cual modifica los píxeles 
  para ahorrar espacio. {red('Guardar en JPEG destruye los datos LSB')}.
    """)


# ──────────────────────────────────────────────
#  Submenú
# ──────────────────────────────────────────────
_SUBMENU = [
    ("1", "Ocultar mensaje en imagen",            _mode_hide),
    ("2", "Extraer mensaje de imagen",            _mode_extract),
    ("3", "¿Qué es LSB Steganography?",           _mode_explain),
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
        section_title("HERRAMIENTA 18 — ESTEGANOGRAFÍA LSB")
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
