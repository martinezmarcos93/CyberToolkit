"""
hash_tool.py — Herramienta 3: Generador / verificador de hashes
Calcula y verifica MD5, SHA-1, SHA-256 y SHA-512 para archivos y texto.
"""

import hashlib
import os
import sys

# Asegura que el directorio raíz esté en el path al ejecutar directamente
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils import (
    ok, error, warn, info, result,
    section_title, separator, dim, cyan, green, yellow, white, red,
    prompt, ask_yes_no, pause, validate_file, read_file_bytes, format_size,
)


# ──────────────────────────────────────────────
#  Constantes internas
# ──────────────────────────────────────────────
ALGORITHMS = {
    "1": ("MD5",    hashlib.md5,    "⚠ Obsoleto para seguridad, útil para integridad rápida"),
    "2": ("SHA-1",  hashlib.sha1,   "⚠ Deprecado en firmas digitales, aún usado en Git"),
    "3": ("SHA-256",hashlib.sha256, "✓ Estándar recomendado para integridad de archivos"),
    "4": ("SHA-512",hashlib.sha512, "✓ Mayor seguridad, salida de 128 caracteres hex"),
}

CHECKSUM_EXT = ".checksum"


# ──────────────────────────────────────────────
#  Cálculo de hash
# ──────────────────────────────────────────────
def _hash_bytes(data: bytes, algo_func) -> str:
    """Calcula el hash de un bloque de bytes."""
    return algo_func(data).hexdigest()


def _hash_file_streaming(path: str, algo_func) -> str | None:
    """
    Calcula el hash de un archivo en modo streaming (chunk a chunk).
    Maneja archivos grandes sin cargar todo en memoria.
    """
    BUF = 65536  # 64 KB por chunk
    h = algo_func()
    try:
        with open(path, "rb") as f:
            while chunk := f.read(BUF):
                h.update(chunk)
        return h.hexdigest()
    except OSError as e:
        error(f"No se pudo leer el archivo: {e}")
        return None


# ──────────────────────────────────────────────
#  Submenú de selección de algoritmo
# ──────────────────────────────────────────────
def _select_algorithm() -> tuple[str, object] | None:
    """Muestra el submenú de algoritmos y devuelve (nombre, función)."""
    print()
    info("Seleccioná el algoritmo de hash:")
    separator("─", 58)
    for key, (name, _, note) in ALGORITHMS.items():
        print(f"  {cyan(f'[{key}]')} {white(name):<10} {dim(note)}")
    separator("─", 58)

    choice = prompt("Opción", default="3")
    if choice not in ALGORITHMS:
        error("Opción inválida.")
        return None

    name, func, _ = ALGORITHMS[choice]
    return name, func


# ──────────────────────────────────────────────
#  Modo 1: Calcular hash de un archivo
# ──────────────────────────────────────────────
def _mode_hash_file() -> None:
    section_title("CALCULAR HASH DE ARCHIVO")

    path = prompt("Ruta del archivo")
    if not path:
        warn("No se ingresó ninguna ruta.")
        return
    if not validate_file(path):
        error(f"El archivo '{path}' no existe o no es legible.")
        return

    algo = _select_algorithm()
    if algo is None:
        return
    algo_name, algo_func = algo

    info(f"Calculando {algo_name} de '{os.path.basename(path)}'...")
    size = os.path.getsize(path)
    digest = _hash_file_streaming(path, algo_func)

    if digest is None:
        return

    print()
    separator("─", 58)
    result("Archivo",    path)
    result("Tamaño",     format_size(size))
    result(algo_name,    green(digest))
    separator("─", 58)

    # Ofrecer guardar el checksum
    if ask_yes_no("¿Guardar el hash en un archivo .checksum?", default=False):
        out_path = path + CHECKSUM_EXT
        try:
            with open(out_path, "w") as f:
                f.write(f"{digest}  {os.path.basename(path)}\n")
                f.write(f"# Algoritmo: {algo_name}\n")
            ok(f"Checksum guardado en: {out_path}")
        except OSError as e:
            error(f"No se pudo guardar el archivo: {e}")


# ──────────────────────────────────────────────
#  Modo 2: Calcular hash de texto
# ──────────────────────────────────────────────
def _mode_hash_text() -> None:
    section_title("CALCULAR HASH DE TEXTO")

    text = prompt("Texto a hashear")
    if not text:
        warn("No se ingresó ningún texto.")
        return

    algo = _select_algorithm()
    if algo is None:
        return
    algo_name, algo_func = algo

    data   = text.encode("utf-8")
    digest = _hash_bytes(data, algo_func)

    print()
    separator("─", 58)
    result("Texto",     f'"{text}"')
    result("Bytes",     str(len(data)))
    result(algo_name,   green(digest))
    separator("─", 58)
    ok("Hash calculado.")


# ──────────────────────────────────────────────
#  Modo 3: Verificar integridad de un archivo
# ──────────────────────────────────────────────
def _mode_verify_file() -> None:
    section_title("VERIFICAR INTEGRIDAD DE ARCHIVO")

    path = prompt("Ruta del archivo a verificar")
    if not path:
        warn("No se ingresó ninguna ruta.")
        return
    if not validate_file(path):
        error(f"El archivo '{path}' no existe o no es legible.")
        return

    # Intentar cargar desde .checksum automáticamente
    checksum_path = path + CHECKSUM_EXT
    expected = ""
    if os.path.isfile(checksum_path):
        info(f"Se encontró archivo de checksum: {checksum_path}")
        if ask_yes_no("¿Usar el hash guardado en ese archivo?", default=True):
            try:
                with open(checksum_path) as f:
                    first_line = f.readline().strip()
                    expected = first_line.split()[0]
                info(f"Hash esperado cargado: {dim(expected)}")
            except OSError:
                warn("No se pudo leer el archivo .checksum. Ingresalo manualmente.")

    if not expected:
        expected = prompt("Hash esperado (hex)")
        if not expected:
            warn("No se ingresó hash esperado.")
            return

    expected = expected.strip().lower()

    algo = _select_algorithm()
    if algo is None:
        return
    algo_name, algo_func = algo

    info(f"Calculando {algo_name}...")
    computed = _hash_file_streaming(path, algo_func)
    if computed is None:
        return

    computed = computed.lower()

    print()
    separator("─", 58)
    result("Archivo",   path)
    result("Esperado",  yellow(expected))
    result("Calculado", cyan(computed))
    separator("─", 58)

    if computed == expected:
        print(f"\n  {green('✓ INTEGRIDAD VERIFICADA')} — El archivo no fue alterado.")
    else:
        print(f"\n  {red('✗ FALLO DE INTEGRIDAD')} — Los hashes no coinciden.")
        warn("El archivo puede haber sido modificado, corrompido o descargado incorrectamente.")

    print()


# ──────────────────────────────────────────────
#  Modo 4: Comparar dos archivos
# ──────────────────────────────────────────────
def _mode_compare_files() -> None:
    section_title("COMPARAR DOS ARCHIVOS")

    path_a = prompt("Ruta del primer archivo")
    if not path_a or not validate_file(path_a):
        error("El primer archivo no existe o no es legible.")
        return

    path_b = prompt("Ruta del segundo archivo")
    if not path_b or not validate_file(path_b):
        error("El segundo archivo no existe o no es legible.")
        return

    algo = _select_algorithm()
    if algo is None:
        return
    algo_name, algo_func = algo

    info(f"Calculando {algo_name} de ambos archivos...")

    hash_a = _hash_file_streaming(path_a, algo_func)
    hash_b = _hash_file_streaming(path_b, algo_func)

    if hash_a is None or hash_b is None:
        return

    size_a = format_size(os.path.getsize(path_a))
    size_b = format_size(os.path.getsize(path_b))

    print()
    separator("─", 58)
    result(f"Archivo A ({size_a})", os.path.basename(path_a))
    result(f"  {algo_name}", cyan(hash_a))
    print()
    result(f"Archivo B ({size_b})", os.path.basename(path_b))
    result(f"  {algo_name}", cyan(hash_b))
    separator("─", 58)

    if hash_a == hash_b:
        print(f"\n  {green('✓ ARCHIVOS IDÉNTICOS')} — Mismo contenido binario.")
    else:
        print(f"\n  {red('✗ ARCHIVOS DISTINTOS')} — El contenido difiere.")

    print()


# ──────────────────────────────────────────────
#  Submenú de la herramienta
# ──────────────────────────────────────────────
_SUBMENU = [
    ("1", "Calcular hash de un archivo",      _mode_hash_file),
    ("2", "Calcular hash de un texto",         _mode_hash_text),
    ("3", "Verificar integridad de archivo",   _mode_verify_file),
    ("4", "Comparar dos archivos",             _mode_compare_files),
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
    """Punto de entrada llamado desde main.py."""
    while True:
        section_title("HERRAMIENTA 3 — GENERADOR / VERIFICADOR DE HASHES")
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
            error("Opción no válida. Ingresá un número del 0 al 4.")

        pause()


# ──────────────────────────────────────────────
#  Ejecución directa (desarrollo)
# ──────────────────────────────────────────────
if __name__ == "__main__":
    run()
