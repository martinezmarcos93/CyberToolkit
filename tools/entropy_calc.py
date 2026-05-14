"""
entropy_calc.py — Herramienta 10: Calculadora de entropía de archivos
Calcula la entropía de Shannon normalizada (0–8 bits) byte a byte
y muestra un histograma ASCII de distribución de bytes.
"""

import math
import os
import sys
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils import (
    ok, error, warn, info, result,
    section_title, separator, dim, cyan, green, yellow, white, red, magenta,
    prompt, pause, validate_file, format_size,
)
from config import classify_entropy, ENTROPY_RANGES


# ──────────────────────────────────────────────
#  Cálculo de entropía de Shannon
# ──────────────────────────────────────────────
def _calc_entropy(data: bytes) -> float:
    """
    Calcula la entropía de Shannon normalizada en bits por byte (0.0 – 8.0).
    H = -Σ p(x) · log2(p(x))
    """
    if not data:
        return 0.0

    total = len(data)
    counts = Counter(data)

    entropy = 0.0
    for count in counts.values():
        p = count / total
        entropy -= p * math.log2(p)

    return entropy


def _calc_byte_distribution(data: bytes) -> list[int]:
    """
    Devuelve una lista de 256 posiciones con la frecuencia de cada byte (0–255).
    """
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    return counts


# ──────────────────────────────────────────────
#  Histograma ASCII
# ──────────────────────────────────────────────
def _print_histogram(counts: list[int], total: int) -> None:
    """
    Muestra un histograma ASCII agrupando los 256 valores de byte
    en 16 grupos de 16 bytes cada uno.
    """
    BAR_WIDTH = 30   # ancho máximo de la barra
    GROUPS    = 16   # número de grupos

    # Sumar frecuencias por grupo
    group_counts = []
    for g in range(GROUPS):
        start = g * 16
        group_sum = sum(counts[start: start + 16])
        group_counts.append(group_sum)

    max_count = max(group_counts) if max(group_counts) > 0 else 1

    print()
    print(f"  {white('HISTOGRAMA DE DISTRIBUCIÓN DE BYTES')}")
    separator("─", 58)
    print(f"  {'Rango':<12} {'Frecuencia':<10} {'Distribución'}")
    separator("─", 58)

    for g, count in enumerate(group_counts):
        start   = g * 16
        end     = start + 15
        pct     = count / total * 100
        bar_len = int((count / max_count) * BAR_WIDTH)

        # Color del bloque según rango de bytes
        if start < 32:
            color = dim          # control chars
        elif start < 128:
            color = cyan         # ASCII imprimible
        elif start < 160:
            color = yellow       # extended / latin
        else:
            color = magenta      # high bytes

        bar   = color("█" * bar_len + "░" * (BAR_WIDTH - bar_len))
        label = f"0x{start:02X}–0x{end:02X}"
        print(f"  {dim(label):<12} {dim(f'{pct:5.1f}%'):<10} {bar}")

    separator("─", 58)
    print(f"  {dim('Leyenda:')} {dim('ctrl')} · {cyan('ASCII')} · {yellow('latin')} · {magenta('high')}")


# ──────────────────────────────────────────────
#  Color según nivel de entropía
# ──────────────────────────────────────────────
def _color_entropy(entropy: float) -> str:
    """Colorea el valor de entropía según su nivel."""
    if entropy < 3.0:
        return green(f"{entropy:.4f} bits/byte")
    elif entropy < 6.0:
        return yellow(f"{entropy:.4f} bits/byte")
    elif entropy < 7.5:
        return cyan(f"{entropy:.4f} bits/byte")
    else:
        return red(f"{entropy:.4f} bits/byte")


def _print_entropy_scale(entropy: float) -> None:
    """Muestra una barra de escala con la posición de la entropía calculada."""
    SCALE_W = 40
    pos = int((entropy / 8.0) * SCALE_W)

    bar = ""
    for i in range(SCALE_W):
        frac = i / SCALE_W * 8.0
        if i == pos:
            bar += red("▼")
        elif frac < 3.0:
            bar += green("─")
        elif frac < 6.0:
            bar += yellow("─")
        elif frac < 7.5:
            bar += cyan("─")
        else:
            bar += red("─")

    print(f"\n  0 {bar} 8")
    print(f"  {dim('░ bajo'):<10} {dim('medio'):^20} {dim('cifrado'):>10}")


# ──────────────────────────────────────────────
#  Modo 1: Analizar un archivo
# ──────────────────────────────────────────────
def _mode_analyze_file() -> None:
    section_title("ENTROPÍA DE ARCHIVO")

    path = prompt("Ruta del archivo")
    if not path:
        warn("No se ingresó ninguna ruta.")
        return
    if not validate_file(path):
        error(f"El archivo '{path}' no existe o no es legible.")
        return

    size = os.path.getsize(path)
    if size == 0:
        warn("El archivo está vacío.")
        return

    info(f"Leyendo '{os.path.basename(path)}' ({format_size(size)})...")

    try:
        with open(path, "rb") as f:
            data = f.read()
    except OSError as e:
        error(f"No se pudo leer el archivo: {e}")
        return

    entropy = _calc_entropy(data)
    label, desc = classify_entropy(entropy)
    unique_bytes = len(set(data))
    counts = _calc_byte_distribution(data)

    # Resultados
    print()
    separator("─", 58)
    result("Archivo",         os.path.basename(path))
    result("Tamaño",          format_size(size))
    result("Bytes únicos",    f"{unique_bytes} / 256")
    result("Entropía",        _color_entropy(entropy))
    result("Clasificación",   white(label))
    result("Interpretación",  dim(desc))
    separator("─", 58)

    _print_entropy_scale(entropy)

    # Diagnóstico adicional
    print()
    if entropy >= 7.9:
        warn("Entropía máxima detectada. Alta probabilidad de cifrado o compresión.")
        info("Posibles causas: archivo .zip, .gz, .enc, o ejecutable empaquetado.")
    elif entropy >= 7.0:
        info("Entropía muy alta. Puede ser un archivo comprimido o con datos binarios densos.")
    elif entropy >= 5.0:
        info("Entropía media-alta. Típico de binarios, multimedia o código compilado.")
    elif entropy >= 3.0:
        ok("Entropía normal. Probablemente texto o datos estructurados.")
    else:
        ok("Entropía baja. Datos muy repetitivos o archivo casi vacío.")

    # Histograma opcional
    print()
    from utils import ask_yes_no
    if ask_yes_no("¿Mostrar histograma de distribución de bytes?", default=True):
        _print_histogram(counts, size)


# ──────────────────────────────────────────────
#  Modo 2: Analizar texto directo
# ──────────────────────────────────────────────
def _mode_analyze_text() -> None:
    section_title("ENTROPÍA DE TEXTO")

    text = prompt("Texto a analizar")
    if not text:
        warn("No se ingresó ningún texto.")
        return

    data     = text.encode("utf-8")
    entropy  = _calc_entropy(data)
    label, desc = classify_entropy(entropy)
    unique   = len(set(data))

    print()
    separator("─", 58)
    result("Texto",           f'"{text}"')
    result("Longitud",        f"{len(text)} caracteres / {len(data)} bytes")
    result("Bytes únicos",    f"{unique} / {len(data)}")
    result("Entropía",        _color_entropy(entropy))
    result("Clasificación",   white(label))
    result("Interpretación",  dim(desc))
    separator("─", 58)

    _print_entropy_scale(entropy)
    print()
    ok("Análisis de texto completado.")


# ──────────────────────────────────────────────
#  Modo 3: Comparar entropía de varios archivos
# ──────────────────────────────────────────────
def _mode_compare_files() -> None:
    section_title("COMPARAR ENTROPÍA DE ARCHIVOS")

    info("Ingresá las rutas de los archivos a comparar (Enter en blanco para terminar).")
    paths = []
    while True:
        p = prompt(f"Archivo {len(paths) + 1}")
        if not p:
            break
        if not validate_file(p):
            warn(f"'{p}' no existe o no es legible. Omitido.")
            continue
        paths.append(p)
        if len(paths) >= 8:
            warn("Máximo 8 archivos por comparación.")
            break

    if not paths:
        warn("No se ingresó ningún archivo válido.")
        return

    results = []
    for path in paths:
        try:
            with open(path, "rb") as f:
                data = f.read()
            ent = _calc_entropy(data)
            label, _ = classify_entropy(ent)
            results.append((os.path.basename(path), ent, label, os.path.getsize(path)))
        except OSError as e:
            warn(f"Error leyendo '{path}': {e}")

    if not results:
        error("No se pudo analizar ningún archivo.")
        return

    # Ordenar de mayor a menor entropía
    results.sort(key=lambda x: x[1], reverse=True)

    print()
    separator("─", 58)
    print(f"  {'Archivo':<25} {'Entropía':>10}  {'Nivel':<12} {'Tamaño'}")
    separator("─", 58)
    for name, ent, label, size in results:
        name_short = name[:24] if len(name) > 24 else name
        print(f"  {white(name_short):<25} {_color_entropy(ent):>10}  {dim(label):<12} {dim(format_size(size))}")
    separator("─", 58)

    top = results[0]
    print(f"\n  {cyan('▲ Mayor entropía:')} {white(top[0])} — {_color_entropy(top[1])}")
    print()
    ok("Comparación completada.")


# ──────────────────────────────────────────────
#  Tabla de referencia de entropía
# ──────────────────────────────────────────────
def _mode_reference_table() -> None:
    section_title("TABLA DE REFERENCIA — ENTROPÍA DE SHANNON")

    print()
    separator("─", 58)
    print(f"  {'Rango (bits)':<18} {'Nivel':<14} {'Descripción'}")
    separator("─", 58)
    for lo, hi, label, desc in ENTROPY_RANGES:
        range_str = f"{lo:.1f} – {hi:.1f}"
        print(f"  {dim(range_str):<18} {white(label):<14} {dim(desc)}")
    separator("─", 58)

    print(f"""
  {cyan('Ejemplos típicos:')}
  {dim('·')} Archivo de texto plano (.txt)     → {green('3.5 – 5.0 bits')}
  {dim('·')} Código fuente (.py, .js)           → {green('4.0 – 5.5 bits')}
  {dim('·')} Ejecutable compilado (.exe, .elf)  → {yellow('5.5 – 7.0 bits')}
  {dim('·')} Imagen (.jpg, .png)                → {yellow('6.0 – 7.5 bits')}
  {dim('·')} Archivo comprimido (.zip, .gz)     → {red('7.5 – 8.0 bits')}
  {dim('·')} Archivo cifrado (AES, RSA)         → {red('7.9 – 8.0 bits')}
  {dim('·')} Malware empaquetado / obfuscado    → {red('> 7.5 bits')}
    """)


# ──────────────────────────────────────────────
#  Submenú
# ──────────────────────────────────────────────
_SUBMENU = [
    ("1", "Analizar entropía de un archivo",         _mode_analyze_file),
    ("2", "Analizar entropía de un texto",            _mode_analyze_text),
    ("3", "Comparar entropía de varios archivos",     _mode_compare_files),
    ("4", "Ver tabla de referencia de entropía",      _mode_reference_table),
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
        section_title("HERRAMIENTA 10 — CALCULADORA DE ENTROPÍA DE ARCHIVOS")
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


if __name__ == "__main__":
    run()
