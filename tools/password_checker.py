"""
password_checker.py — Herramienta 2: Verificador de fortaleza de contraseñas
Evalúa entropía, detecta contraseñas comunes y estima tiempos de cracking.
La contraseña NUNCA se almacena en disco, solo vive en memoria durante la sesión.
"""

import math
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils import (
    ok, error, warn, info, result,
    section_title, separator, dim, cyan, green, yellow, white, red, magenta,
    prompt, ask_yes_no, pause,
)
from config import (
    WEAK_PASSWORDS, CRACK_SPEEDS, DEFAULT_HASH_ALGO,
    CHARSET_LOWER, CHARSET_UPPER, CHARSET_DIGITS, CHARSET_SYMBOLS,
)


# ──────────────────────────────────────────────
#  Análisis del juego de caracteres usado
# ──────────────────────────────────────────────
def _detect_charset_size(password: str) -> tuple[int, list[str]]:
    """
    Detecta qué grupos de caracteres usa la contraseña y
    devuelve (tamaño_del_pool_estimado, lista_de_grupos).
    """
    groups = []
    pool_size = 0

    if any(c in CHARSET_LOWER for c in password):
        pool_size += len(CHARSET_LOWER)   # 26
        groups.append("minúsculas (a-z)")
    if any(c in CHARSET_UPPER for c in password):
        pool_size += len(CHARSET_UPPER)   # 26
        groups.append("mayúsculas (A-Z)")
    if any(c in CHARSET_DIGITS for c in password):
        pool_size += len(CHARSET_DIGITS)  # 10
        groups.append("dígitos (0-9)")
    if any(c in CHARSET_SYMBOLS for c in password):
        pool_size += len(CHARSET_SYMBOLS) # 32
        groups.append("símbolos (!@#...)")
    if any(ord(c) > 127 for c in password):
        pool_size += 128                  # Unicode extendido aprox.
        groups.append("caracteres unicode")

    return max(pool_size, 1), groups


# ──────────────────────────────────────────────
#  Cálculo de entropía
# ──────────────────────────────────────────────
def _calc_entropy(length: int, charset_size: int) -> float:
    """Entropía teórica = longitud × log2(pool)."""
    if charset_size <= 1 or length <= 0:
        return 0.0
    return length * math.log2(charset_size)


# ──────────────────────────────────────────────
#  Estimación de tiempo de cracking
# ──────────────────────────────────────────────
def _format_time(seconds: float) -> str:
    """Convierte segundos a una cadena legible."""
    if seconds < 0.001:
        return green("instantáneo")
    if seconds < 1:
        return red(f"{seconds * 1000:.0f} milisegundos")
    if seconds < 60:
        return red(f"{seconds:.1f} segundos")
    if seconds < 3600:
        return red(f"{seconds / 60:.1f} minutos")
    if seconds < 86400:
        return yellow(f"{seconds / 3600:.1f} horas")
    if seconds < 86400 * 30:
        return yellow(f"{seconds / 86400:.1f} días")
    if seconds < 86400 * 365:
        return yellow(f"{seconds / (86400 * 30):.1f} meses")
    if seconds < 86400 * 365 * 1000:
        return green(f"{seconds / (86400 * 365):.1f} años")
    if seconds < 86400 * 365 * 1_000_000:
        return green(f"{seconds / (86400 * 365 * 1000):.1f} miles de años")
    return magenta("millones de años")


def _estimate_crack_times(total_combinations: float) -> dict[str, dict[str, str]]:
    """
    Estima tiempos de cracking para cada algoritmo en sus modos
    offline (GPU), offline (CPU) y online (throttled).
    Asume ataque de fuerza bruta: tiempo = total_combinaciones / velocidad / 2 (promedio).
    """
    times = {}
    for algo, data in CRACK_SPEEDS.items():
        # En promedio se encuentra a la mitad del espacio de búsqueda
        avg_attempts = total_combinations / 2
        times[algo] = {
            "gpu":    _format_time(avg_attempts / data["offline_gpu"]),
            "cpu":    _format_time(avg_attempts / data["offline_cpu"]),
            "online": _format_time(avg_attempts / (data["online"] / 60)),  # intentos/min → /seg
        }
    return times


# ──────────────────────────────────────────────
#  Detección de patrones débiles
# ──────────────────────────────────────────────
def _detect_patterns(password: str) -> list[str]:
    """
    Detecta patrones que reducen la seguridad real de la contraseña.
    Devuelve lista de advertencias.
    """
    warnings = []
    low = password.lower()

    # Secuencias de teclado
    keyboard_seqs = [
        "qwerty", "qwertyuiop", "asdfgh", "asdfghjkl",
        "zxcvbn", "1234567", "7654321", "abcdef", "fedcba",
    ]
    for seq in keyboard_seqs:
        if seq in low:
            warnings.append(f"Contiene secuencia de teclado: '{seq}'")

    # Solo números
    if password.isdigit():
        warnings.append("Solo contiene dígitos")

    # Solo letras
    if password.isalpha():
        warnings.append("Solo contiene letras")

    # Repetición de caracteres
    if re.search(r'(.)\1{2,}', password):
        warnings.append("Tiene 3 o más caracteres repetidos consecutivos")

    # Sustituciones obvias (leet speak)
    leet_map = {'@': 'a', '3': 'e', '1': 'i', '0': 'o', '5': 's', '$': 's', '4': 'a'}
    de_leeted = password.lower()
    for k, v in leet_map.items():
        de_leeted = de_leeted.replace(k, v)
    if de_leeted in WEAK_PASSWORDS:
        warnings.append("Es una contraseña común con sustituciones simples (leet speak)")

    # Año al final o al principio
    if re.search(r'(19|20)\d{2}', password):
        warnings.append("Contiene un año (patrón frecuente en ataques de diccionario)")

    # Longitud crítica
    if len(password) < 8:
        warnings.append("Longitud menor a 8 caracteres")

    return warnings


# ──────────────────────────────────────────────
#  Puntuación global
# ──────────────────────────────────────────────
def _score_password(
    entropy: float,
    is_common: bool,
    patterns: list[str],
) -> tuple[str, str]:
    """
    Devuelve (etiqueta_coloreada, recomendación) para la contraseña analizada.
    """
    if is_common:
        return red("MUY DÉBIL ✗"), "Está en la lista de contraseñas más usadas del mundo. Cambiala YA."

    # Penalizar por patrones
    penalty = len(patterns) * 8
    effective_entropy = max(0.0, entropy - penalty)

    if effective_entropy < 28:
        return red("MUY DÉBIL ✗"),    "Demasiado corta o predecible. Usá al menos 12 caracteres mixtos."
    elif effective_entropy < 40:
        return red("DÉBIL ✗"),        "Fácilmente crackeable. Aumentá longitud y variedad de caracteres."
    elif effective_entropy < 60:
        return yellow("MODERADA ~"),  "Aceptable, pero mejorable. Añadí símbolos o más longitud."
    elif effective_entropy < 80:
        return green("FUERTE ✓"),     "Buena contraseña. Guardala en un gestor de contraseñas."
    elif effective_entropy < 110:
        return green("MUY FUERTE ✓"), "Excelente fortaleza. Resistente a ataques masivos."
    else:
        return magenta("EXTREMA ✓"),  "Prácticamente irrompible con el hardware actual."


# ──────────────────────────────────────────────
#  Barra visual de fortaleza
# ──────────────────────────────────────────────
def _print_strength_bar(entropy: float, max_entropy: float = 120.0) -> None:
    """Muestra una barra de fortaleza proporcional a la entropía."""
    BAR_W  = 40
    ratio  = min(entropy / max_entropy, 1.0)
    filled = int(ratio * BAR_W)
    empty  = BAR_W - filled

    if ratio < 0.33:
        color = red
    elif ratio < 0.60:
        color = yellow
    elif ratio < 0.80:
        color = green
    else:
        color = magenta

    bar = color("█" * filled) + dim("░" * empty)
    pct = ratio * 100
    print(f"\n  Fortaleza: [{bar}] {dim(f'{pct:.0f}%')}")


# ──────────────────────────────────────────────
#  Modo 1: Analizar una contraseña
# ──────────────────────────────────────────────
def _mode_check_password() -> None:
    section_title("VERIFICAR FORTALEZA DE CONTRASEÑA")

    warn("La contraseña NO se almacena en disco. Solo vive en memoria durante este análisis.")
    print()

    # Leer sin echo si es posible
    try:
        import getpass
        password = getpass.getpass(f"  {cyan('❯')} Ingresá la contraseña (oculta): ")
    except Exception:
        password = prompt("Ingresá la contraseña")

    if not password:
        warn("No se ingresó ninguna contraseña.")
        return

    # Análisis
    charset_size, groups = _detect_charset_size(password)
    entropy = _calc_entropy(len(password), charset_size)
    is_common = password.lower() in WEAK_PASSWORDS
    patterns = _detect_patterns(password)
    total_combinations = charset_size ** len(password)
    crack_times = _estimate_crack_times(total_combinations)
    strength_label, recommendation = _score_password(entropy, is_common, patterns)

    # ── Resultados ──
    print()
    separator("═", 58)
    print(f"  {white('RESULTADO DEL ANÁLISIS')}")
    separator("─", 58)
    result("Longitud",            f"{len(password)} caracteres")
    result("Juegos de caracteres", ", ".join(groups) if groups else "ninguno detectado")
    result("Tamaño del pool",     f"{charset_size} símbolos posibles")
    result("Entropía teórica",    f"{entropy:.1f} bits")
    result("Combinaciones",       f"{total_combinations:.2e}")
    separator("─", 58)

    # Presencia en diccionario
    if is_common:
        print(f"  {red('✗ EN DICCIONARIO')} — Contraseña extremadamente común")
    else:
        print(f"  {green('✓ NO en diccionario')} — No está en el top de contraseñas comunes")

    # Patrones
    if patterns:
        print()
        warn(f"Patrones débiles detectados ({len(patterns)}):")
        for p in patterns:
            print(f"    {red('·')} {p}")
    else:
        print(f"\n  {green('✓ Sin patrones débiles detectados')}")

    # Puntuación
    _print_strength_bar(entropy)
    print(f"\n  Fortaleza general: {strength_label}")
    separator("─", 58)

    # Tiempos de cracking
    print(f"\n  {white('ESTIMACIÓN DE TIEMPO DE CRACKING')}")
    separator("─", 58)
    print(f"  {'Algoritmo':<12} {'GPU (offline)':<22} {'CPU (offline)':<22} {'Online'}")
    separator("─", 58)
    for algo, times in crack_times.items():
        print(f"  {dim(algo):<12} {times['gpu']:<22} {times['cpu']:<22} {times['online']}")
    separator("─", 58)

    print(f"\n  {cyan('Recomendación:')} {recommendation}")
    print()
    ok("Análisis completado. La contraseña no fue guardada.")


# ──────────────────────────────────────────────
#  Modo 2: Analizar contraseña desde argumento (sin getpass)
#  Útil para pruebas con contraseñas no sensibles
# ──────────────────────────────────────────────
def _mode_check_sample() -> None:
    section_title("ANALIZAR MUESTRA DE CONTRASEÑAS")

    info("Ingresá contraseñas de ejemplo para análisis comparativo.")
    info("No uses tus contraseñas reales en este modo (se muestran en pantalla).")
    print()

    samples = []
    while True:
        pwd = prompt(f"Contraseña {len(samples) + 1} (Enter para terminar)")
        if not pwd:
            break
        samples.append(pwd)
        if len(samples) >= 6:
            warn("Máximo 6 muestras por comparación.")
            break

    if not samples:
        warn("No se ingresó ninguna contraseña.")
        return

    print()
    separator("─", 70)
    print(f"  {'Contraseña':<25} {'Bits':>6}  {'En dicc.':<10} {'Fortaleza'}")
    separator("─", 70)

    for pwd in samples:
        charset_size, _ = _detect_charset_size(pwd)
        entropy = _calc_entropy(len(pwd), charset_size)
        is_common = pwd.lower() in WEAK_PASSWORDS
        patterns = _detect_patterns(pwd)
        strength_label, _ = _score_password(entropy, is_common, patterns)

        pwd_display = pwd[:24] if len(pwd) > 24 else pwd
        common_str  = red("Sí ✗") if is_common else green("No ✓")

        print(f"  {dim(pwd_display):<25} {dim(f'{entropy:.1f}'):>6}  {common_str:<10} {strength_label}")

    separator("─", 70)
    print()


# ──────────────────────────────────────────────
#  Modo 3: Explicación didáctica
# ──────────────────────────────────────────────
def _mode_explain() -> None:
    section_title("¿CÓMO SE CRACKEAN LAS CONTRASEÑAS?")

    print(f"""
  {white('Tipos de ataque')}
  {dim('─' * 56)}

  {cyan('1. Diccionario')}
     El atacante prueba palabras comunes, contraseñas filtradas
     (HaveIBeenPwned) y sus variantes con leet speak o números.
     → Mitiga: no uses palabras reales ni sustituciones obvias.

  {cyan('2. Fuerza bruta')}
     Prueba todas las combinaciones posibles del espacio de chars.
     Con una GPU moderna: {red('60 mil millones')} de hashes MD5 por segundo.
     → Mitiga: longitud y variedad de caracteres.

  {cyan('3. Ataque híbrido')}
     Combina diccionario + mutaciones (mayúsculas, añadir números).
     → Mitiga: entropía real alta, no solo apariencia de complejidad.

  {cyan('4. Ataque online')}
     Prueba contraseñas directamente en el servicio (login web).
     Limitado por throttling, CAPTCHA y bloqueo de cuenta.
     → Suele ser ~{yellow('100-1000 intentos/min')}.

  {white('Diferencia offline vs online')}
  {dim('─' * 56)}
  Offline: el atacante tiene el hash (base de datos filtrada).
  Puede probar miles de millones por segundo sin restricciones.

  Online: ataca directamente el servicio. Mucho más lento,
  pero el hash no está expuesto.

  {white('¿Qué hace segura una contraseña?')}
  {dim('─' * 56)}
  {dim('·')} {green('Longitud')} — el factor más importante (más bits)
  {dim('·')} {green('Variedad')} — mix de chars aumenta el pool
  {dim('·')} {green('Aleatoriedad')} — generada con secrets, no inventada
  {dim('·')} {red('NO')} reutilización entre servicios
  {dim('·')} {red('NO')} información personal (fechas, nombres)
    """)


# ──────────────────────────────────────────────
#  Submenú
# ──────────────────────────────────────────────
_SUBMENU = [
    ("1", "Analizar mi contraseña (entrada oculta)",     _mode_check_password),
    ("2", "Comparar muestras de contraseñas",            _mode_check_sample),
    ("3", "¿Cómo se crackean las contraseñas?",          _mode_explain),
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
        section_title("HERRAMIENTA 2 — VERIFICADOR DE FORTALEZA DE CONTRASEÑAS")
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
