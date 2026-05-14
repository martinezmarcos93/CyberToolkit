"""
password_generator.py — Herramienta 9: Generador de contraseñas seguras
Genera contraseñas aleatorias criptográficamente seguras y frases Diceware en español.
Usa el módulo 'secrets' (fuente de entropía del SO, apta para uso criptográfico).
"""

import math
import os
import secrets
import string
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils import (
    ok, error, warn, info, result,
    section_title, separator, dim, cyan, green, yellow, white, red, magenta,
    prompt, ask_yes_no, pause,
)
from config import (
    CHARSET_LOWER, CHARSET_UPPER, CHARSET_DIGITS, CHARSET_SYMBOLS, CHARSET_FULL,
    MIN_PASSWORD_LENGTH, DICEWARE_WORDS,
)


# ──────────────────────────────────────────────
#  Cálculo de entropía de una contraseña generada
# ──────────────────────────────────────────────
def _calc_password_entropy(length: int, charset_size: int) -> float:
    """
    Entropía = longitud × log2(tamaño_del_juego_de_caracteres).
    Mide cuántos bits de aleatoriedad tiene la contraseña.
    """
    if charset_size <= 1 or length <= 0:
        return 0.0
    return length * math.log2(charset_size)


def _entropy_label(bits: float) -> tuple[str, str]:
    """Devuelve (etiqueta_coloreada, recomendación) según los bits de entropía."""
    if bits < 28:
        return red("Muy débil"),    "Aumentá la longitud o el juego de caracteres."
    elif bits < 36:
        return red("Débil"),        "Mínimo aceptable solo para sistemas con throttling."
    elif bits < 60:
        return yellow("Moderada"),  "Válida para uso general con gestores de contraseñas."
    elif bits < 80:
        return green("Fuerte"),     "Buena para la mayoría de usos."
    elif bits < 128:
        return green("Muy fuerte"), "Excelente. Resistente a ataques masivos."
    else:
        return magenta("Extrema"),  "Prácticamente irrompible con hardware actual."


# ──────────────────────────────────────────────
#  Generación de contraseña aleatoria
# ──────────────────────────────────────────────
def generate_password(
    length: int,
    use_lower:   bool = True,
    use_upper:   bool = True,
    use_digits:  bool = True,
    use_symbols: bool = True,
    exclude_ambiguous: bool = False,
) -> str:
    """
    Genera una contraseña aleatoria usando secrets.choice().
    Garantiza al menos un carácter de cada grupo activado.
    """
    # Construir el pool de caracteres
    pool = ""
    required = []

    AMBIGUOUS = "0O1lI|"  # caracteres visualmente confusos

    def clean(chars: str) -> str:
        if exclude_ambiguous:
            return "".join(c for c in chars if c not in AMBIGUOUS)
        return chars

    if use_lower:
        c = clean(CHARSET_LOWER)
        pool += c
        required.append(secrets.choice(c))
    if use_upper:
        c = clean(CHARSET_UPPER)
        pool += c
        required.append(secrets.choice(c))
    if use_digits:
        c = clean(CHARSET_DIGITS)
        pool += c
        required.append(secrets.choice(c))
    if use_symbols:
        c = clean(CHARSET_SYMBOLS)
        pool += c
        required.append(secrets.choice(c))

    if not pool:
        raise ValueError("Debe activarse al menos un juego de caracteres.")

    # Completar la longitud con caracteres aleatorios del pool
    remaining = [secrets.choice(pool) for _ in range(length - len(required))]
    password_chars = required + remaining

    # Mezclar con Fisher-Yates usando secrets
    for i in range(len(password_chars) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        password_chars[i], password_chars[j] = password_chars[j], password_chars[i]

    return "".join(password_chars)


# ──────────────────────────────────────────────
#  Generación de frase Diceware
# ──────────────────────────────────────────────
def generate_diceware(
    num_words: int,
    separator_char: str = "-",
    capitalize: bool = True,
) -> str:
    """
    Genera una frase de contraseña Diceware eligiendo palabras al azar
    de la lista DICEWARE_WORDS con secrets.choice().
    """
    words = [secrets.choice(DICEWARE_WORDS) for _ in range(num_words)]
    if capitalize:
        words = [w.capitalize() for w in words]
    return separator_char.join(words)


# ──────────────────────────────────────────────
#  Display de resultado
# ──────────────────────────────────────────────
def _display_password(password: str, charset_size: int, label_extra: str = "") -> None:
    """Muestra la contraseña con su análisis de entropía."""
    bits = _calc_password_entropy(len(password), charset_size)
    strength_label, recommendation = _entropy_label(bits)

    print()
    separator("─", 58)
    print(f"\n  {cyan('Contraseña generada:')}")
    print(f"\n    {green(password)}\n")
    separator("─", 58)
    result("Longitud",        f"{len(password)} caracteres")
    result("Juego de chars",  f"{charset_size} símbolos posibles")
    result("Entropía",        f"{bits:.1f} bits")
    result("Fortaleza",       strength_label)
    if label_extra:
        result("Info extra",  dim(label_extra))
    separator("─", 58)
    info(recommendation)
    print()


# ──────────────────────────────────────────────
#  Modo 1: Contraseña aleatoria
# ──────────────────────────────────────────────
def _mode_random_password() -> None:
    section_title("GENERAR CONTRASEÑA ALEATORIA")

    # Longitud
    raw_len = prompt("Longitud de la contraseña", default=str(MIN_PASSWORD_LENGTH))
    try:
        length = int(raw_len)
        if length < 4:
            warn("Longitud mínima es 4. Usando 4.")
            length = 4
        if length > 512:
            warn("Longitud máxima es 512. Usando 512.")
            length = 512
    except ValueError:
        error("Longitud inválida.")
        return

    # Opciones de juego de caracteres
    print()
    info("Configurá el juego de caracteres:")
    use_lower   = ask_yes_no(f"  ¿Incluir minúsculas?  (a-z, {len(CHARSET_LOWER)} chars)", default=True)
    use_upper   = ask_yes_no(f"  ¿Incluir mayúsculas?  (A-Z, {len(CHARSET_UPPER)} chars)", default=True)
    use_digits  = ask_yes_no(f"  ¿Incluir dígitos?     (0-9, {len(CHARSET_DIGITS)} chars)", default=True)
    use_symbols = ask_yes_no(f"  ¿Incluir símbolos?    (!@#..., {len(CHARSET_SYMBOLS)} chars)", default=True)
    no_ambig    = ask_yes_no("  ¿Excluir caracteres ambiguos? (0,O,1,l,I,|)", default=False)

    if not any([use_lower, use_upper, use_digits, use_symbols]):
        error("Debe activarse al menos un juego de caracteres.")
        return

    # Calcular tamaño real del pool
    pool = ""
    AMBIGUOUS = "0O1lI|"
    def clean(chars):
        return "".join(c for c in chars if c not in AMBIGUOUS) if no_ambig else chars

    if use_lower:   pool += clean(CHARSET_LOWER)
    if use_upper:   pool += clean(CHARSET_UPPER)
    if use_digits:  pool += clean(CHARSET_DIGITS)
    if use_symbols: pool += clean(CHARSET_SYMBOLS)
    charset_size = len(pool)

    # Cuántas contraseñas generar
    raw_qty = prompt("¿Cuántas contraseñas generar?", default="1")
    try:
        qty = max(1, min(int(raw_qty), 20))
    except ValueError:
        qty = 1

    print()
    info(f"Generando {qty} contraseña(s) de {length} caracteres...")

    for i in range(qty):
        try:
            pwd = generate_password(length, use_lower, use_upper, use_digits, use_symbols, no_ambig)
        except ValueError as e:
            error(str(e))
            return

        if qty == 1:
            _display_password(pwd, charset_size)
        else:
            bits = _calc_password_entropy(length, charset_size)
            label, _ = _entropy_label(bits)
            print(f"  {dim(f'{i+1}.')} {green(pwd)}  {dim(f'({bits:.0f} bits')} {label}{dim(')')}")

    if qty > 1:
        print()
        bits = _calc_password_entropy(length, charset_size)
        label, rec = _entropy_label(bits)
        result("Entropía por contraseña", f"{bits:.1f} bits — {label}")
        info(rec)


# ──────────────────────────────────────────────
#  Modo 2: Frase Diceware
# ──────────────────────────────────────────────
def _mode_diceware() -> None:
    section_title("GENERAR FRASE DICEWARE")

    info("Una frase Diceware combina palabras al azar para crear")
    info("contraseñas memorables pero criptográficamente fuertes.")
    print()

    raw_words = prompt("¿Cuántas palabras?", default="5")
    try:
        num_words = int(raw_words)
        if num_words < 3:
            warn("Mínimo recomendado: 3 palabras. Usando 3.")
            num_words = 3
        if num_words > 12:
            warn("Máximo: 12 palabras. Usando 12.")
            num_words = 12
    except ValueError:
        error("Número inválido.")
        return

    sep = prompt("Separador entre palabras", default="-")
    if not sep:
        sep = "-"
    capitalize = ask_yes_no("¿Capitalizar primera letra de cada palabra?", default=True)

    raw_qty = prompt("¿Cuántas frases generar?", default="1")
    try:
        qty = max(1, min(int(raw_qty), 10))
    except ValueError:
        qty = 1

    # Entropía: log2(N_palabras) por cada palabra elegida
    vocab_size = len(DICEWARE_WORDS)
    bits = num_words * math.log2(vocab_size)

    print()
    info(f"Vocabulario: {vocab_size} palabras · Entropía: {bits:.1f} bits por frase")
    print()

    for i in range(qty):
        phrase = generate_diceware(num_words, sep, capitalize)
        label, _ = _entropy_label(bits)

        if qty == 1:
            separator("─", 58)
            print(f"\n  {cyan('Frase generada:')}")
            print(f"\n    {green(phrase)}\n")
            separator("─", 58)
            result("Palabras",    str(num_words))
            result("Vocabulario", f"{vocab_size} palabras en español")
            result("Entropía",    f"{bits:.1f} bits")
            result("Fortaleza",   label)
            separator("─", 58)
            _, rec = _entropy_label(bits)
            info(rec)
        else:
            print(f"  {dim(f'{i+1}.')} {green(phrase)}  {dim(f'({bits:.0f} bits')} {label}{dim(')')}")

    print()


# ──────────────────────────────────────────────
#  Modo 3: Explicación didáctica
# ──────────────────────────────────────────────
def _mode_explain() -> None:
    section_title("¿POR QUÉ IMPORTA LA ENTROPÍA?")

    print(f"""
  {white('Entropía y contraseñas')}
  {dim('─' * 56)}

  La entropía mide cuánta aleatoriedad tiene una contraseña.
  A mayor entropía, más tiempo tarda un atacante en encontrarla
  por fuerza bruta, independientemente del hardware que use.

  {cyan('Fórmula:')}  H = longitud × log₂(tamaño_del_juego_de_caracteres)

  {white('Ejemplos de entropía:')}
  {dim('·')} "abc"           →  {red(' ~14 bits')}   Crackeada en microsegundos
  {dim('·')} "P@ss1234"      →  {yellow(' ~52 bits')}   Minutos con GPU moderna
  {dim('·')} 12 chars mixtos →  {green(' ~79 bits')}   Años con el hardware actual
  {dim('·')} 5 palabras DW   →  {green(' ~99 bits')}   Décadas incluso con GPUs
  {dim('·')} 16 chars mixtos →  {magenta('~105 bits')}   Prácticamente irrompible

  {white('¿Por qué usar secrets en lugar de random?')}
  {dim('·')} random() usa un PRNG (Pseudo-Random Number Generator)
  {dim('·')} secrets() usa /dev/urandom o CryptGenRandom del SO
  {dim('·')} Solo secrets() es apto para uso criptográfico
  {dim('·')} random() puede predecirse si se conoce la semilla

  {white('¿Diceware vs contraseña aleatoria?')}
  {dim('·')} Diceware es más fácil de memorizar
  {dim('·')} Una contraseña aleatoria de igual entropía ocupa menos espacio
  {dim('·')} Para gestores de contraseñas: aleatoria. Para recordar: Diceware.
    """)


# ──────────────────────────────────────────────
#  Submenú
# ──────────────────────────────────────────────
_SUBMENU = [
    ("1", "Generar contraseña aleatoria",         _mode_random_password),
    ("2", "Generar frase Diceware",               _mode_diceware),
    ("3", "¿Por qué importa la entropía?",        _mode_explain),
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
        section_title("HERRAMIENTA 9 — GENERADOR DE CONTRASEÑAS SEGURAS")
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
