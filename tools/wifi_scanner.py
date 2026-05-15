"""
wifi_scanner.py — Herramienta 14: Escáner de redes Wi-Fi
Escaneo de redes wireless cercanas con detección de cifrado (WEP/WPA/WPA2/WPA3)
e intensidad de señal. (Implementación inicial para Windows vía netsh).
"""

import sys
import os
import subprocess
import re

# Asegura que el directorio raíz esté en el path al ejecutar directamente
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils import (
    ok, error, warn, info, result,
    section_title, separator, dim, cyan, green, yellow, white, red,
    prompt, pause
)


def _scan_windows() -> list[dict]:
    """Usa netsh wlan show networks mode=bssid para escanear en Windows."""
    networks = []
    try:
        # Forzamos chcp 437 para tener salida en inglés o al menos ASCII sin acentos problemáticos,
        # pero netsh respeta el idioma del SO. Buscamos patrones comunes.
        cmd = 'netsh wlan show networks mode=bssid'
        output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, text=True, errors="replace")
        
        current_net = None
        
        for line in output.split('\n'):
            line = line.strip()
            if not line:
                continue
                
            # Detectar inicio de una red (SSID)
            # Ej: SSID 1 : MiRedWifi
            ssid_match = re.match(r"^SSID\s+\d+\s+:\s+(.*)$", line, re.IGNORECASE)
            if ssid_match:
                if current_net:
                    networks.append(current_net)
                current_net = {
                    "ssid": ssid_match.group(1).strip() or "<Oculto>",
                    "auth": "Desconocido",
                    "cipher": "Desconocido",
                    "bssids": []
                }
                continue
                
            if not current_net:
                continue
                
            # Autenticación / Cifrado
            if "Autenticaci" in line or "Authentication" in line:
                parts = line.split(":")
                if len(parts) > 1:
                    current_net["auth"] = parts[1].strip()
            
            if "Cifrado" in line or "Encryption" in line:
                parts = line.split(":")
                if len(parts) > 1:
                    current_net["cipher"] = parts[1].strip()
                    
            # BSSID (MAC Address) y Señal
            bssid_match = re.match(r"^BSSID\s+\d+\s+:\s+([0-9a-fA-F:]+)$", line, re.IGNORECASE)
            if bssid_match:
                current_net["bssids"].append({
                    "mac": bssid_match.group(1).strip(),
                    "signal": "0%",
                    "channel": "?"
                })
                
            if "Se" in line and "al" in line or "Signal" in line:
                parts = line.split(":")
                if len(parts) > 1 and current_net["bssids"]:
                    current_net["bssids"][-1]["signal"] = parts[1].strip()
                    
            if "Canal" in line or "Channel" in line:
                parts = line.split(":")
                if len(parts) > 1 and current_net["bssids"]:
                    current_net["bssids"][-1]["channel"] = parts[1].strip()

        if current_net:
            networks.append(current_net)
            
    except subprocess.CalledProcessError as e:
        warn(f"Error al ejecutar netsh: {e}")
    except FileNotFoundError:
        warn("Comando 'netsh' no encontrado. ¿Estás en Windows?")
        
    return networks


def _scan_linux() -> list[dict]:
    """Usa nmcli para escanear en Linux (NetworkManager)."""
    networks = []
    try:
        cmd = 'nmcli -t -f SSID,BSSID,SECURITY,SIGNAL,CHAN dev wifi'
        output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, text=True, errors="replace")
        
        for line in output.split('\n'):
            line = line.strip()
            if not line:
                continue
            
            # nmcli separa por ':' pero las MACs tienen ':'
            # El formato es: SSID:BSSID:SECURITY:SIGNAL:CHAN
            # Como la MAC tiene 5 dos puntos, dividimos de forma cuidadosa.
            # Mejor usar awk o expresiones regulares si fuera un bash script,
            # pero aquí podemos hacer split por ':' e inferir.
            # Por simplicidad, esta es una implementación educativa básica.
            parts = line.split(':')
            if len(parts) >= 10:
                ssid = parts[0]
                mac = ":".join(parts[1:7])
                sec = parts[7]
                sig = parts[8] + "%"
                chan = parts[9]
                
                net = {
                    "ssid": ssid or "<Oculto>",
                    "auth": sec if sec else "Abierta",
                    "cipher": "-",
                    "bssids": [{"mac": mac, "signal": sig, "channel": chan}]
                }
                networks.append(net)
    except subprocess.CalledProcessError as e:
        warn(f"Error al ejecutar nmcli: {e}")
    except FileNotFoundError:
        warn("Comando 'nmcli' no encontrado. ¿Estás en Linux con NetworkManager?")
        
    return networks


def _mode_scan() -> None:
    section_title("ESCÁNER DE REDES WI-FI")

    info("Iniciando escaneo de redes (puede tardar unos segundos)...")
    
    if os.name == 'nt':
        networks = _scan_windows()
    else:
        networks = _scan_linux()

    if not networks:
        error("No se encontraron redes o la interfaz Wi-Fi está apagada/no existe.")
        return

    print()
    separator("═", 75)
    print(f"  {white('REDES WI-FI DETECTADAS')}")
    separator("─", 75)
    print(f"  {'SSID':<25} {'Señal':<8} {'Canal':<6} {'Seguridad'}")
    separator("─", 75)

    vuln_networks = 0

    # Ordenar por intensidad de señal (del primer BSSID)
    def _get_sig(net):
        if not net["bssids"]: return 0
        sig_str = net["bssids"][0]["signal"].replace("%", "").strip()
        try: return int(sig_str)
        except ValueError: return 0

    networks.sort(key=_get_sig, reverse=True)

    for net in networks:
        ssid = net["ssid"]
        if len(ssid) > 23:
            ssid = ssid[:20] + "..."
            
        auth = net["auth"].upper()
        
        # Determinar riesgo de la red
        is_vuln = False
        if "ABIERTA" in auth or "OPEN" in auth or auth == "" or "NONE" in auth:
            is_vuln = True
            auth_color = red
            auth_text = "Abierta (Sin cifrado) ⚠"
        elif "WEP" in auth:
            is_vuln = True
            auth_color = red
            auth_text = "WEP (Obsoleto) ⚠"
        elif "WPA2" in auth or "WPA3" in auth:
            auth_color = green
            auth_text = auth
        elif "WPA" in auth:
            auth_color = yellow
            auth_text = auth + " (Débil)"
        else:
            auth_color = dim
            auth_text = auth

        if is_vuln:
            vuln_networks += 1

        bssid_info = net["bssids"][0] if net["bssids"] else {"signal": "?", "channel": "?"}
        sig = bssid_info["signal"]
        chan = bssid_info["channel"]

        print(f"  {white(ssid):<25} {cyan(sig):<8} {dim(chan):<6} {auth_color(auth_text)}")

    separator("─", 75)
    result("Total de redes", str(len(networks)))
    if vuln_networks > 0:
        result("Redes riesgosas", red(str(vuln_networks)))
    print()


def _mode_explain() -> None:
    section_title("SEGURIDAD EN REDES WI-FI (802.11)")

    print(f"""
  {white('1. Redes Abiertas (Sin Cifrado)')}
  {dim('─' * 56)}
  Cualquiera puede capturar el tráfico (sniffing) usando modo monitor.
  Todo lo que no sea HTTPS (texto plano) puede ser leído y modificado.
  Ataques comunes: Evil Twin, ARP Spoofing.

  {white('2. WEP (Wired Equivalent Privacy)')}
  {dim('─' * 56)}
  El protocolo de seguridad original, {red('totalmente roto')}. 
  Puede ser crackeado en segundos capturando suficientes paquetes (IVs) 
  e inyectando tráfico (ataque PTW o KoreK).

  {white('3. WPA / WPA2 (Wi-Fi Protected Access)')}
  {dim('─' * 56)}
  Usa cifrado robusto (AES/CCMP). Sin embargo, las redes WPA2-Personal (PSK) 
  son vulnerables a {yellow('ataques de diccionario')} si se captura el 
  "4-way handshake" que ocurre cuando un cliente legítimo se conecta.
  También vulnerable al ataque {yellow('KRACK')} (depende del parche del cliente).

  {white('4. WPA3')}
  {dim('─' * 56)}
  El estándar más nuevo. Reemplaza PSK por SAE (Simultaneous Authentication 
  of Equals), haciendo que los ataques de diccionario offline sean imposibles
  (aunque han surgido vulnerabilidades como "Dragonblood").

  {white('5. WPS (Wi-Fi Protected Setup)')}
  {dim('─' * 56)}
  Un pin de 8 dígitos para conectarse rápido. Vulnerable a ataques de fuerza 
  bruta ({red('Reaver')} / Pixie Dust), ya que el pin se valida en mitades.
    """)


# ──────────────────────────────────────────────
#  Submenú
# ──────────────────────────────────────────────
_SUBMENU = [
    ("1", "Escanear redes Wi-Fi cercanas",        _mode_scan),
    ("2", "¿Cómo se hackea el Wi-Fi?",            _mode_explain),
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
        section_title("HERRAMIENTA 14 — ESCÁNER WI-FI")
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
