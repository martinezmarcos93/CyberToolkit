"""
honeypot.py — Herramienta 23: Honeypot de servicios TCP
Levanta servicios falsos simulados (SSH, HTTP, FTP, MySQL) para 
atrapar y registrar la actividad de escáneres y atacantes.
"""

import sys
import os
import socket
import threading
import time

# Asegura que el directorio raíz esté en el path al ejecutar directamente
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils import (
    ok, error, warn, info, result,
    section_title, separator, dim, cyan, green, yellow, white, red, magenta,
    prompt, pause
)


# Configuración de los servicios simulados
_SERVICES = {
    21:   {"name": "FTP",   "banner": b"220 (vsFTPd 3.0.3)\r\n"},
    22:   {"name": "SSH",   "banner": b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n"},
    80:   {"name": "HTTP",  "banner": b""}, # El banner se envía tras la petición
    3306: {"name": "MySQL", "banner": b"Y\x00\x00\x00\x0a8.0.28-0ubuntu0.20.04.3\x00\x01\x00\x00\x00\x00\x00\x00\x00"},
}

_is_running = False
_active_threads = []
_logs = []

def _log_event(port: int, ip: str, event_type: str, data: str = ""):
    """Registra la actividad del honeypot en memoria (y podría ser en archivo)."""
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    service_name = _SERVICES.get(port, {}).get("name", "Unknown")
    
    msg = f"[{timestamp}] [Port {port}/{service_name}] [{event_type}] IP: {ip}"
    if data:
        msg += f" | Data: {data}"
        
    _logs.append(msg)
    
    # Imprimir en vivo (cuidando que el texto no se superponga si hay muchas peticiones)
    color_ip = cyan(ip)
    if event_type == "CONNECT":
        print(f"\r  {green('(+) CONEXIÓN:')} {color_ip} al puerto {port} ({service_name})" + " "*10)
    elif event_type == "DATA":
        print(f"\r  {red('(!) PAYLOAD:')}  {color_ip} envió: {dim(repr(data))}" + " "*10)


def _handle_connection(client_socket: socket.socket, addr: tuple, port: int):
    """Maneja la conexión individual de un atacante."""
    ip, _ = addr
    _log_event(port, ip, "CONNECT")
    
    service = _SERVICES.get(port)
    if not service:
        client_socket.close()
        return
        
    try:
        client_socket.settimeout(5.0)
        
        # 1. Enviar banner falso si el protocolo lo requiere (FTP, SSH, MySQL)
        if service["banner"] and port != 80:
            client_socket.sendall(service["banner"])
            
        # 2. Leer lo que el atacante envía (Payload / Exploits)
        data = client_socket.recv(1024)
        if data:
            decoded_data = data.decode('utf-8', errors='replace').strip()
            _log_event(port, ip, "DATA", decoded_data[:100]) # Guardar max 100 chars
            
            # 3. Respuesta falsa para HTTP
            if port == 80:
                http_resp = (
                    b"HTTP/1.1 200 OK\r\n"
                    b"Server: Apache/2.4.41 (Ubuntu)\r\n"
                    b"Content-Type: text/html\r\n"
                    b"\r\n"
                    b"<html><body><h1>It works!</h1></body></html>\n"
                )
                client_socket.sendall(http_resp)
                
    except Exception:
        pass
    finally:
        try:
            client_socket.close()
        except:
            pass


def _start_listener(port: int):
    """Inicia un socket a la escucha en un puerto específico."""
    global _is_running
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server.bind(("0.0.0.0", port))
        server.listen(5)
        # Timeout para que el accept() no se bloquee eternamente y podamos apagarlo
        server.settimeout(1.0) 
    except Exception as e:
        print(f"\r  {red('Error')} al vincular puerto {port}: {e}")
        return

    while _is_running:
        try:
            client, addr = server.accept()
            # Lanzar un hilo para no bloquear el listener principal
            t = threading.Thread(target=_handle_connection, args=(client, addr, port), daemon=True)
            t.start()
        except socket.timeout:
            continue
        except Exception:
            break
            
    server.close()


def _mode_start() -> None:
    global _is_running
    section_title("HONEYPOT TCP LIGERO")
    
    print(f"Se van a simular los siguientes servicios en todas las interfaces (0.0.0.0):")
    for p, s in _SERVICES.items():
        print(f"  {dim('·')} Puerto {cyan(str(p)):<5} -> {white(s['name'])}")
        
    print()
    warn("Asegurate de NO tener servicios reales corriendo en estos puertos locales.")
    if prompt("¿Iniciar Honeypot? (s/n)", default="n").lower() != "s":
        return
        
    _is_running = True
    _logs.clear()
    
    info("Iniciando hilos del honeypot...")
    
    for port in _SERVICES.keys():
        t = threading.Thread(target=_start_listener, args=(port,), daemon=True)
        _active_threads.append(t)
        t.start()
        
    print()
    info(f"Honeypot activo. (Presioná {yellow('Ctrl+C')} para detener)")
    separator("─", 60)
    
    try:
        # Loop principal esperando la interrupción del usuario
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\r" + " "*60 + "\r", end="")
        warn("Deteniendo honeypot... (esperando cierre de puertos)")
        _is_running = False
        
        # Esperar un poco a que los hilos mueran solos gracias al timeout
        for t in _active_threads:
            t.join(timeout=1.5)
            
        _active_threads.clear()
        
    print()
    result("Eventos capturados", str(len(_logs)))
    if _logs:
        if prompt("¿Deseas exportar el log capturado a honeypot.log? (s/n)", default="s").lower() == "s":
            try:
                with open("honeypot.log", "w", encoding="utf-8") as f:
                    for l in _logs:
                        f.write(l + "\n")
                ok("Logs exportados a honeypot.log")
            except Exception as e:
                error(f"No se pudo guardar el archivo: {e}")
    print()


def _mode_explain() -> None:
    section_title("¿QUÉ ES UN HONEYPOT?")

    print(f"""
  {white('1. Concepto Básico (Trampa)')}
  {dim('─' * 56)}
  Un Honeypot (Tarro de Miel) es un sistema diseñado intencionalmente
  para ser {cyan('atacado')}. No tiene ningún valor para los usuarios reales, 
  por lo tanto, {red('cualquier conexión a él es hostil por definición')}.

  {white('2. Deception Technology')}
  {dim('─' * 56)}
  Sirve para engañar a escáneres como Nmap y scripts automáticos.
  Al devolver banners falsos (Ej. diciendo que somos un servidor MySQL),
  el atacante pierde tiempo intentando lanzar exploits contra un 
  servicio que en realidad es solo un script de Python.

  {white('3. Recolección de Inteligencia (Threat Intel)')}
  {dim('─' * 56)}
  Lo más valioso de un honeypot es que graba qué IPs nos están atacando
  y qué contraseñas o payloads están probando. Esa información se puede 
  usar para actualizar automáticamente los Firewalls de la red real.

  {white('4. Tipos de Honeypot')}
  {dim('─' * 56)}
  {dim('·')} {yellow('Low-Interaction:')} Fingen tener el puerto abierto (esta herramienta).
  {dim('·')} {yellow('High-Interaction:')} Son sistemas operativos vulnerables reales 
    (máquinas virtuales) donde se deja entrar al hacker para estudiar
    sus movimientos (TTPs).
    """)


# ──────────────────────────────────────────────
#  Submenú
# ──────────────────────────────────────────────
_SUBMENU = [
    ("1", "Iniciar Honeypot",                     _mode_start),
    ("2", "¿Qué es un Honeypot?",                 _mode_explain),
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
        section_title("HERRAMIENTA 23 — HONEYPOT TCP")
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
