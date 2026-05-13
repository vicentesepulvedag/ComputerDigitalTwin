import subprocess
from config.settings import CAPTURE_FILTER


def _normalize_ports(ports) -> list:
    if not ports:
        return []

    if isinstance(ports, str):
        raw_ports = [p.strip() for p in ports.split(",")]
    else:
        raw_ports = [str(p).strip() for p in ports]

    return [p for p in raw_ports if p.isdigit()]


def _build_port_filter(ports) -> list:
    ports_list = _normalize_ports(ports)
    if not ports_list:
        return []

    filtro = ["and", "("]
    for i, port in enumerate(ports_list):
        if i > 0:
            filtro.append("or")
        filtro.extend(["port", port])
    filtro.append(")")
    return filtro


def run_nmap_scan(subnet: str, ports: str) -> dict:
    """Ejecuta un escaneo Nmap en la subred especificada y devuelve un diccionario con el resultado."""
    # -Pn: salta host discovery (Windows firewall bloquea ICMP)
    # -sT: TCP connect scan (completa handshake, evita detección stateful)
    # -f: fragmenta paquetes para evadir firewalls simples
    # -g 53: usa puerto origen 53 (DNS) que suele estar permitido
    # -T5: máxima velocidad
    # --data-length 24: rellena paquetes con datos aleatorios (evita filtros de paquetes vacíos)
    # --spoof-mac 0: spoofea MAC a una genérica
    nmap_command = ["sudo", "nmap", "-Pn", "-sT", "-f", "-g", "53", "-T5", "--data-length", "24", "--spoof-mac", "0", "-p", ports, "--open", subnet]

    try:
        result = subprocess.run(
            nmap_command, capture_output=True, text=True, check=True
        )
        return {"status": "success", "output": result.stdout}
    except FileNotFoundError:
        raise RuntimeError("Nmap no está instalado. Ejecuta: sudo pacman -S nmap")
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"Error al ejecutar escaneo Nmap: {e.stderr}")


def run_tcpdump_capture(
    interface: str,
    timeout_sec: int,
    ports=None,
    include_payload: bool = False,
    extra_verbose: bool = False,
    force_any: bool = True,
) -> dict:
    """Ejecuta una captura de tcpdump guardando en un caché (PCAP) y lo lee después para evitar pérdidas en vivo."""
    import os
    pcap_cache = "/tmp/soc_capture.pcap"
    capture_iface = "any" if force_any else interface
    
    # 1. Comando que GUARDA el tráfico en un archivo .pcap en lugar de imprimirlo en consola
    # Usamos interface "any" para que si el ataque ocurre dentro de la misma máquina (loopback), tampoco se escape.
    comando_captura = [
        "sudo",
        "timeout",
        str(timeout_sec),
        "tcpdump",
        "-i",
        capture_iface,  # Usamos "any" si force_any=True para atrapar loopback
        "-nn",
    ]

    comando_captura.append("-vvv" if extra_verbose else "-v")
    if include_payload:
        comando_captura.extend(["-s", "0"])

    # Usamos el filtro dinámico de settings.py enfocado en la VM (TARGET_IP)
    comando_captura.extend(["tcp", "and"])
    comando_captura.extend(CAPTURE_FILTER.split())

    comando_captura.extend(_build_port_filter(ports))
    comando_captura.extend(["-w", pcap_cache])

    try:
        # Ejecutamos la recolección
        subprocess.run(comando_captura, capture_output=True)

        # 2. Comando que LEE el caché procesado. Esto evita los bugs de buffering de stdout
        if os.path.exists(pcap_cache):
            comando_leer = ["tcpdump", "-nn"]
            comando_leer.append("-vvv" if extra_verbose else "-v")
            # Leemos solo cabeceras para evitar ruido de payload binario en los logs
            comando_leer.extend(["-r", pcap_cache])
            result = subprocess.run(comando_leer, capture_output=True, text=True)
            
            lineas = result.stdout.strip().split("\n")
            logs = [linea for linea in lineas if linea and "tcpdump" not in linea.lower()]
            
            # Limpiamos el caché
            subprocess.run(["sudo", "rm", "-f", pcap_cache])
            
            return {"status": "success", "logs": logs}
        else:
            return {"status": "error", "logs": [], "message": "No se pudo crear el archivo caché pcap."}
    except FileNotFoundError:
        raise RuntimeError("tcpdump no está instalado. Usa: sudo pacman -S tcpdump")
    except Exception as e:
        raise RuntimeError(f"Error al ejecutar tcpdump: {str(e)}")
