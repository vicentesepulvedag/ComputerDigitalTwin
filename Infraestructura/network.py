import subprocess
import config.settings


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

    # Refrescar cache de sudo justo antes de la captura
    try:
        subprocess.run(["sudo", "-v"], check=True)
    except subprocess.CalledProcessError:
        return {
            "status": "error",
            "logs": [],
            "message": "No se pudo autenticar con sudo.",
        }

    pcap_cache = "/tmp/soc_capture.pcap"
    capture_iface = "any" if force_any else interface

    # 1. Comando que GUARDA el tráfico en un archivo .pcap
    # --foreground evita problemas de grupo de procesos con timeout
    comando_captura = [
        "sudo",
        "timeout",
        "--foreground",
        str(timeout_sec),
        "tcpdump",
        "-i",
        capture_iface,
        "-nn",
    ]

    comando_captura.append("-vvv" if extra_verbose else "-v")
    if include_payload:
        comando_captura.extend(["-s", "0"])

    comando_captura.extend(["tcp", "and", "host", config.settings.TARGET_IP])
    comando_captura.extend(_build_port_filter(ports))
    comando_captura.extend(["-w", pcap_cache])

    print(
        f"[debug] Capturando en {capture_iface} hacia {config.settings.TARGET_IP} ({timeout_sec}s)"
    )
    print(f"[debug] Comando: {' '.join(comando_captura)}")

    try:
        # Ejecutamos la recolección (NO capture_output para ver errores en vivo)
        res = subprocess.run(comando_captura, capture_output=True, text=True)
        if res.returncode != 0 and res.returncode != 124:
            stderr = res.stderr.strip() if res.stderr else "sin stderr"
            return {
                "status": "error",
                "logs": [],
                "message": f"tcpdump falló (código {res.returncode}): {stderr[:300]}",
            }

        # 2. Lee el caché
        if os.path.exists(pcap_cache):
            comando_leer = ["tcpdump", "-nn"]
            comando_leer.append("-vvv" if extra_verbose else "-v")
            comando_leer.extend(["-r", pcap_cache])
            result = subprocess.run(comando_leer, capture_output=True, text=True)

            lineas = result.stdout.strip().split("\n")
            logs = [
                linea for linea in lineas if linea and "tcpdump" not in linea.lower()
            ]

            subprocess.run(["sudo", "rm", "-f", pcap_cache])
            print(f"[debug] Captura completada: {len(logs)} líneas")
            return {"status": "success", "logs": logs}
        else:
            return {
                "status": "error",
                "logs": [],
                "message": "No se creó el archivo pcap (sin tráfico o error).",
            }
    except FileNotFoundError:
        raise RuntimeError("tcpdump no está instalado. Usa: sudo pacman -S tcpdump")
    except Exception as e:
        exc_type = type(e).__name__
        raise RuntimeError(f"Error en captura tcpdump ({exc_type}): {str(e)}")
