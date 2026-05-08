import subprocess


def run_nmap_scan(subnet: str, ports: str) -> dict:
    """Ejecuta un escaneo Nmap en la subred especificada y devuelve un diccionario con el resultado."""
    nmap_command = ["nmap", "-p", ports, "--open", subnet]

    try:
        result = subprocess.run(
            nmap_command, capture_output=True, text=True, check=True
        )
        return {"status": "success", "output": result.stdout}
    except FileNotFoundError:
        raise RuntimeError("Nmap no está instalado. Ejecuta: sudo pacman -S nmap")
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"Error al ejecutar escaneo Nmap: {e.stderr}")


def run_tcpdump_capture(interface: str, timeout_sec: int) -> dict:
    """Ejecuta una captura de tcpdump con un timeout especifico y retorna un dict con las lineas analizadas."""
    comando_tcpdump = [
        "sudo",
        "timeout",
        str(timeout_sec),
        "tcpdump",
        "-i",
        interface,
        "-n",
        "-l",
    ]

    try:
        result = subprocess.run(comando_tcpdump, capture_output=True, text=True)

        # Timeout return code is usually 124, which is expected here so we don't 'check=True'
        lineas = result.stdout.strip().split("\n")
        logs = [linea for linea in lineas if linea and "tcpdump" not in linea.lower()]

        if not logs and result.stderr:
            # Leer posibles pings o capturas enviadas por stderr
            lineas_err = result.stderr.strip().split("\n")
            logs = [
                linea
                for linea in lineas_err
                if "139" in linea or "445" in linea or "IP" in linea
            ]

        return {"status": "success", "logs": logs}
    except FileNotFoundError:
        raise RuntimeError("tcpdump no está instalado. Usa: sudo pacman -S tcpdump")
    except Exception as e:
        raise RuntimeError(f"Error al ejecutar tcpdump: {str(e)}")
