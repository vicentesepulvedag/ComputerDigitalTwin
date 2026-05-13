import subprocess


def run_nmap_scan(subnet: str, ports: str) -> dict:
    """Ejecuta un escaneo Nmap básico en la subred/IP especificada."""
    nmap_command = [
        "sudo", "nmap",
        "-Pn", "-sT", "-f", "-g", "53",
        "-T5", "--data-length", "24", "--spoof-mac", "0",
        "-p", ports, "--open", subnet,
    ]

    try:
        result = subprocess.run(
            nmap_command, capture_output=True, text=True, check=True
        )
        return {"status": "success", "output": result.stdout}
    except FileNotFoundError:
        raise RuntimeError("Nmap no está instalado. Ejecuta: sudo pacman -S nmap")
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"Error al ejecutar escaneo Nmap: {e.stderr}")
