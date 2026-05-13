import subprocess


def run_nmap_vuln_scan(target_ip: str, ports: str) -> dict:
    """
    Ejecuta un escaneo Nmap enfocado en detectar vulnerabilidades (como CVEs) en una IP específica.
    Especialmente útil para Windows XP (SMB/NetBIOS).
    """
    # -Pn: Ignorar ping (Windows firewall bloquea ICMP)
    # -sT: TCP connect scan (completa handshake, evita detección stateful)
    # -sV: Detección de versiones
    # -f: fragmenta paquetes para evadir firewalls
    # -g 53: usa puerto origen 53 (DNS) que suele estar permitido
    # -T5: máxima velocidad
    # --data-length 24: rellena paquetes con datos aleatorios (evita filtros de paquetes vacíos)
    # --spoof-mac 0: spoofea MAC a una genérica
    # --script vuln,smb-vuln*: Ejecuta todos los scripts de vuln y específicos de SMB
    nmap_command = [
        "sudo",
        "nmap",
        "-Pn",
        "-sT",
        "-sV",
        "-f",
        "-g",
        "53",
        "-T5",
        "--data-length",
        "24",
        "--spoof-mac",
        "0",
        "-p",
        ports,
        "--script",
        "vuln,smb-vuln*",
        target_ip,
    ]
    try:
        # Agregamos timeout=300 (5 minutos) para evitar que el proceso se quede colgado eternamente
        result = subprocess.run(
            nmap_command, capture_output=True, text=True, check=True, timeout=300
        )
        return {"status": "success", "output": result.stdout}

    except subprocess.TimeoutExpired:
        return {
            "status": "error",
            "message": "El escaneo de Nmap superó el tiempo límite (5 minutos) y fue abortado.",
        }
    except FileNotFoundError:
        return {
            "status": "error",
            "message": "Nmap no está instalado o no se puede encontrar en el PATH.",
        }
    except subprocess.CalledProcessError as e:
        return {
            "status": "error",
            "message": f"Error al ejecutar escaneo de vulnerabilidades Nmap: {e.stderr}",
        }
