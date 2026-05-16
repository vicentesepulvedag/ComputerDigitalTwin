import sys
import os

sys.path.append(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
)

from config.settings import OS_CONFIGS, TARGET_PORTS, seleccionar_os
from Agentes.Red.Herramientas.nmap_scanner import run_nmap_scan
from Agentes.Red.Herramientas.nmap_vuln_scanner import run_nmap_vuln_scan
from Agentes.Red.Herramientas.ms17_010_checker import check_vulnerability
from Agentes.Red.Herramientas.ms17_010_extract import (
    ejecutar_extraccion,
    ejecutar_exploit_sin_exfil,
)


def ejecutar_ataque(modo="normal", os_name=None) -> dict:
    if os_name is None:
        os_name = "Windows XP"
    os_name = seleccionar_os(os_name)
    target_ip = OS_CONFIGS[os_name]["TARGET_IP"]

    try:
        if modo == "vuln":
            resultado = run_nmap_vuln_scan(target_ip, TARGET_PORTS)
        elif modo == "ms17-010":
            checker = check_vulnerability(
                target_ip,
                username=OS_CONFIGS[os_name]["SMB_USER"],
                password=OS_CONFIGS[os_name]["SMB_PASS"],
            )
            lines = [f"Target OS: {checker['target_os']}"]
            if checker["vulnerable"]:
                lines.append("[!] VULNERABLE a MS17-010 (EternalBlue)")
                if checker["pipes"]:
                    lines.append(
                        f"Named pipes accesibles: {', '.join(checker['pipes'])}"
                    )
                else:
                    lines.append("No se encontraron named pipes accesibles")
            else:
                lines.append("[+] Target parcheado o no vulnerable")
            return {
                "status": "success",
                "message": "MS17-010 check completado.",
                "data": "\n".join(lines),
            }
        elif modo == "ms17-010-no-exfil":
            ejecutar_exploit_sin_exfil(os_name=os_name)
            return {
                "status": "success",
                "message": "MS17-010 exploit sin exfiltración completado.",
                "data": "Exploit MS17-010 ejecutado sin extracción de archivos.",
            }
        elif modo == "ms17-010-extract":
            ejecutar_extraccion(os_name=os_name)
            return {
                "status": "success",
                "message": "MS17-010 extracción completada.",
                "data": "Extracción de archivos vía MS17-010 completada.",
            }
        else:
            resultado = run_nmap_scan(target_ip, TARGET_PORTS)

        return {
            "status": "success",
            "message": "Escaneo de red completado exitosamente.",
            "data": resultado["output"],
        }
    except Exception as e:
        return {"status": "error", "message": str(e), "data": None}


if __name__ == "__main__":
    print("Este módulo provee la lógica del Red Team y debe ser importado en main.py.")
