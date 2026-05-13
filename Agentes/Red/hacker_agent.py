import sys
import os

sys.path.append(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
)

from config.settings import TARGET_IP, TARGET_PORTS
from Agentes.Red.Herramientas.nmap_scanner import run_nmap_scan
from Agentes.Red.Herramientas.nmap_vuln_scanner import run_nmap_vuln_scan
from Agentes.Red.Herramientas.ms17_010_checker import check_vulnerability
from Agentes.Red.Herramientas.ms17_010_extract import ejecutar_extraccion


def ejecutar_ataque(modo="normal") -> dict:
    try:
        if modo == "vuln":
            resultado = run_nmap_vuln_scan(TARGET_IP, TARGET_PORTS)
        elif modo == "ms17-010":
            checker = check_vulnerability(TARGET_IP)
            lines = [f"Target OS: {checker['target_os']}"]
            if checker["vulnerable"]:
                lines.append("[!] VULNERABLE a MS17-010 (EternalBlue)")
                if checker["pipes"]:
                    lines.append(f"Named pipes accesibles: {', '.join(checker['pipes'])}")
                else:
                    lines.append("No se encontraron named pipes accesibles")
            else:
                lines.append("[+] Target parcheado o no vulnerable")
            return {
                "status": "success",
                "message": "MS17-010 check completado.",
                "data": "\n".join(lines),
            }
        elif modo == "ms17-010-extract":
            ejecutar_extraccion()
            return {
                "status": "success",
                "message": "MS17-010 extracción completada.",
                "data": "Extracción de archivos vía MS17-010 completada.",
            }
        else:
            resultado = run_nmap_scan(TARGET_IP, TARGET_PORTS)

        return {
            "status": "success",
            "message": "Escaneo de red completado exitosamente.",
            "data": resultado["output"],
        }
    except Exception as e:
        return {"status": "error", "message": str(e), "data": None}


if __name__ == "__main__":
    print("Este módulo provee la lógica del Red Team y debe ser importado en main.py.")
