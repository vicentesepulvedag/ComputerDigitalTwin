import sys
import os

sys.path.append(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
)

from config.settings import TARGET_IP, TARGET_PORTS
from Agentes.Red.Herramientas.nmap_scanner import run_nmap_scan
from Agentes.Red.Herramientas.nmap_vuln_scanner import run_nmap_vuln_scan


def ejecutar_ataque(modo="normal") -> dict:
    """Orquesta el ataque de red utilizando las herramientas de infraestructura o de vulnerability scanner."""
    try:
        if modo == "vuln":
            resultado = run_nmap_vuln_scan(
                TARGET_IP, TARGET_PORTS
            )  # Ahora ataca la IP exacta
        else:
            resultado = run_nmap_scan(
                TARGET_IP, TARGET_PORTS
            )  # Ahora ataca la IP exacta

        return {
            "status": "success",
            "message": "Escaneo de red completado exitosamente.",
            "data": resultado["output"],
        }
    except Exception as e:
        return {"status": "error", "message": str(e), "data": None}


if __name__ == "__main__":
    print("Este módulo provee la lógica del Red Team y debe ser importado en main.py.")
