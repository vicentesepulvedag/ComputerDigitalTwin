import sys
import os

sys.path.append(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
)

from config.settings import RED_SUBNET, TARGET_PORTS
from Infraestructura.network import run_nmap_scan


def ejecutar_ataque() -> dict:
    """Orquesta el ataque de red utilizando las herramientas de infraestructura."""
    try:
        resultado = run_nmap_scan(RED_SUBNET, TARGET_PORTS)
        return {
            "status": "success",
            "message": "Escaneo de red completado exitosamente.",
            "data": resultado["output"],
        }
    except Exception as e:
        return {"status": "error", "message": str(e), "data": None}


if __name__ == "__main__":
    print("Este módulo provee la lógica del Red Team y debe ser importado en main.py.")
