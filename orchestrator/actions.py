import time
import threading
import sys
import os
import shutil
import textwrap

from config.settings import OS_CONFIGS, set_os
from Infraestructura.vm_manager import restore_snapshot, start_vm
from Agentes.Red.hacker_agent import ejecutar_ataque
from Agentes.Blue.soc_agent import capturar_trafico, analizar_logs_llm
from Agentes.Blue.cvss import calcular_cvss, clasificar
from Agentes.Red.Herramientas.ms17_010_extract import ejecutar_extraccion
from reports.exporter import PDFExporter
from reports.csv_exporter import CSVExporter
from cli.menu import select_export_format


def _cfg(os_name):
    return OS_CONFIGS.get(os_name, OS_CONFIGS["Windows XP"])


def seleccionar_os() -> str:
    ops = list(OS_CONFIGS.keys())
    print()
    for i, nombre in enumerate(ops, 1):
        cfg = OS_CONFIGS[nombre]
        print(f"  {i}. {nombre} ({cfg['VM_NAME']} @ {cfg['TARGET_IP']})")
    print(f"  {len(ops) + 1}. Mantener actual")

    opcion = input("\nElige (1-{}): ".format(len(ops) + 1)).strip()
    try:
        idx = int(opcion)
        if 1 <= idx <= len(ops):
            nombre = ops[idx - 1]
            set_os(nombre)
            return nombre
    except ValueError:
        pass
    return None  # señal de "mantener actual"


def ejecutar_red_team(modo: str, os_name: str) -> dict:
    resultado = ejecutar_ataque(modo=modo, os_name=os_name)
    return resultado


def ejecutar_extraccion_ms17(os_name: str) -> dict:
    try:
        ejecutar_extraccion(os_name=os_name)
        return {"status": "success", "data": "Extracción completada."}
    except Exception as e:
        return {"status": "error", "message": str(e)}


def restaurar_entorno(os_name: str) -> dict:
    cfg = _cfg(os_name)
    res = restore_snapshot(cfg["VM_NAME"], cfg["SNAPSHOT"])
    start_vm(cfg["VM_NAME"])
    exfil = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "Telemetria",
        "exfil",
    )
    if os.path.exists(exfil):
        shutil.rmtree(exfil)
    return {
        "status": "success",
        "message": res["message"],
        "exfil_cleaned": os.path.exists(exfil) is False,
    }


def _hacker_worker(modo: str, os_name: str, resultado: dict):
    time.sleep(2)
    res = ejecutar_ataque(modo=modo, os_name=os_name)
    resultado.update(res)


class SimulacionResult:
    def __init__(self):
        self.status: str = "ok"
        self.error_msg: str = ""
        self.logs: list = []
        self.llm_response: dict = {}
        self.cvss_score: float = 0.0
        self.cvss_nivel: str = ""
        self.vm_restore_msg: str = ""
        self.modo: str = ""
        self.os_name: str = ""


def ejecutar_simulacion(modo: str, os_name: str) -> SimulacionResult:
    result = SimulacionResult()
    result.modo = modo
    result.os_name = os_name

    cfg = _cfg(os_name)

    try:
        # Fase 1: Preparación
        res_restore = restore_snapshot(cfg["VM_NAME"], cfg["SNAPSHOT"])
        result.vm_restore_msg = res_restore["message"]
        start_vm(cfg["VM_NAME"])
        time.sleep(5)

        # Fase 2: Ataque + Defensa simultáneos
        ataque_result = {}
        hilo = threading.Thread(
            target=_hacker_worker, args=(modo, os_name, ataque_result)
        )
        hilo.start()

        tiempo_escucha = (
            15 if modo == "normal" else (30 if modo == "ms17-010-extract" else 45)
        )
        captura = capturar_trafico(segundos=tiempo_escucha, modo=modo)
        hilo.join()

        # Fase 3: Análisis
        logs = captura.get("logs", [])
        result.logs = logs

        if captura["status"] == "error":
            result.status = "error"
            result.error_msg = f"Error capturando tráfico: {captura['message']}"
            return result

        if not logs:
            result.status = "warning"
            result.error_msg = "No se capturó actividad del Red Team."
            return result

        llm_resp = analizar_logs_llm(logs)
        result.llm_response = llm_resp

        vulns = llm_resp.get("vulnerabilities", [])
        if vulns:
            v = vulns[0]
            metrics = v.get("CVSS_metrics", {})
            result.cvss_score = calcular_cvss(metrics)
            result.cvss_nivel = clasificar(result.cvss_score)
        if llm_resp and logs:

            vulns = llm_resp.get("vulnerabilities", [])

            if vulns:

                v = vulns[0]

                report_data = {
                    "threat": v.get("name", "Amenaza detectada"),
                    "target_os": os_name,
                    "cvss": f"{result.cvss_score} [{result.cvss_nivel}]",
                    "description": v.get("description", ""),
                    "technical_explanation": v.get(
                        "technical_explanation", ""
                    ),
                    "mitigations": v.get("mitigations", []),
                    "logs": "\n".join(logs)
                }

                export_option = select_export_format()

                if export_option == "1":
                    PDFExporter.export(report_data)

                elif export_option == "2":
                    CSVExporter.export(report_data)
    except Exception as e:
        result.status = "error"
        result.error_msg = str(e)

    return result
