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
from digital_twin import init_twin, get_twin


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


def _init_graph():
    dt = get_twin()
    if dt.graph.number_of_nodes() == 0:
        init_twin(OS_CONFIGS)


def _update_graph_from_attack(modo: str, os_name: str):
    dt = get_twin()
    vm_id = os_name.lower().replace(" ", "_")
    from datetime import datetime

    ts = datetime.now().isoformat(timespec="seconds")
    step_id = f"attack_{vm_id}_{modo}_{ts.replace(':', '-')}"

    desc_map = {
        "normal": "Escaneo de puertos básico (nmap)",
        "vuln": "Escaneo de vulnerabilidades (nmap --script vuln)",
        "ms17-010": "Verificación MS17-010 (EternalBlue Checker)",
        "ms17-010-no-exfil": "Exploit MS17-010 sin exfiltración",
        "ms17-010-extract": "Exploit MS17-010 con exfiltración de archivos",
    }
    dt.add_attack_step(step_id, modo, desc_map.get(modo, modo), ts)

    attack_origin = "attack_origin"
    if dt.graph.has_node(attack_origin):
        dt.link_steps(attack_origin, step_id)

    dt.link_attack_target(step_id, vm_id)

    svc_id = f"{vm_id}/smb"
    if dt.graph.has_node(svc_id) and modo in (
        "ms17-010", "ms17-010-no-exfil", "ms17-010-extract",
    ):
        vuln_id = f"{svc_id}/ms17-010"
        if not dt.graph.has_node(vuln_id):
            dt.add_vulnerability(
                vuln_id, "CVE-2017-0144",
                "EternalBlue — desbordamiento de búfer en SMBv1",
                severity="CRITICAL",
            )
            dt.link_service_vulnerability(svc_id, vuln_id)
        dt.link_attack_exploit(step_id, vuln_id)

    if modo in ("vuln",):
        vuln_id = f"{svc_id}/cve-scan"
        if not dt.graph.has_node(vuln_id):
            dt.add_vulnerability(
                vuln_id, "N/A (escanéo general)",
                "Vulnerabilidades detectadas por escaneo nmap",
                severity="MEDIA",
            )
            dt.link_service_vulnerability(svc_id, vuln_id)

    if modo == "ms17-010-extract":
        file_id = f"{vm_id}/extracted_data"
        if not dt.graph.has_node(file_id):
            dt.add_file(file_id, "C:\\Telemetria\\exfil\\*")
        dt.link_attack_exfil(step_id, file_id)


def _update_graph_from_detection(os_name: str, llm_response: dict):
    dt = get_twin()
    vulns = llm_response.get("vulnerabilities", [])
    if not vulns:
        return
    v = vulns[0]
    detection_id = f"detection_{os_name.lower().replace(' ', '_')}_{v.get('type', 'unknown')}"
    dt.add_node(detection_id, "detection", threat_type=v.get("type", ""), description=v.get("description", ""))

    steps = dt.get_attackers()
    if steps:
        dt.link_attack_detected(steps[-1], detection_id)


def ejecutar_red_team(modo: str, os_name: str) -> dict:
    _init_graph()
    _update_graph_from_attack(modo, os_name)
    resultado = ejecutar_ataque(modo=modo, os_name=os_name)
    return resultado


def ejecutar_extraccion_ms17(os_name: str) -> dict:
    try:
        ejecutar_extraccion(os_name=os_name)
        return {"status": "success", "data": "Extracción completada."}
    except Exception as e:
        return {"status": "error", "message": str(e)}


def limpiar_exfil() -> None:
    exfil = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "Telemetria",
        "exfil",
    )
    if os.path.exists(exfil):
        shutil.rmtree(exfil)


def restaurar_entorno(os_name: str) -> dict:
    cfg = _cfg(os_name)
    res = restore_snapshot(cfg["VM_NAME"], cfg["SNAPSHOT"])
    start_vm(cfg["VM_NAME"])
    limpiar_exfil()
    return {
        "status": "success",
        "message": res["message"],
        "exfil_cleaned": True,
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
        self.report_data: dict | None = None


def ejecutar_simulacion(modo: str, os_name: str) -> SimulacionResult:
    result = SimulacionResult()
    result.modo = modo
    result.os_name = os_name

    _init_graph()
    _update_graph_from_attack(modo, os_name)

    cfg = _cfg(os_name)

    try:
        # Fase 1: Preparación
        limpiar_exfil()
        start_vm(cfg["VM_NAME"])
        time.sleep(5)

        # Fase 2: Ataque + Defensa simultáneos
        ataque_result = {}
        hilo = threading.Thread(
            target=_hacker_worker, args=(modo, os_name, ataque_result)
        )
        hilo.start()

        tiempo_escucha = (
            15
            if modo == "normal"
            else 30 if modo in ("ms17-010-no-exfil", "ms17-010-extract") else 45
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

        _update_graph_from_detection(os_name, llm_resp)

        vulns = llm_resp.get("vulnerabilities", [])
        if vulns:
            v = vulns[0]
            metrics = v.get("CVSS_metrics", {})
            result.cvss_score = calcular_cvss(metrics)
            result.cvss_nivel = clasificar(result.cvss_score)

            result.report_data = {
                "threat": v.get("type", "Amenaza detectada"),
                "target_os": os_name,
                "cvss": f"{result.cvss_score} [{result.cvss_nivel}]",
                "description": v.get("description", ""),
                "technical_explanation": v.get("explanation", ""),
                "mitigations": [
                    {"description": r, "command": "", "severity": "MEDIA", "note": ""}
                    for r in (v.get("recommendations") or [])
                ],
                "logs": "\n".join(logs) if logs else "",
            }
    except Exception as e:
        result.status = "error"
        result.error_msg = str(e)

    return result
