import sys
import os
import json
from openai import OpenAI

sys.path.append(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
)

import config.settings
from Infraestructura.network import run_tcpdump_capture
from Infraestructura.log_parser import filter_relevant_logs
from Agentes.Blue.log_processor import (
    format_logs_for_prompt,
    summarize_logs,
    parse_llm_json,
)

if not config.settings.LLM_API_KEY:
    raise ValueError(
        "Por favor, configura la variable de entorno LLM_API_KEY (Asegúrate de crear un archivo '.env' en la raíz con la llave)."
    )

client = OpenAI(
    api_key=config.settings.LLM_API_KEY, base_url=config.settings.LLM_BASE_URL
)
client_pro = OpenAI(
    api_key=config.settings.LLM_BETTER_API_KEY,
    base_url=config.settings.LLM_BETTER_BASE_URL,
)


def _select_detection_llm():
    """Prioriza el modelo/API premium para análisis de logs, con fallback seguro."""
    better_model = getattr(config.settings, "LLM_BETTER_MODEL", None)
    better_key = getattr(config.settings, "LLM_BETTER_API_KEY", None)
    if better_model and better_key:
        return client_pro, better_model
    return client, config.settings.LLM_MODEL


def capturar_trafico(segundos: int = 15, modo: str = "normal") -> dict:
    try:
        include_payload = modo in ("vuln", "ms17-010-no-exfil", "ms17-010-extract")
        extra_verbose = modo in ("vuln", "ms17-010-no-exfil", "ms17-010-extract")
        res = run_tcpdump_capture(
            interface=config.settings.IFACE,
            timeout_sec=segundos,
            ports=config.settings.TARGET_PORTS,
            include_payload=include_payload,
            extra_verbose=extra_verbose,
        )
        return res
    except Exception as e:
        return {"status": "error", "message": str(e), "logs": []}


def _detect_vulnerabilities(logs_texto, resumen_trafico, exfil_context=None):
    exfil_section = ""
    if exfil_context:
        exfil_section = f"""
EVIDENCIA DE EXFILTRACIÓN - Los siguientes archivos de usuario fueron descargados desde el objetivo:
{chr(10).join('  - ' + f for f in exfil_context)}
Si ves esto combinado con tráfico SMB a C$ en los logs, es EXFILTRACIÓN DE DATOS confirmada.
Clasifícalo como severidad CRÍTICA, Revisa los logs para poder evaluar el tipo de exfiltración de datos que se ha explotado.
"""

    prompt = f"""
Eres un analista experto de un SOC. Analiza los siguientes logs de tcpdump.
Sistema operativo objetivo: {config.settings.OS_CHOICE}
Resumen del tráfico:
{json.dumps(resumen_trafico, ensure_ascii=True)}
{exfil_section}
Logs:
{logs_texto}

Clasifica la actividad en UNA de estas categorías (o ninguna):

1) ESCANEO BÁSICO (Nmap SYN) — Paquetes SYN aislados sin payload, a múltiples puertos, sin continuación. Severidad BAJA.

2) ESCANEO DE VULNERABILIDADES (Nmap NSE) — Conexiones ordenadas y espaciadas a puertos SMB (139, 445). Cada comando SMB tiene request+response antes del siguiente. Accede a varios named pipes (browser, samr, srvsvc, spoolss) en secuencia. Tamaños de paquete variados. Severidad MEDIA.

3) EXPLOTACIÓN MS17-010 ETERNALBLUE — CRITERIOS ESTRICTOS (debe cumplir VARIOS):
   - Ráfaga de paquetes en < 1 segundo (grooming: 4-8 paquetes de TAMAÑO IDÉNTICO, ej. varios de 102 bytes seguidos)
   - Paquetes SMB Transaction Secondary con payloads grandes (>1000 bytes) o fragmentados en segmentos de ~1448 bytes
   - Múltiples operaciones WriteAndX raw pipe simultáneas (sin esperar respuesta entre ellas)
   - Secuencia de paquetes con tamaños repetitivos exactos: 102, 110, 118, 126 (grooming) seguido de WriteAndX grande
   - Tráfico sostenido en ráfaga densa (< 0.1s entre paquetes)
   SI hay grooming + write ANDEX pero NO hay acceso a C$ ni descarga de archivos de usuario → esto es EXPLOTACIÓN SIN EXFILTRACIÓN. Severidad ALTA.
   SI el tráfico es ESPACIADO, ORDENADO, con pausas entre conexiones → es NSE, NO EternalBlue.

4) EXPLOTACIÓN MS17-010 ETERNALBLUE CON EXFILTRACIÓN — Ráfaga densa de grooming + write ANDEX + acceso a C$ + descarga de archivos de usuario (cookies, index.dat, desktop.ini, succes.txt). Severidad CRÍTICA.

5) POST-EXPLOTACIÓN / EXFILTRACIÓN SMB (SIN EXPLOIT VISIBLE) — Acceso a C$ + descarga de archivos de usuario, pero SIN los patrones de grooming/WriteAndX de EternalBlue. Severidad CRÍTICA.

Guía para NO confundir Nmap NSE con EternalBlue:
- NSE: conexiones espaciadas (>0.5s entre grupos), tamaños variados, named pipes en orden
- EternalBlue: ráfaga densa (<0.1s entre paquetes), tamaños duplicados exactos, transacciones solapadas
- Si los logs muestran "flags [S]" (SYN) → es inicio de conexión Nmap, no exploit activo
- Si el tiempo entre paquetes es >1s → probablemente NSE, no exploit

Responde SOLO en JSON:
{{"vulnerabilities": [{{"type": "str", "description": "str detallada", "CVSS_metrics": {{"AV": float, "AC": float, "PR": float, "UI": float, "C": float, "I": float, "A": float}}}}]}}
Para EternalBlue sin exfiltración (categoría 3): AV=NETWORK(0.85), AC=LOW(0.77), PR=NONE(0.85), UI=NONE(0.85), C=HIGH(0.56), I=HIGH(0.56), A=HIGH(0.56).
Para EternalBlue con exfiltración (categoría 4) o exfiltración sola (categoría 5): AV=NETWORK(0.85), AC=LOW(0.77), PR=LOW(0.62), UI=NONE(0.85), C=HIGH(0.56), I=HIGH(0.56), A=HIGH(0.56).
Para escaneo NSE: AV=NETWORK(0.85), AC=LOW(0.77), PR=NONE(0.85), UI=NONE(0.85), C=LOW(0.22), I=LOW(0.22), A=NONE(0.00).
Para escaneo básico: AV=NETWORK(0.85), AC=LOW(0.77), PR=NONE(0.85), UI=NONE(0.85), C=NONE(0.00), I=NONE(0.00), A=NONE(0.00).
{{"vulnerabilities": []}} si no hay actividad ofensiva clara.
"""
    try:
        detection_client, detection_model = _select_detection_llm()
        response = detection_client.chat.completions.create(
            model=detection_model,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.1,
        )
        content = response.choices[0].message.content.strip()
        result = parse_llm_json(content)
        if not isinstance(result, dict):
            return {"vulnerabilities": []}
        if "vulnerabilities" not in result:
            result["vulnerabilities"] = []
        elif not isinstance(result["vulnerabilities"], list):
            result["vulnerabilities"] = [result["vulnerabilities"]]
        return result
    except Exception as e:
        return {"vulnerabilities": [], "error": f"Detection error: {str(e)}"}


def _generate_recommendations(vulnerabilities):
    if not vulnerabilities:
        return vulnerabilities

    vuln = vulnerabilities[0]
    vuln_type = vuln.get("type", "Desconocida")
    vuln_desc = vuln.get("description", "")[:500]

    prompt = f"""
Eres un ingeniero senior de ciberseguridad. Respuesta SOLO en JSON, sin texto adicional.

Amenaza detectada en {config.settings.OS_CHOICE}:
Tipo: {vuln_type}
Descripción: {vuln_desc}

Genera:
1) "explanation": texto explicativo detallado (qué es, cómo funciona, impacto, por qué es crítica)
2) "recommendations": lista de strings. Cada string debe tener este formato exacto:
   "[Alta] Descripción de qué hace, dónde ejecutarlo (CMD/PowerShell) y por qué:\\ncomando exacto\\nNota post-ejecución (opcional)"

Ejemplo de recommendation:
"[Alta] Deshabilitar SMBv1 en CMD como administrador:\\ndism /online /disable-feature /featurename:SMB1Protocol\\nReiniciar el sistema después de ejecutar."

JSON válido (sin markdown, sin texto extra):
{{"explanation": "...texto...", "recommendations": ["[Alta] Descripción:\\ncomando", "[Media] Descripción:\\ncomando"]}}
"""
    try:
        response = client_pro.chat.completions.create(
            model=config.settings.LLM_BETTER_MODEL,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.1,
        )
        content = response.choices[0].message.content.strip()
        result = parse_llm_json(content)
        recs = result.get("recommendations", []) if isinstance(result, dict) else []
        explanation = result.get("explanation", "") if isinstance(result, dict) else ""
        for vuln in vulnerabilities:
            vuln["recommendations"] = recs
            vuln["explanation"] = explanation
        return vulnerabilities
    except Exception as e:
        for vuln in vulnerabilities:
            vuln["recommendations"] = [
                f"[Alta] Revisar manualmente: error generando recomendaciones - {str(e)}"
            ]
            vuln["explanation"] = "No se pudo generar la explicación."
        return vulnerabilities


def analizar_logs_llm(logs: list) -> dict:
    logs_limpios = filter_relevant_logs(logs)
    if not logs_limpios:
        return {"vulnerabilities": []}

    print("\n[Debug SOC] Logs enviados al LLM:")
    for l in logs_limpios[:5]:
        print(f"  > {l}")
    print(f"  > ... ({len(logs_limpios)} líneas en total)")

    exfil_context = None
    manifest = os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
        "Telemetria",
        "exfil",
        ".exfil_manifest.txt",
    )
    if os.path.exists(manifest):
        with open(manifest) as f:
            lines = [l.strip() for l in f if l.strip()]
            if lines:
                exfil_context = lines
                print(f"[*] Evidencia de exfiltración: {len(lines)} archivos extraídos")

    logs_texto = format_logs_for_prompt(logs_limpios)
    resumen_trafico = summarize_logs(logs_limpios)

    print("[*] Fase 1: Detectando vulnerabilidades...")
    detection = _detect_vulnerabilities(logs_texto, resumen_trafico, exfil_context)

    if not detection.get("vulnerabilities"):
        return detection

    print(f"[*] Fase 2: Generando recomendaciones detalladas...")
    detection["vulnerabilities"] = _generate_recommendations(
        detection["vulnerabilities"]
    )
    return detection
