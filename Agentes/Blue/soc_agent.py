import sys
import os
import json
import re
from openai import OpenAI

sys.path.append(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
)

from config.settings import LLM_API_KEY, LLM_BASE_URL, LLM_MODEL, IFACE, TARGET_PORTS
from Infraestructura.network import run_tcpdump_capture
from Infraestructura.log_parser import filter_relevant_logs

if not LLM_API_KEY:
    raise ValueError(
        "Por favor, configura la variable de entorno LLM_API_KEY (Asegúrate de crear un archivo '.env' en la raíz con la llave)."
    )

# Usamos el cliente OpenAI, compatible con Groq, DeepSeek, OpenRouter, etc.
client = OpenAI(api_key=LLM_API_KEY, base_url=LLM_BASE_URL)


def _format_logs_for_prompt(logs: list) -> str:
    return "\n".join(f"{i + 1}. {log}" for i, log in enumerate(logs))


def _summarize_logs(logs: list) -> dict:
    flags_counts = {}
    ttl_values = set()
    length_zero = 0
    length_nonzero = 0
    max_length = 0
    ports = set()
    src_ports = set()
    dst_ports = set()
    src_ips = set()
    dst_ips = set()

    for log in logs:
        match = re.search(r"flags \[([^\]]+)\]", log, re.IGNORECASE)
        if match:
            flag = match.group(1).lower()
            flags_counts[flag] = flags_counts.get(flag, 0) + 1

        match = re.search(r"ttl (\d+)", log, re.IGNORECASE)
        if match:
            ttl_values.add(int(match.group(1)))

        match = re.search(r"length (\d+)", log, re.IGNORECASE)
        if match:
            length = int(match.group(1))
            if length == 0:
                length_zero += 1
            else:
                length_nonzero += 1
                if length > max_length:
                    max_length = length

        match = re.search(
            r"(\d+\.\d+\.\d+\.\d+)\.(\d+) > (\d+\.\d+\.\d+\.\d+)\.(\d+):",
            log,
        )
        if match:
            src_ip, src_port, dst_ip, dst_port = match.groups()
            src_ips.add(src_ip)
            dst_ips.add(dst_ip)
            src_ports.add(src_port)
            dst_ports.add(dst_port)
            ports.add(src_port)
            ports.add(dst_port)

        for port in re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\.(\d{1,5})\b", log):
            ports.add(port)

    indicadores = []
    if len(dst_ports) >= 5 and length_nonzero > 0:
        indicadores.append("multi_port_with_payload")
    if any(flag in flags_counts for flag in ["none", "fpu", "fin", "xmas"]):
        indicadores.append("stealth_flag_scan")
    if "syn" in flags_counts and len(dst_ports) >= 5:
        indicadores.append("syn_scan_pattern")

    return {
        "total_lines": len(logs),
        "flags": flags_counts,
        "payload_lengths": {
            "zero": length_zero,
            "non_zero": length_nonzero,
            "max": max_length,
        },
        "ttl_unique": sorted(ttl_values)[:12],
        "src_ips": sorted(src_ips)[:10],
        "dst_ips": sorted(dst_ips)[:10],
        "src_ports": sorted(src_ports)[:20],
        "dst_ports": sorted(dst_ports)[:20],
        "ports": sorted(ports)[:20],
        "indicators": indicadores,
    }


def _parse_llm_json(content: str) -> dict:
    text = content.strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?", "", text).strip()
        if text.endswith("```"):
            text = text[: -len("```")].strip()

    try:
        return json.loads(text)
    except json.JSONDecodeError:
        match = re.search(r"\{.*\}", text, re.DOTALL)
        if match:
            return json.loads(match.group(0))
        raise


def capturar_trafico(segundos: int = 15, modo: str = "normal") -> dict:
    """Invoca la infraestructura para capturar logs reales."""
    try:
        include_payload = modo == "vuln"
        extra_verbose = modo == "vuln"
        res = run_tcpdump_capture(
            interface=IFACE,
            timeout_sec=segundos,
            ports=TARGET_PORTS,
            include_payload=include_payload,
            extra_verbose=extra_verbose,
        )
        return res
    except Exception as e:
        return {"status": "error", "message": str(e), "logs": []}


def analizar_logs_llm(logs: list) -> dict:
    """Envía los logs capturados al LLM y retorna un dict con las vulnerabilidades."""
    logs_limpios = filter_relevant_logs(logs)
    if not logs_limpios:
        return {"vulnerabilities": []}

    print("\n[Debug SOC] Logs enviados al LLM:")
    for l in logs_limpios[:5]:
        print(f"  > {l}")
    print(f"  > ... ({len(logs_limpios)} líneas en total)")

    logs_texto = _format_logs_for_prompt(logs_limpios)
    resumen_trafico = _summarize_logs(logs_limpios)

    prompt = f"""
Eres un analista experto de un SOC (Centro de Operaciones de Seguridad). Analiza los siguientes logs de tcpdump capturados en el firewall (-v mode):
Resumen derivado automáticamente (para contexto):
{json.dumps(resumen_trafico, ensure_ascii=True)}

Logs en orden de captura:
{logs_texto}
    
Tu objetivo es detectar CUALQUIER tipo de actividad ofensiva. INCLUSO los escaneos básicos de Nmap DEBEN ser reportados como una amenaza.

Diferencia claramente entre:
1) Escaneos básicos de puertos (ej. Nmap detectando disponibilidad mediante paquetes SYN que no pasan datos). Clasifícalo como amenaza de severidad baja/media.
2) Intentos de explotación o escaneo avanzado de vulnerabilidades (ej. Nmap NSE scripts, enviando datos adicionales y payloads hacia puertos específicos). Clasifícalo como severidad alta/crítica.

Guia adicional:
- Si hay payloads no vacios hacia multiples puertos o indicadores "multi_port_with_payload", considera el evento como escaneo avanzado.
- Si ves trafico sostenido hacia SMB/NetBIOS (puertos 139/445) con payloads, considera riesgo alto.

Responde SOLO en formato JSON estricto indicando:
- "vulnerabilities": Lista de anomalías o ataques detectados. Siempre que haya un escaneo o ataque, esta lista DEBE contener al menos un elemento.
Dentro de cada elemento de "vulnerabilities":
- "type": Nombre de la amenaza (ej. "Escaneo de Reconocimiento Nmap", "Evaluación Agresiva de Vulnerabilidades").
- "description": Explicación muy detallada justificando en base a tamaño de paquetes, puertos y banderas por qué se le asigna esta clasificación.
- "CVSS_metrics": Diccionario con las llaves "AV", "AC", "PR", "UI", "C", "I", "A" usando sus valores numéricos (float).
- "recommendations": Lista de recomendaciones técnicas para mitigar el ataque.

Solo devuelve {{"vulnerabilities": []}} si NO hay absolutamente NINGÚN paquete relacionado a Nmap, intentos de conexión o tráfico inusual.
"""
    try:
        response = client.chat.completions.create(
            model=LLM_MODEL,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.1,
        )
        content = response.choices[0].message.content.strip()
        parsed = _parse_llm_json(content)
        if not isinstance(parsed, dict):
            return {"vulnerabilities": []}
        if "vulnerabilities" not in parsed:
            parsed["vulnerabilities"] = []
        elif not isinstance(parsed["vulnerabilities"], list):
            parsed["vulnerabilities"] = [parsed["vulnerabilities"]]
        return parsed
    except Exception as e:
        return {"vulnerabilities": [], "error": f"Error procesando LLM: {str(e)}"}


_CVSS_MAP = {
    "AV": {"NETWORK": 0.85, "ADJACENT": 0.62, "LOCAL": 0.55, "PHYSICAL": 0.2, "N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"LOW": 0.77, "HIGH": 0.44, "L": 0.77, "H": 0.44},
    "PR": {"NONE": 0.85, "LOW": 0.62, "HIGH": 0.27, "N": 0.85, "L": 0.62, "H": 0.27},
    "UI": {"NONE": 0.85, "REQUIRED": 0.62, "N": 0.85, "R": 0.62},
    "C": {"HIGH": 0.56, "LOW": 0.22, "NONE": 0.0, "H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"HIGH": 0.56, "LOW": 0.22, "NONE": 0.0, "H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"HIGH": 0.56, "LOW": 0.22, "NONE": 0.0, "H": 0.56, "L": 0.22, "N": 0.0},
}


def _cvss_metric(key: str, value) -> float:
    try:
        return float(value)
    except (ValueError, TypeError):
        mapping = _CVSS_MAP.get(key, {})
        return mapping.get(str(value).upper().strip(), 0.0)


def calcular_cvss(metrics: dict) -> float:
    try:
        C = _cvss_metric("C", metrics.get("C", 0.0))
        I = _cvss_metric("I", metrics.get("I", 0.0))
        A = _cvss_metric("A", metrics.get("A", 0.0))
        AV = _cvss_metric("AV", metrics.get("AV", 0.0))
        AC = _cvss_metric("AC", metrics.get("AC", 0.0))
        PR = _cvss_metric("PR", metrics.get("PR", 0.0))
        UI = _cvss_metric("UI", metrics.get("UI", 0.0))
    except (ValueError, TypeError):
        return 0.0

    impact = 1 - (1 - C) * (1 - I) * (1 - A)
    impact_score = 6.42 * impact
    exploitability = 8.22 * AV * AC * PR * UI

    base_score = min(impact_score + exploitability, 10)
    return round(base_score, 2)


def clasificar(score: float) -> str:
    if score >= 9:
        return "CRITICAL"
    if score >= 7:
        return "HIGH"
    if score >= 4:
        return "MEDIUM"
    return "LOW"
