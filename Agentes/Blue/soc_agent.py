import sys
import os
import json
from openai import OpenAI

sys.path.append(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
)

from config.settings import LLM_API_KEY, LLM_BASE_URL, LLM_MODEL, IFACE, TARGET_PORTS
from Infraestructura.network import run_tcpdump_capture
from Infraestructura.log_parser import filter_relevant_logs
from Agentes.Blue.log_processor import (
    format_logs_for_prompt,
    summarize_logs,
    parse_llm_json,
)

if not LLM_API_KEY:
    raise ValueError(
        "Por favor, configura la variable de entorno LLM_API_KEY (Asegúrate de crear un archivo '.env' en la raíz con la llave)."
    )

client = OpenAI(api_key=LLM_API_KEY, base_url=LLM_BASE_URL)


def capturar_trafico(segundos: int = 15, modo: str = "normal") -> dict:
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
    logs_limpios = filter_relevant_logs(logs)
    if not logs_limpios:
        return {"vulnerabilities": []}

    print("\n[Debug SOC] Logs enviados al LLM:")
    for l in logs_limpios[:5]:
        print(f"  > {l}")
    print(f"  > ... ({len(logs_limpios)} líneas en total)")

    logs_texto = format_logs_for_prompt(logs_limpios)
    resumen_trafico = summarize_logs(logs_limpios)

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
        parsed = parse_llm_json(content)
        if not isinstance(parsed, dict):
            return {"vulnerabilities": []}
        if "vulnerabilities" not in parsed:
            parsed["vulnerabilities"] = []
        elif not isinstance(parsed["vulnerabilities"], list):
            parsed["vulnerabilities"] = [parsed["vulnerabilities"]]
        return parsed
    except Exception as e:
        return {"vulnerabilities": [], "error": f"Error procesando LLM: {str(e)}"}
