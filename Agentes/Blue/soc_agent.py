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
        include_payload = modo in ("vuln", "ms17-010-extract")
        extra_verbose = modo in ("vuln", "ms17-010-extract")
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
3) Explotación activa de MS17-010 (EternalBlue). Identifícala por estos patrones:
   - Múltiples conexiones SMB al puerto 445 con acceso a named pipes IPC$ (spoolss, samr, browser, lsarpc, srvsvc)
   - Comandos SMB WriteAndX con "raw pipe" mode (modo escritura directa a named pipe)
   - Secuencias de paquetes SMB Transaction/NT Transaction de tamaños similares (grooming de pool de memoria)
   - Múltiples SMB Transaction Secondary packets modificando el mismo transaction ID (manipulación de structuras)
   - Tráfico SMB post-explotación con Service Control Manager (svcctl) RPC para crear/eliminar servicios
   - SMB session setup y tree connect a IPC$ repetidos en corto tiempo
   CUALQUIER combinación de WriteAndX raw pipe + named pipe + múltiples transactions secundarias ES UN EXPLOIT EN EJECUCIÓN, clasifícalo como CRITICAL.
4) Post-explotación / exfiltración de datos vía SMB. Identifícala por estos patrones:
   - Tráfico SMB hacia el recurso compartido C$ (TreeConnect a C$) inmediatamente después de la explotación
   - Acceso a rutas de perfil de usuario: "Documents and Settings\\*\\Cookies\\", "Local Settings\\History\\", "Desktop\\"
   - Descarga de archivos específicos del usuario: index.dat, desktop.ini, documentos del escritorio
   - Múltiples peticiones SMB ReadAndX para archivos de usuario (indican exfiltración activa)
   - Conexiones SMB persistentes con session setup + tree connect a C$ para navegar el sistema de archivos
   - Listado de directorios (SMB TRANS2_FIND_FIRST2/NEXT2) sobre "Documents and Settings\\" para enumerar usuarios del sistema
   CUALQUIER acceso a archivos de usuario vía C$ tras un exploit SMB ES EXFILTRACIÓN, clasifícalo como CRITICAL.

Guia adicional:
- Si hay payloads no vacios hacia multiples puertos o indicadores "multi_port_with_payload", considera el evento como escaneo avanzado.
- Si ves trafico sostenido hacia SMB/NetBIOS (puertos 139/445) con payloads, considera riesgo alto.
- Si ves indicadores "ms17_grooming" o "ms17_writeandx_pipe" en el resumen, es evidencia contundente de MS17-010 exploitation.
- Si hay acceso a named pipes (spoolss, samr, browser, srvsvc) seguido de tráfico SMB denso, es explotación activa.
- Si ves acceso a C$ share + descarga de archivos de usuario (index.dat, Cookies, Desktop), es exfiltración post-explotación.

Responde SOLO en formato JSON estricto indicando:
- "vulnerabilities": Lista de anomalías o ataques detectados. Siempre que haya un escaneo o ataque, esta lista DEBE contener al menos un elemento.
Dentro de cada elemento de "vulnerabilities":
- "type": Nombre de la amenaza (ej. "Escaneo de Reconocimiento Nmap", "Evaluación Agresiva de Vulnerabilidades", "Explotación MS17-010 EternalBlue", "Exfiltración de Datos Post-Explotación SMB").
- "description": Explicación muy detallada justificando en base a tamaño de paquetes, puertos y banderas por qué se le asigna esta clasificación.
- "CVSS_metrics": Diccionario con las llaves "AV", "AC", "PR", "UI", "C", "I", "A" usando sus valores numéricos (float). Para MS17-010 usa AV=NETWORK(0.85), AC=LOW(0.77), PR=NONE(0.85), UI=NONE(0.85), C=HIGH(0.56), I=HIGH(0.56), A=HIGH(0.56). Para exfiltración post-explotación usa AV=NETWORK(0.85), AC=LOW(0.77), PR=LOW(0.62), UI=NONE(0.85), C=HIGH(0.56), I=LOW(0.22), A=NONE(0.00).
- "recommendations": Lista de recomendaciones técnicas para mitigar el ataque. Para MS17-010 incluir: parchear SMB (MS17-010), deshabilitar SMBv1, segmentar red, aislar el host comprometido. Para exfiltración incluir: rotar credenciales, auditar accesos SMB, monitorizar accesos anómalos a C$.

Solo devuelve {{"vulnerabilities": []}} si NO hay absolutamente NINGÚN paquete relacionado a Nmap, intentos de conexión, named pipes o tráfico inusual.
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
