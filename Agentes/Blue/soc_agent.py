import sys
import os
import json
from openai import OpenAI

sys.path.append(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
)

from config.settings import LLM_API_KEY, LLM_BASE_URL, LLM_MODEL, IFACE
from Infraestructura.network import run_tcpdump_capture
from Infraestructura.log_parser import filter_relevant_logs

if not LLM_API_KEY:
    raise ValueError(
        "Por favor, configura la variable de entorno LLM_API_KEY (Asegúrate de crear un archivo '.env' en la raíz con la llave)."
    )

# Usamos el cliente OpenAI, compatible con Groq, DeepSeek, OpenRouter, etc.
client = OpenAI(api_key=LLM_API_KEY, base_url=LLM_BASE_URL)


def capturar_trafico(segundos: int = 15) -> dict:
    """Invoca la infraestructura para capturar logs reales."""
    try:
        res = run_tcpdump_capture(interface=IFACE, timeout_sec=segundos)
        return {"status": "success", "logs": res["logs"]}
    except Exception as e:
        return {"status": "error", "message": str(e), "logs": []}


def analizar_logs_llm(logs: list) -> dict:
    """Envía los logs capturados al LLM y retorna un dict con las vulnerabilidades."""
    logs_limpios = filter_relevant_logs(logs)
    if not logs_limpios:
        return {"vulnerabilities": []}

    prompt = f"""
Eres un experto en ciberseguridad. Analiza estos logs:
{logs_limpios}
    
Responde SOLO en JSON indicando vulnerabilidades, tipo, métricas CVSS_metrics (AV, AC, PR, UI, C, I, A) usando sus valores numéricos (float), y recomendaciones.
Si no hay, devuelve {{"vulnerabilities": []}}
"""
    try:
        response = client.chat.completions.create(
            model=LLM_MODEL,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.1,
        )
        content = response.choices[0].message.content.strip()
        if content.startswith("```json") and content.endswith("```"):
            content = content[len("```json") : -len("```")].strip()
        return json.loads(content)
    except Exception as e:
        raise RuntimeError(f"Error procesando LLM: {str(e)}")


def calcular_cvss(metrics: dict) -> float:
    try:
        # Convertimos explícitamente a float por si el LLM devuelve las métricas como strings (ej. "0.5")
        C = float(metrics.get("C", 0.0))
        I = float(metrics.get("I", 0.0))
        A = float(metrics.get("A", 0.0))
        AV = float(metrics.get("AV", 0.0))
        AC = float(metrics.get("AC", 0.0))
        PR = float(metrics.get("PR", 0.0))
        UI = float(metrics.get("UI", 0.0))
    except (ValueError, TypeError):
        # Si la IA alucina y devuelve palabras (ej. "High"), evitamos el crash devolviendo un valor por defecto.
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
