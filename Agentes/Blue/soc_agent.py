import os
import json
import random
import subprocess
import google.generativeai as genai

from dotenv import load_dotenv
load_dotenv()

# Configuración de Gemini
GOOGLE_API_KEY = os.getenv('GOOGLE_API_KEY')

if not GOOGLE_API_KEY:
    raise ValueError("Por favor, configura la variable de entorno GOOGLE_API_KEY.")

genai.configure(api_key=GOOGLE_API_KEY)
gemini_model = genai.GenerativeModel('gemini-2.5-flash')

# -----------------------------
# 1. CAPTURA DE LOGS REALES (RED)
# -----------------------------
def capturar_trafico_red(segundos=15, quiet=False):
    if not quiet: print(f"\n[+] Escuchando la red del laboratorio (virbr1) durante {segundos} segundos...")
    if not quiet: print("[!] (¡Rápido! Ve a la otra consola y lanza tu Hacker_Agent)")
    try:
        # Usamos timeout o en su defecto comunicamos python a nivel de sleep
        import time
        comando_tcpdump = ["tcpdump", "-i", "virbr1", "-n", "-l"]
        proceso = subprocess.Popen(comando_tcpdump, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
        time.sleep(segundos)
        
        # Detener la captura enviando CTR+C de forma limpia al proceso subyacente
        proceso.terminate()
        try:
            proceso.wait(timeout=2)
        except subprocess.TimeoutExpired:
            proceso.kill()

        stdout, _ = proceso.communicate()
        
        # Procesamos la salida y la convertimos en una lista de logs
        lineas = stdout.strip().split('\n')
        logs = [linea for linea in lineas if linea and "tcpdump" not in linea.lower()]
        
        if not logs:
            logs = ["[INFO] No se capturó tráfico malicioso en los 15 segundos."]
            
        if not quiet: print("[+] Captura finalizada.")
        return logs
    except FileNotFoundError:
        if not quiet: print("[!] tcpdump no está instalado. Usa: sudo pacman -S tcpdump")
        return ["[ERROR] Error de dependencia en el SOC."]

# -----------------------------
# 1. LLM ANALIZA LOGS
# -----------------------------
def analizar_logs_llm(logs):
    prompt = f"""
Eres un experto en ciberseguridad. Tu tarea es analizar logs de seguridad para identificar vulnerabilidades y posibles ataques. Para cada vulnerabilidad o ataque detectado, debes proporcionar su tipo, las métricas CVSS v3.1 base (AV, AC, PR, UI, C, I, A) y recomendaciones específicas. Si no encuentras vulnerabilidades claras, puedes indicar que no hay.

Analiza los siguientes logs y responde SOLO en formato JSON. Si detectas múltiples vulnerabilidades, listalas en un array. Si no detectas ninguna, el array debe estar vacío.

Logs:
{logs}

Formato de la salida JSON (ejemplo con una vulnerabilidad):
{{
  "vulnerabilities": [
    {{
      "type": "Inyección SQL",
      "description": "Intento de inyección SQL detectado en la tabla 'usuarios' con un payload común.",
      "CVSS_metrics": {{
        "AV": 0.85, "AC": 0.77, "PR": 0.85, "UI": 0.85, "C": 0.56, "I": 0.56, "A": 0.22
      }},
      "recommendations": [
        "Implementar sentencias preparadas o consultas parametrizadas.",
        "Validar y sanitizar toda la entrada de usuario.",
        "Usar un Firewall de Aplicaciones Web (WAF) para filtrar solicitudes maliciosas."
      ]
    }}
  ]
}}

Si no se detecta ninguna vulnerabilidad:
{{"vulnerabilities": []}}
"""

    # Usa el modelo de Gemini para generar contenido
    response = gemini_model.generate_content(prompt)

    content = response.text

    # Extraer el JSON de la respuesta si está envuelto en un bloque de código markdown
    if content.startswith('```json') and content.endswith('```'):
        content = content[len('```json'):-len('```')].strip()

    try:
        return json.loads(content)
    except Exception as e:
        print("Error interpretando respuesta del LLM:")
        print(f"Contenido: {content}")
        print(f"Error: {e}")
        return None

# -----------------------------
# 2. CVSS
# -----------------------------
def calcular_cvss(metrics):
    C, I, A = metrics["C"], metrics["I"], metrics["A"]
    AV, AC, PR, UI = metrics["AV"], metrics["AC"], metrics["PR"], metrics["UI"]

    impact = 1 - (1 - C) * (1 - I) * (1 - A)
    impact_score = 6.42 * impact

    exploitability = 8.22 * AV * AC * PR * UI

    base_score = min(impact_score + exploitability, 10)
    return round(base_score, 2)

def clasificar(score):
    if score >= 9: return "CRITICAL"
    if score >= 7: return "HIGH"
    if score >= 4: return "MEDIUM"
    return "LOW"

# -----------------------------
