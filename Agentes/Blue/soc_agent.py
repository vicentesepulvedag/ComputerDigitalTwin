import os
import json
import random
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
# LOGS SIMULADOS
# -----------------------------
logs = [
    "[INFO] User login attempt from 192.168.1.100",
    "[WARNING] Multiple failed login attempts for 'admin' from 203.0.113.45",
    "[ALERT] Suspicious SQL query detected on 'users' table: ' OR '1'='1 --",
    "[INFO] Data extraction anomaly detected from financial database",
    "[ERROR] Unauthenticated access attempt to '/admin' from 10.0.0.2",
    "[CRITICAL] Malware detected: /tmp/exploit.exe downloaded by user 'john'",
    "[WARNING] Cross-Site Scripting (XSS) payload detected in URL parameter: <script>alert('XSS')</script>"
]

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
# 3. CHATBOT
# -----------------------------
def chatbot():
    print("🤖 Chatbot de Ciberseguridad (comandos: 'analizar', 'logs', 'ayuda', 'salir')")

    while True:
        user_input = input("\nTú: ")

        if user_input.lower() == "salir":
            print("Adiós. ¡Gracias por usar el Chatbot de Ciberseguridad!")
            break

        elif user_input.lower() == "analizar":
            print("\nAnalizando logs con LLM...\n")

            llm_response = analizar_logs_llm(logs)

            if llm_response and 'vulnerabilities' in llm_response:
                vulnerabilities = llm_response['vulnerabilities']
                if vulnerabilities:
                    vuln = random.choice(vulnerabilities)

                    metrics_for_cvss = vuln.get('CVSS_metrics', {})
                    if all(k in metrics_for_cvss for k in ['AV', 'AC', 'PR', 'UI', 'C', 'I', 'A']):
                        score = calcular_cvss(metrics_for_cvss)
                        nivel = clasificar(score)

                        print("🤖 Resultado:")
                        print(f"- Tipo de vulnerabilidad: {vuln.get('type', 'Desconocido')}")
                        print(f"- Descripción: {vuln.get('description', 'No hay descripción disponible.')}")
                        print(f"- CVSS Score: {score}")
                        print(f"- Severidad: {nivel}")

                        if vuln.get('recommendations'):
                            print("\nRecomendaciones:")
                            for rec in vuln['recommendations']:
                                print(f"- {rec}")
                        print("\n" + "="*40 + "\n") # Separador
                    else:
                        print("Error: No se encontraron todas las métricas CVSS necesarias para la vulnerabilidad seleccionada.")
                        print(f"Métricas recibidas: {metrics_for_cvss}")
                else:
                    print("No se detectaron vulnerabilidades en los logs.")
            else:
                print("Error en el análisis o no se pudo interpretar la respuesta del LLM.")

        elif user_input.lower() == "logs":
            print("\n--- Logs actuales ---")
            for i, log in enumerate(logs):
                print(f"{i+1}. {log}")
            print("---------------------")

        elif user_input.lower() == "ayuda":
            print("\n--- Comandos disponibles ---")
            print("'analizar': Procesa los logs actuales para detectar vulnerabilidades.")
            print("'logs': Muestra la lista de logs que se están analizando.")
            print("'ayuda': Muestra esta lista de comandos.")
            print("'salir': Finaliza la conversación con el chatbot.")
            print("--------------------------")

        else:
            print("Comando no reconocido. Por favor, usa 'analizar', 'logs', 'ayuda' o 'salir'.")

# -----------------------------
# MAIN
# -----------------------------
if __name__ == "__main__":
    chatbot()
