import random

# Importamos las funciones principales del SOC
from Agentes.Blue.soc_agent import (
    capturar_trafico,
    analizar_logs_llm,
    calcular_cvss,
    clasificar,
)


def iniciar_chatbot():
    print(
        "🤖 SOC Agent (Blue Team) activado. Comandos: 'analizar', 'logs', 'ayuda', 'salir')"
    )

    # Lista local de logs en memoria
    logs_actuales = []

    while True:
        user_input = input("\nTú: ")

        if user_input.lower() == "salir":
            print("Adiós. ¡Gracias por usar el SOC Agent!")
            break

        elif user_input.lower() == "analizar":
            print("\nAnalizando con IA las anomalías de la red...\n")
            if not logs_actuales:
                print(
                    "No tienes logs capturados. Usa el comando 'logs' primero para esnifar la red."
                )
                continue

            llm_response = analizar_logs_llm(logs_actuales)

            if llm_response and "vulnerabilities" in llm_response:
                vulnerabilities = llm_response["vulnerabilities"]
                if vulnerabilities:
                    vuln = random.choice(vulnerabilities)

                    metrics_for_cvss = vuln.get("CVSS_metrics", {})
                    if all(
                        k in metrics_for_cvss
                        for k in ["AV", "AC", "PR", "UI", "C", "I", "A"]
                    ):
                        score = calcular_cvss(metrics_for_cvss)
                        nivel = clasificar(score)

                        print("🤖 Resultado:")
                        print(
                            f"- Tipo de vulnerabilidad: {vuln.get('type', 'Desconocido')}"
                        )
                        print(
                            f"- Descripción: {vuln.get('description', 'No hay descripción disponible.')}"
                        )
                        print(f"- CVSS Score: {score}")
                        print(f"- Severidad: {nivel}")

                        if vuln.get("recommendations"):
                            print("\nRecomendaciones:")
                            for rec in vuln["recommendations"]:
                                print(f"- {rec}")
                        print("\n" + "=" * 40 + "\n")  # Separador
                    else:
                        print(
                            "Error: No se encontraron todas las métricas CVSS necesarias para la vulnerabilidad seleccionada."
                        )
                        print(f"Métricas recibidas: {metrics_for_cvss}")
                else:
                    print("No se detectaron vulnerabilidades en los logs.")
            else:
                print(
                    "Error en el análisis o no se pudo interpretar la respuesta del LLM."
                )

        elif user_input.lower() == "logs":
            print("\n--- Iniciando captura NIDS en [virbr1] ---")
            print(
                "💡 CONSEJO: Tienes 15 segundos para lanzar hacker_agent.py en tu otra terminal"
            )
            resultado = capturar_trafico(segundos=15)
            if resultado.get("status") == "error":
                print(f"[!] Error al capturar tráfico: {resultado.get('message', 'Desconocido')}")
                logs_actuales = []
            else:
                logs_actuales = resultado.get("logs", [])
            print("\n--- Logs capturados recientemente ---")
            for i, log in enumerate(logs_actuales):
                print(f"{i+1}. {log}")
            print("---------------------")

        elif user_input.lower() == "ayuda":
            print("\n--- Comandos disponibles ---")
            print(
                "'analizar': Procesa los logs actuales para detectar vulnerabilidades."
            )
            print("'logs': Muestra la lista de logs que se están analizando.")
            print("'ayuda': Muestra esta lista de comandos.")
            print("'salir': Finaliza la conversación con el chatbot.")
            print("--------------------------")

        else:
            print(
                "Comando no reconocido. Por favor, usa 'analizar', 'logs', 'ayuda' o 'salir'."
            )
