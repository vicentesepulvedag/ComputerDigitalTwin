import sys
import time
import threading
import subprocess

from config.settings import VM_NAME, SNAPSHOT
from Infraestructura.vm_manager import restore_snapshot, start_vm
from Agentes.Red.hacker_agent import ejecutar_ataque
from Agentes.Blue.soc_agent import capturar_trafico, analizar_logs_llm
from Agentes.Blue.cvss import calcular_cvss, clasificar
from Agentes.Red.Herramientas.ms17_010_extract import ejecutar_extraccion


def accion_hacker_en_segundo_plano(modo="normal"):
    print(
        f"[Red Team] Hacker preparado (Modo: {modo}). Lanzando ataque en 2 segundos..."
    )
    time.sleep(2)

    resultado = ejecutar_ataque(modo=modo)
    if resultado["status"] == "success":
        print(
            f"\n[Red Team] Ataque completado. \nPreview: {resultado['data'][:200]}...\n"
        )
    else:
        print(f"[!] Error en Red Team: {resultado['message']}")


def simular_ciberataque(modo_ataque="normal"):
    print("\n" + "=" * 60)
    print("🚀 INICIANDO SIMULACIÓN DE CIBERATAQUE (RED vs BLUE)")
    print("=" * 60)

    try:
        # FASE 1: Preparación del Entorno
        print("\n[>>>] FASE 1: Preparación de Infraestructura")
        print(f"[*] Restaurando snapshot '{SNAPSHOT}' de la máquina '{VM_NAME}'...")
        res_restore = restore_snapshot(VM_NAME, SNAPSHOT)
        print(res_restore["message"])

        print("[*] Iniciando la máquina virtual...")
        res_start = start_vm(VM_NAME)
        print(res_start["message"])

        print(
            "[*] Esperando 5 segundos para que Windows XP cargue los servicios de red..."
        )
        time.sleep(5)

        # FASE 2: Ataque y Defensa Simultáneos
        print("\n[>>>] FASE 2: Ejecución del Ataque y Monitoreo del SOC")
        print(f"[+] Iniciando SOC Manager...")

        hilo_hacker = threading.Thread(
            target=accion_hacker_en_segundo_plano, args=(modo_ataque,)
        )
        hilo_hacker.start()

        # Si el ataque es de vulnerabilidad suele tardar más, aumentamos el tiempo de escucha
        tiempo_escucha = 15 if modo_ataque == "normal" else (60 if modo_ataque == "ms17-010-extract" else 45)
        print(f"[+] Blue Team: Escuchando tráfico por {tiempo_escucha} segundos...")
        resultado_captura = capturar_trafico(segundos=tiempo_escucha, modo=modo_ataque)

        # Esperamos a que los hilos terminen
        hilo_hacker.join()

        # FASE 3: Análisis Forense por IA
        print("\n[>>>] FASE 3: Análisis de Inteligencia Artificial (SOC)")
        logs_capturados = resultado_captura.get("logs", [])

        if resultado_captura["status"] == "error":
            print(f"[!] Error al capturar tráfico: {resultado_captura['message']}")
        elif not logs_capturados:
            print(
                "[!] El SOC no capturó ninguna actividad del Red Team. Revisa la conectividad."
            )
        else:
            print(
                "[*] Logs capturados por el Firewall. Enviando a la IA para análisis forense..."
            )
            llm_response = analizar_logs_llm(logs_capturados)

            vulnerabilities = llm_response.get("vulnerabilities", [])
            if vulnerabilities:
                vuln = vulnerabilities[0]
                metrics = vuln.get("CVSS_metrics", {})

                score = calcular_cvss(metrics)
                nivel = clasificar(score)

                print(
                    "\n"
                    + "📊 RESULTADO DEL REPORTE INCIDENTE (GENERADO POR IA)".center(60)
                )
                print("-" * 60)
                print(f"🚨 Amenaza detectada: {vuln.get('type', 'Desconocido')}")
                # Usar textwrap para formatear la descripción y que no sea una línea infinita
                descripcion = vuln.get("description", "Sin descripción detallada.")
                print("📝 Descripción detallada:")
                import textwrap

                for linea in textwrap.wrap(descripcion, width=70):
                    print(f"   {linea}")
                print(f"⚠️  Gravedad (CVSS 3.1): {score} [{nivel}]")

                if vuln.get("recommendations"):
                    print("\n🛡️ RECOMENDACIONES DE MITIGACIÓN:")
                    # Si el LLM devolvió un string en lugar de una lista, lo imprimimos directamente.
                    recs = vuln["recommendations"]
                    if isinstance(recs, str):
                        print(f"   * {recs}")
                    elif isinstance(recs, list):
                        for rec in recs:
                            print(f"   * {rec}")
            else:
                print(
                    "[!] La IA determinó que el tráfico era benigno o no se encontraron vulnerabilidades claras."
                )
    except Exception as e:
        print(f"\n[!] ERROR CRÍTICO durante la simulación: {str(e)}")

    print("\n" + "=" * 60)
    print("✅ SIMULACIÓN FINALIZADA")
    print("=" * 60)


def menu_interactivo():
    # Cacheamos las credenciales de sudo al inicio para que no interrumpa el output asíncrono
    try:
        print("[*] Verificando permisos de superusuario...")
        subprocess.run(["sudo", "-v"], check=True)
    except subprocess.CalledProcessError:
        print("[!] Error, se necesitan permisos para ejecutar Nmap/tcpdump.")
        sys.exit(1)

    while True:
        print("\n" + "#" * 50)
        print("👑 ORQUESTADOR GLOBAL - COMPUTER DIGITAL TWIN")
        print("#" * 50)
        print("  1. Iniciar Simulación Completa (Ataque Básico + SOC automatizado)")
        print("  2. Iniciar Simulación Completa (Ataque con Evaluación CVEs + SOC)")
        print("  3. Iniciar solo Red Team (Manual Básico)")
        print("  4. Iniciar solo Red Team (Evaluación de Vulnerabilidades/CVEs)")
        print("  5. Iniciar solo Red Team (MS17-010 Checker)")
        print("  6. Iniciar solo Red Team (MS17-010 Extracción de Archivos)")
        print("  7. Iniciar Simulación Completa (MS17-010 + SOC)")
        print("  8. Salir")

        opcion = input("\nElige una opción (1-8): ")

        if opcion == "1":
            simular_ciberataque(modo_ataque="normal")
        elif opcion == "2":
            simular_ciberataque(modo_ataque="vuln")
        elif opcion == "3":
            print("\n" + "=" * 60)
            print("🔴 INICIANDO ATAQUE MANUAL (RED TEAM BÁSICO)")
            print("=" * 60)

            print("[*] Iniciando ataque. Por favor espera...")
            resultado = ejecutar_ataque(modo="normal")

            if resultado["status"] == "success":
                print(f"[✅] Ataque finalizado con éxito.\n")
                print("Resultados del escaneo:")
                print("-" * 40)
                print(resultado["data"])
                print("-" * 40)
            else:
                print(f"[❌] Error en el ataque: {resultado['message']}")
        elif opcion == "4":
            print("\n" + "=" * 60)
            print("🔴 INICIANDO ATAQUE MANUAL (EVALUACIÓN DE VULNERABILIDADES)")
            print("=" * 60)

            print(
                "[*] Iniciando escaneo de vulnerabilidades con Nmap NSE. Por favor espera..."
            )
            resultado = ejecutar_ataque(modo="vuln")

            if resultado["status"] == "success":
                print(f"[✅] Escaneo finalizado con éxito.\n")
                print("Resultados del análisis de vulnerabilidades:")
                print("-" * 40)
                print(resultado["data"])
                print("-" * 40)
            else:
                print(f"[❌] Error en el análisis: {resultado['message']}")
        elif opcion == "5":
            print("\n" + "=" * 60)
            print("🔴 INICIANDO MS17-010 CHECKER (ETERNALBLUE)")
            print("=" * 60)
            print("[*] Verificando si el target es vulnerable a MS17-010...")
            resultado = ejecutar_ataque(modo="ms17-010")
            if resultado["status"] == "success":
                print(f"\n{resultado['data']}")
            else:
                print(f"[❌] Error: {resultado['message']}")
        elif opcion == "6":
            print("\n" + "=" * 60)
            print("🔴 INICIANDO MS17-010 EXTRACCIÓN DE ARCHIVOS")
            print("=" * 60)
            ejecutar_extraccion()
        elif opcion == "7":
            simular_ciberataque(modo_ataque="ms17-010-extract")
        elif opcion == "8":
            print("Saliendo del simulador...")
            sys.exit(0)
        else:
            print("[!] Opción inválida. Intenta nuevamente.")


if __name__ == "__main__":
    menu_interactivo()
