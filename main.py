import sys
import time
import threading

from config.settings import VM_NAME, SNAPSHOT
from Infraestructura.vm_manager import restore_snapshot, start_vm
from Agentes.Red.hacker_agent import ejecutar_ataque
from Agentes.Blue.soc_agent import capturar_trafico, analizar_logs_llm, calcular_cvss, clasificar

def accion_hacker_en_segundo_plano():
    print("[Red Team] Hacker preparado. Lanzando ataque en 2 segundos...")
    time.sleep(2)
    
    resultado = ejecutar_ataque()
    if resultado["status"] == "success":
        print(f"\n[Red Team] Ataque completado. \nPreview: {resultado['data'][:200]}...\n")
    else:
        print(f"[!] Error en Red Team: {resultado['message']}")

def simular_ciberataque():
    print("\n" + "="*60)
    print("🚀 INICIANDO SIMULACIÓN DE CIBERATAQUE (RED vs BLUE)")
    print("="*60)
    
    try:
        # FASE 1: Preparación del Entorno
        print("\n[>>>] FASE 1: Preparación de Infraestructura")
        print(f"[*] Restaurando snapshot '{SNAPSHOT}' de la máquina '{VM_NAME}'...")
        res_restore = restore_snapshot(VM_NAME, SNAPSHOT)
        print(res_restore['message'])
        
        print("[*] Iniciando la máquina virtual...")
        res_start = start_vm(VM_NAME)
        print(res_start['message'])
        
        print("[*] Esperando 5 segundos para que Windows XP cargue los servicios de red...")
        time.sleep(5)
        
        # FASE 2: Ataque y Defensa Simultáneos
        print("\n[>>>] FASE 2: Ejecución del Ataque y Monitoreo del SOC")
        print(f"[+] Iniciando SOC Manager...")
        
        hilo_hacker = threading.Thread(target=accion_hacker_en_segundo_plano)
        hilo_hacker.start()
        
        print("[+] Blue Team: Escuchando tráfico...")
        resultado_captura = capturar_trafico(segundos=15)
        hilo_hacker.join() 
        
        # FASE 3: Análisis Forense por IA
        print("\n[>>>] FASE 3: Análisis de Inteligencia Artificial (SOC)")
        logs_capturados = resultado_captura.get('logs', [])
        
        if resultado_captura["status"] == "error":
            print(f"[!] Error al capturar tráfico: {resultado_captura['message']}")
        elif not logs_capturados:
            print("[!] El SOC no capturó ninguna actividad del Red Team. Revisa la conectividad.")
        else:
            print("[*] Logs capturados por el Firewall. Enviando a la IA para análisis forense...")
            llm_response = analizar_logs_llm(logs_capturados)
            
            vulnerabilities = llm_response.get('vulnerabilities', [])
            if vulnerabilities:
                vuln = vulnerabilities[0] 
                metrics = vuln.get('CVSS_metrics', {})
                
                score = calcular_cvss(metrics)
                nivel = clasificar(score)
                
                print("\n" + "📊 RESULTADO DEL REPORTE INCIDENTE (GENERADO POR IA)".center(60))
                print("-" * 60)
                print(f"🚨 Amenaza detectada: {vuln.get('type', 'Desconocido')}")
                print(f"📝 Descripción detallada: {vuln.get('description', '')}")
                print(f"⚠️  Gravedad (CVSS 3.1): {score} [{nivel}]")
                
                if vuln.get('recommendations'):
                    print("\n🛡️ RECOMENDACIONES DE MITIGACIÓN:")
                    for rec in vuln['recommendations']:
                        print(f"   * {rec}")
            else:
                print("[!] La IA determinó que el tráfico era benigno o no se encontraron vulnerabilidades claras.")
    except Exception as e:
        print(f"\n[!] ERROR CRÍTICO durante la simulación: {str(e)}")
        
    print("\n" + "="*60)
    print("✅ SIMULACIÓN FINALIZADA")
    print("="*60)

def menu_interactivo():
    while True:
        print("\n" + "#"*50)
        print("👑 ORQUESTADOR GLOBAL - COMPUTER DIGITAL TWIN")
        print("#"*50)
        print("  1. Iniciar Simulación Completa (Ataque + SOC automatizado)")
        print("  2. Iniciar solo Red Team (Manual)")
        print("  3. Salir")
        
        opcion = input("\nElige una opción (1-3): ")
        
        if opcion == '1':
            simular_ciberataque()
        elif opcion == '2':
            print("El Red Team puede activarse importando e invocando 'ejecutar_ataque()' de hacker_agent.py")
        elif opcion == '3':
            print("Saliendo del simulador...")
            sys.exit(0)
        else:
            print("[!] Opción inválida. Intenta nuevamente.")

if __name__ == '__main__':
    menu_interactivo()
