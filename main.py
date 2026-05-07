import sys
import os
import time
import threading
import random

# Agregamos la ruta principal para que Python reconozca la carpeta "Agentes" como módulos
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from Agentes.Red.hacker_agent import restore_and_start_vm, scan_network
from Agentes.Blue.soc_agent import capturar_trafico_red, analizar_logs_llm, calcular_cvss, clasificar

def accion_hacker_en_segundo_plano():
    """Ejecuta el escaneo de Nmap con un retraso para que el SOC logre iniciar tcpdump."""
    print("[Red Team] Hacker preparado. Lanzando ataque en 2 segundos...")
    time.sleep(2)
    scan_network(quiet=True)

def simular_ciberataque():
    print("\n" + "="*60)
    print("🚀 INICIANDO SIMULACIÓN DE CIBERATAQUE (RED vs BLUE)")
    print("="*60)
    
    # FASE 1: Preparación del Entorno
    print("\n[>>>] FASE 1: Preparación de Infraestructura")
    # Restauramos y encendemos la máquina virtual, asegurando que Windows XP esté listo
    restore_and_start_vm(quiet=True)
    
    # FASE 2: Ataque y Defensa Simultáneos
    print("\n[>>>] FASE 2: Ejecución del Ataque y Monitoreo del SOC")
    
    # Creamos un hilo paralelo para el Red Team (Así ataca mientras el Blue Team escucha)
    hilo_hacker = threading.Thread(target=accion_hacker_en_segundo_plano)
    hilo_hacker.start()
    
    # El Blue Team principal inicia la captura de tráfico esperando a atrapar al Nmap (15s)
    logs_capturados = capturar_trafico_red(segundos=15, quiet=True)
    
    # Nos aseguramos de que el hacker terminó su escaneo
    hilo_hacker.join() 
    
    # FASE 3: Análisis Forense por IA
    print("\n[>>>] FASE 3: Análisis de Inteligencia Artificial (SOC)")
    if logs_capturados and "No se capturó" not in logs_capturados[0]:
        print("[*] Logs capturados por el Firewall. Enviando a Gemini para análisis forense...")
        
        # Limitamos los logs a 10 líneas para no saturar al LLM en este ejemplo si agarró mucha basura
        if len(logs_capturados) > 10:
            logs_capturados = logs_capturados[:10]
            
        llm_response = analizar_logs_llm(logs_capturados)
        
        if llm_response and 'vulnerabilities' in llm_response:
            vulnerabilities = llm_response['vulnerabilities']
            if vulnerabilities:
                # Mostramos la vulnerabilidad detectada
                vuln = vulnerabilities[0] 
                metrics = vuln.get('CVSS_metrics', {})
                
                if all(k in metrics for k in ['AV', 'AC', 'PR', 'UI', 'C', 'I', 'A']):
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
                    print("Error interpretando las métricas CVSS.")
            else:
                print("[!] Gemini determinó que el tráfico era benigno.")
        else:
            print("[!] Error leyendo JSON desde Gemini.")
    else:
        print("[!] El SOC no capturó ninguna actividad del Red Team. Revisa la conectividad.")
        
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
            print("El Red Team puede activarse ejecutando independientemente: python Agentes/Red/hacker_agent.py")
        elif opcion == '3':
            print("Saliendo del simulador...")
            sys.exit(0)
        else:
            print("[!] Opción inválida. Intenta nuevamente.")

if __name__ == '__main__':
    menu_interactivo()