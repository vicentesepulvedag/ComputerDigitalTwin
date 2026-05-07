import subprocess
import time

# Configuración de la máquina virtual (Modifica estos valores)
VM_NAME = "XP_Testing_1"
SNAPSHOT_NAME = "XP_Ready_Hack"

def restore_and_start_vm(quiet=False):
    if not quiet: print(f"[*] Restaurando snapshot '{SNAPSHOT_NAME}' de la máquina '{VM_NAME}'...")
    subprocess.run(["virsh", "-c", "qemu:///system", "snapshot-revert", VM_NAME, SNAPSHOT_NAME], check=True)
    
    if not quiet: print("[*] Iniciando la máquina virtual (si es necesario)...")
    # Intentamos encenderla, pero si ya está encendida (porque el snapshot se tomó en ese estado), ignoramos el error
    result = subprocess.run(["virsh", "-c", "qemu:///system", "start", VM_NAME], capture_output=True, text=True)
    if "Domain is already active" in result.stderr:
        if not quiet: print("[*] La máquina ya estaba encendida.")
    elif result.returncode != 0:
        if not quiet: print(f"[!] Advertencia al iniciar: {result.stderr.strip()}")
        
    if not quiet: print("[*] Esperando 20 segundos para que Windows XP cargue los servicios de red...")
    time.sleep(20)

def scan_network(quiet=False):
    if not quiet: print("[*] Iniciando Fase 1: Reconocimiento (Escaneo de red)")
    if not quiet: print("[*] Buscando puertos NetBIOS y SMB (139, 445) en lab_aislada...")
    
    # Escaneamos la subred de la red aislada (192.168.100.0/24)
    # Buscamos específicamente los puertos vulnerables de Windows XP
    try:
        nmap_command = ["nmap", "-p", "139,445", "--open", "192.168.100.0/24"]
        result = subprocess.run(nmap_command, capture_output=True, text=True)
        if not quiet: print("\n--- Resultados del Escaneo ---")
        if not quiet: print(result.stdout)
    except FileNotFoundError:
        if not quiet: print("[!] Nmap no está instalado. Ejecuta: sudo pacman -S nmap")

if __name__ == "__main__":
    print("=== INICIANDO AGENTE HACKER ===")
    try:
        restore_and_start_vm()
        scan_network()
        print("=== PROCESO COMPLETADO ===")
    except subprocess.CalledProcessError as e:
        print(f"[!] Error controlando la máquina virtual: {e}")
        print("[!] Verifica que los nombres de la VM y el Snapshot sean correctos.")
