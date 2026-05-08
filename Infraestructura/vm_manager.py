import subprocess

def restore_snapshot(vm_name: str, snapshot_name: str) -> dict:
    """Restaura una máquina virtual a un snapshot específico."""
    command = ["virsh", "-c", "qemu:///system", "snapshot-revert", vm_name, snapshot_name]
    try:
        subprocess.run(command, check=True, capture_output=True, text=True)
        return {"status": "success", "message": f"Snapshot '{snapshot_name}' restaurado en '{vm_name}'."}
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"Error restaurando el snapshot {snapshot_name}: {e.stderr.strip()}")

def start_vm(vm_name: str) -> dict:
    """Inicia una máquina virtual."""
    command = ["virsh", "-c", "qemu:///system", "start", vm_name]
    try:
        result = subprocess.run(command, capture_output=True, text=True)
        # return code 0 indicates success, but we check if it was already active
        if "Domain is already active" in result.stderr:
            return {"status": "success", "message": f"La máquina '{vm_name}' ya estaba encendida."}
        elif result.returncode != 0:
            raise RuntimeError(f"Error iniciando la VM: {result.stderr.strip()}")
            
        return {"status": "success", "message": f"Máquina '{vm_name}' encendida correctamente."}
    except Exception as e:
         raise RuntimeError(f"Fallo al intentar controlar la VM {vm_name}: {e}")
