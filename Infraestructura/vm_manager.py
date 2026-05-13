import subprocess
from config.settings import VM_PROVIDER


def restore_snapshot(vm_name: str, snapshot_name: str) -> dict:
    """Restaura una máquina virtual a un snapshot específico."""
    if VM_PROVIDER.lower() == "virtualbox":
        # Comando para usuarios de VBox. Si usas WSL puede que necesites "VBoxManage.exe"
        command = ["VBoxManage", "snapshot", vm_name, "restore", snapshot_name]
    else:
        command = [
            "virsh",
            "-c",
            "qemu:///system",
            "snapshot-revert",
            vm_name,
            snapshot_name,
        ]

    try:
        subprocess.run(command, check=True, capture_output=True, text=True)
        return {
            "status": "success",
            "message": f"Snapshot '{snapshot_name}' restaurado en '{vm_name}' (Provider: {VM_PROVIDER}).",
        }
    except subprocess.CalledProcessError as e:
        raise RuntimeError(
            f"Error restaurando el snapshot {snapshot_name}: {e.stderr.strip() if e.stderr else str(e)}"
        )


def start_vm(vm_name: str) -> dict:
    """Inicia una máquina virtual."""
    if VM_PROVIDER.lower() == "virtualbox":
        command = ["VBoxManage", "startvm", vm_name, "--type", "headless"]
    else:
        command = ["virsh", "-c", "qemu:///system", "start", vm_name]

    try:
        result = subprocess.run(command, capture_output=True, text=True)

        if VM_PROVIDER.lower() == "virtualbox":
            if (
                "already locked" in result.stderr
                or "is already active" in result.stderr
                or "state is Saved" in result.stderr
            ):
                return {
                    "status": "success",
                    "message": f"La máquina '{vm_name}' ya estaba encendida o lista.",
                }
            elif result.returncode != 0:
                raise RuntimeError(
                    f"Error iniciando la VM (VirtualBox): {result.stderr.strip()}"
                )
        else:
            # Comportamiento original Libvirt (virsh)
            if "Domain is already active" in result.stderr:
                return {
                    "status": "success",
                    "message": f"La máquina '{vm_name}' ya estaba encendida.",
                }
            elif result.returncode != 0:
                raise RuntimeError(
                    f"Error iniciando la VM (Libvirt): {result.stderr.strip()}"
                )

        return {
            "status": "success",
            "message": f"Máquina '{vm_name}' encendida correctamente (Provider: {VM_PROVIDER}).",
        }
    except Exception as e:
        raise RuntimeError(f"Fallo al intentar controlar la VM {vm_name}: {e}")
