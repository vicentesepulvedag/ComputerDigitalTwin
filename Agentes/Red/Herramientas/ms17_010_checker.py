from struct import pack

from Agentes.Red.Herramientas.mysmb import MYSMB


def check_vulnerability(target_ip: str, port: int = 445) -> dict:
    TRANS_PEEK_NMPIPE = 0x23

    conn = MYSMB(target_ip, port)
    try:
        conn.login("", "")
    except Exception as e:
        return {
            "vulnerable": False,
            "error": f"Login failed: {e}",
            "pipes": [],
        }

    result = {
        "target_os": conn.get_server_os(),
        "vulnerable": False,
        "pipes": [],
    }

    tid = conn.tree_connect_andx("\\\\" + target_ip + "\\" + "IPC$")
    conn.set_default_tid(tid)

    recvPkt = conn.send_trans(
        pack("<H", TRANS_PEEK_NMPIPE),
        maxParameterCount=0xFFFF,
        maxDataCount=0x800,
    )
    status = recvPkt.getNTStatus()
    result["vulnerable"] = status == 0xC0000205

    result["pipes"] = _find_pipes(conn) if result["vulnerable"] else []

    conn.disconnect_tree(tid)
    conn.logoff()
    conn.get_socket().close()
    return result


def _find_pipes(conn) -> list:
    pipes = [
        "netlogon", "lsarpc", "samr", "browser", "spoolss",
        "atsvc", "DAV RPC SERVICE", "epmapper", "eventlog",
        "InitShutdown", "keysvc", "lsass", "LSM_API_service",
        "ntsvcs", "plugplay", "protected_storage", "router",
        "scerpc", "srvsvc", "tapsrv", "trkwks", "W32TIME_ALT", "wkssvc",
    ]
    tid = conn.tree_connect_andx("\\\\" + conn.get_remote_host() + "\\" + "IPC$")
    found = []
    for pipe in pipes:
        try:
            fid = conn.nt_create_andx(tid, pipe)
            conn.close(tid, fid)
            found.append(pipe)
        except Exception:
            pass
    conn.disconnect_tree(tid)
    return found
