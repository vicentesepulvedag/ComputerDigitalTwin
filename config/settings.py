import os
from dotenv import load_dotenv

# Cargar variables de entorno
load_dotenv()

# ============================================================
# Configuración Multi-SO
# ============================================================
OS_CONFIGS = {
    "Windows XP": {
        "VM_NAME": "XP_Testing_1",
        "SNAPSHOT": "XP_Not_Firewall",
        "TARGET_IP": "192.168.100.10",
        "SMB_USER": "",
        "SMB_PASS": "",
        "USER_PATH": "Documents and Settings\\{user}",
        "COOKIES_REL": "Cookies",
        "HISTORY_REL": "Local Settings\\History",
        "DESKTOP_REL": "Escritorio",
        "REG_PATH": "WINDOWS\\system32\\config",
    },
    "Windows 7": {
        "VM_NAME": "Win7_Testing",
        "SNAPSHOT": "Win7_FirewallOFF",
        "TARGET_IP": "192.168.100.9",
        "SMB_USER": "Emergente",
        "SMB_PASS": "admin",
        "USER_PATH": "Users\\{user}",
        "COOKIES_REL": "AppData\\Roaming\\Microsoft\\Windows\\Cookies",
        "HISTORY_REL": "AppData\\Local\\Microsoft\\Windows\\History",
        "DESKTOP_REL": "Desktop",
        "REG_PATH": "Windows\\System32\\config",
    },
    "Windows 10": {
        "VM_NAME": "Win10_Testing",
        "SNAPSHOT": "Win10_Clean",
        "TARGET_IP": "192.168.100.12",
        "SMB_USER": "",
        "SMB_PASS": "",
        "USER_PATH": "Users\\{user}",
        "COOKIES_REL": "AppData\\Roaming\\Microsoft\\Windows\\Cookies",
        "HISTORY_REL": "AppData\\Local\\Microsoft\\Windows\\History",
        "DESKTOP_REL": "Desktop",
        "REG_PATH": "Windows\\System32\\config",
    },
}


def seleccionar_os(nombre):
    for key in OS_CONFIGS:
        if key.lower() == nombre.lower():
            return key
    return "Windows XP"  # fallback


OS_CHOICE = "Windows XP"


def set_os(nombre):
    global OS_CHOICE, VM_NAME, SNAPSHOT, TARGET_IP
    OS_CHOICE = seleccionar_os(nombre)
    cfg = OS_CONFIGS[OS_CHOICE]
    VM_NAME = cfg["VM_NAME"]
    SNAPSHOT = cfg["SNAPSHOT"]
    TARGET_IP = cfg["TARGET_IP"]
    print(f"[*] SO seleccionado: {OS_CHOICE} | VM: {VM_NAME} | IP: {TARGET_IP}")


# Inicializar con valores por defecto
set_os("Windows XP")

VM_PROVIDER = os.getenv("VM_PROVIDER", "libvirt")
TARGET_PORTS = "139,445"
IFACE = os.getenv("IFACE", "vboxnet0" if VM_PROVIDER == "VIRTUALBOX" else "virbr1")

# Filtro BPF para tcpdump/tshark enfocado solo en la VM para reducir ruido
CAPTURE_FILTER = f"host {TARGET_IP}"

# Configuración de IA — modelo rápido (detección de logs)
LLM_API_KEY = os.getenv("LLM_API_KEY")
LLM_BASE_URL = os.getenv("LLM_BASE_URL", "https://api.deepseek.com")
LLM_MODEL = os.getenv("LLM_MODEL", "deepseek-v4-flash")
if not LLM_API_KEY:
    raise ValueError("¡Error! No se encontró LLM_API_KEY. Revisa tu archivo .env")

# Configuración de IA — modelo premium (recomendaciones y análisis profundo)
LLM_BETTER_API_KEY = os.getenv("LLM_BETTER_API_KEY") or LLM_API_KEY
LLM_BETTER_BASE_URL = os.getenv("LLM_BETTER_BASE_URL") or LLM_BASE_URL
LLM_BETTER_MODEL = os.getenv("LLM_BETTER_MODEL", "deepseek-v4-pro")
# Configuración de Telemetría
CAPTURES_DIR = os.path.join(
    os.path.dirname(os.path.dirname(__file__)), "Telemetria", "captures"
)
os.makedirs(CAPTURES_DIR, exist_ok=True)
