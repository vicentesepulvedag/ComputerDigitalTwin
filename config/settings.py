import os
from dotenv import load_dotenv

# Cargar variables de entorno
load_dotenv()

# Configuración de Virtualización
VM_PROVIDER = os.getenv("VM_PROVIDER", "libvirt")  # Opciones: "libvirt" o "virtualbox"
VM_NAME = "XP_Testing_1"
SNAPSHOT = "XP_Not_Firewall"

# Configuración de Red
RED_SUBNET = "192.168.100.0/24"
TARGET_IP = "192.168.100.10"
IFACE = "virbr1"
TARGET_PORTS = "139,445"

# Filtro BPF para tcpdump/tshark enfocado solo en la VM para reducir ruido
CAPTURE_FILTER = f"host {TARGET_IP}"

# Configuración de IA (Compatible con Groq, DeepSeek, OpenRouter, OpenAI)
LLM_API_KEY = os.getenv("LLM_API_KEY")
LLM_BASE_URL = os.getenv("LLM_BASE_URL", "https://api.deepseek.com/v1")
LLM_MODEL = os.getenv("LLM_MODEL", "deepseek-v4-flash")
if not LLM_API_KEY:
    raise ValueError("¡Error! No se encontró LLM_API_KEY. Revisa tu archivo .env")
# Configuración de Telemetría
CAPTURES_DIR = os.path.join(
    os.path.dirname(os.path.dirname(__file__)), "Telemetria", "captures"
)
os.makedirs(CAPTURES_DIR, exist_ok=True)
