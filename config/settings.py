import os
from dotenv import load_dotenv

# Cargar variables de entorno
load_dotenv()

# Configuración de Virtualización
VM_NAME = "XP_Testing_1"
SNAPSHOT = "XP_Ready_Hack"

# Configuración de Red
RED_SUBNET = "192.168.100.0/24"
IFACE = "virbr1"
TARGET_PORTS = "139,445"

# Configuración de IA (Compatible con Groq, DeepSeek, OpenRouter, OpenAI)
LLM_API_KEY = os.getenv('LLM_API_KEY')
LLM_BASE_URL = os.getenv('LLM_BASE_URL', 'https://api.deepseek.com')
LLM_MODEL = os.getenv('LLM_MODEL', 'deepseek-chat')

# Configuración de Telemetría
CAPTURES_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "Telemetria", "captures")
