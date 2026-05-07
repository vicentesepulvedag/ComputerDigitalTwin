import sys
import os

# Agregamos la ruta base del proyecto al path de Python para que pueda encontrar los módulos
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from Agentes.Blue.Interfaz.cli import iniciar_chatbot

if __name__ == "__main__":
    iniciar_chatbot()
