#!/bin/bash

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SUDOERS_FILE="/etc/sudoers.d/cdt"
MARKER="$SCRIPT_DIR/.cdt_setup_done"

# Cleanup automático al salir
trap 'sudo rm -f "$SUDOERS_FILE" 2>/dev/null' EXIT

# ---------------------------------------------------------------
# Lógica principal dentro de una función para capturar errores
# ---------------------------------------------------------------
main() {
    # ----- One-time setup -----
    if [ ! -f "$MARKER" ]; then
        echo "=== Computer Digital Twin — Instalación inicial ==="
        echo ""

        if ! groups "$USER" | grep -q libvirt; then
            echo "[*] Agregando $USER al grupo libvirt..."
            sudo usermod -aG libvirt "$USER" || {
                echo "[!] Error al agregar al grupo libvirt."
                return 1
            }
            echo "[!] Cambio de grupo aplicado. Es necesario cerrar sesión o ejecutar 'newgrp libvirt'."
            echo "    Luego puedes volver a ejecutar este script."
            return 1
        fi

        if [ -d "$SCRIPT_DIR/.venv" ]; then
            echo "[*] Instalando dependencias Python..."
            source "$SCRIPT_DIR/.venv/bin/activate"
            pip install -r "$SCRIPT_DIR/requerimientos.txt" --break-system-packages 2>&1 | tail -1
            deactivate 2>/dev/null
        else
            echo "[!] No existe .venv. Crealo con: python -m venv .venv"
            return 1
        fi

        touch "$MARKER"
        echo "[✓] Instalación completada."
        echo ""
    fi

    # ----- Lanzador -----
    echo "=== Computer Digital Twin — Lanzador ==="

    # Pedir contraseña sudo UNA vez
    if ! sudo -n true 2>/dev/null; then
        if command -v kdialog &>/dev/null; then
            password=$(kdialog --title "Computer Digital Twin" --password "Se necesita contraseña sudo:") || return 1
            echo "$password" | sudo -S -v || {
                kdialog --error "Contraseña incorrecta."
                return 1
            }
        elif command -v zenity &>/dev/null; then
            password=$(zenity --password --title "Computer Digital Twin") || return 1
            echo "$password" | sudo -S -v || {
                zenity --error --text "Contraseña incorrecta."
                return 1
            }
        else
            echo "[*] Escriba la contraseña de sudo:"
            sudo -v || { echo "[!] Contraseña incorrecta."; return 1; }
        fi
    fi

    # Crear sudoers temporal
    COMANDOS="$(which tcpdump),$(which nmap),$(which timeout),$(which rm)"
    echo "$USER ALL=(ALL) NOPASSWD: $COMANDOS" | sudo tee "$SUDOERS_FILE" > /dev/null 2>&1
    sudo chmod 440 "$SUDOERS_FILE" 2>/dev/null

    echo "[*] Sudoers temporal activo."
    echo ""

    cd "$SCRIPT_DIR"
    source .venv/bin/activate
    python main.py
}

# ---------------------------------------------------------------
# Ejecutar y siempre pausar al final
# ------------------------------------------------------------
main; EXIT_CODE=$?

echo ""
echo "Sesión finalizada — sudoers temporal eliminado."

if [ -t 0 ]; then
    echo ""
    read -n 1 -s -r -p "Presiona cualquier tecla para cerrar..."
    echo ""
fi

exit $EXIT_CODE
