# 👑 Computer Digital Twin (Red vs Blue Simulator)

Este proyecto es un simulador de ciberseguridad automatizado diseñado para ejecutar y monitorear ciberataques en entornos controlados mediante la orquestación de Máquinas Virtuales. 

El sistema enfrenta a dos agentes automatizados:
* **🔴 Red Team (Hacker Agent):** Se encarga de atacar la infraestructura vulnerable usando herramientas como Nmap.
* **🔵 Blue Team (SOC Manager con IA):** Captura y analiza el tráfico de red (`tcpdump`) y delega la revisión de alertas y logs a la Inteligencia artificial de Modelos de Lenguaje (OpenAI o Google Gemini) para reaccionar o reportar anomalías en tiempo real.

## 📋 Requisitos Previos

1. **Sistema Operativo:** Se recomienda **Linux**. Si usas Windows, es altamente recomendable utilizar **WSL 2 (Ubuntu u otra distribución)** debido a las dependencias de red subyacentes.
2. **Python 3.10+** (o superior).
3. **Herramientas de red del sistema:** Debes tener instalados `nmap` y `tcpdump` en tu sistema operativo, ya que los scripts de Python los invocan por detrás.
4. Una herramienta de virtualización compatible con la lógica del proyecto (Virtual Machine Manager/Libvirt o VirtualBox).

## 🖥️ Configuración de la Máquina Virtual (Target)

Para que el orquestador pueda interactuar con la infraestructura y automatizar los ataques, es **estrictamente necesario** preparar la máquina virtual vulnerable siguiendo estos pasos:

1. **Crear la Máquina Virtual:** En tu administrador de VMs (Virtual Machine Manager o VirtualBox), crea una nueva máquina y nómbrala **EXACTAMENTE**:
   * `XP_Testing_1`
2. **Descargar e Instalar la ISO:** Puedes descargar la ISO de Windows XP SP3 VL (x86) de Massgrave en el siguiente enlace: [Descargar ISO](https://buzzheavier.com/nar2zwokpo9t). Una vez descargada, colócala en la carpeta `ISO/` (está ignorada en git por su tamaño) y realiza una instalación estándar en tu máquina virtual (esto emulará un sistema legado vulnerable).
3. **Configuración Inicial:** Una vez instalado, asegúrate de que el equipo inicie correctamente y tenga conectividad de red con tu sistema base. (Windows XP suele tener abiertos los puertos 139 y 445 por defecto en configuraciones de red, lo cual es ideal para que Nmap los detecte).
4. **Tomar el Snapshot Base:** Conducida la configuración inicial, crea un **Snapshot (Captura o Instantánea)** de la máquina virtual. Debes nombrarlo **EXACTAMENTE** de la siguiente manera:
   * `XP_Ready_Hack`

*Nota: El orquestador de Python buscará específicamente esta VM (`XP_Testing_1`) y revertirá a este snapshot (`XP_Ready_Hack`) cada vez que inicies una nueva simulación, garantizando que el entorno vuelva a ser limpio y vulnerable.*

## 🚀 Instalación y Configuración

**1. Clonar el repositorio y situarse en la carpeta**
```bash
git clone <url-del-repositorio>
cd ComputerDigitalTwin
```

**2. Crear y activar el entorno virtual**
```bash
python -m venv .venv
source .venv/bin/activate
```
*(Nota para usuarios de Windows WSL: Asegúrate de estar dentro del entorno Linux para que se generen las carpetas estilo bash).*

**3. Instalar las dependencias de Python**
```bash
pip install -r requerimientos.txt
```

**4. Configurar las Variables de Entorno (IA y Virtualización)**
Debes crear un archivo llamado `.env` en la raíz del proyecto. Este archivo proveerá las credenciales para la IA del SOC y permitirá elegir tu proveedor de máquinas virtuales (Libvirt o VirtualBox).
Ejemplo de `/.env`:
```env
LLM_API_KEY="tu-clave-secreta-de-openai-o-gemini"

# Opciones: "libvirt" (por defecto) o "virtualbox"
VM_PROVIDER="virtualbox"
```
*(Nota para usuarios de Windows/WSL: VirtualBox es el proveedor recomendado, solo asegúrate de tener `VBoxManage` accesible desde la línea de comandos).*

## 🎮 Ejecución

Una vez que todo está instalado y configurado correctamente, arranca el orquestador principal:

```bash
python main.py
```

Esto desplegará un menú interactivo en tu terminal desde el cual podrás iniciar la simulación completa o lanzar al Red Team de forma manual.
