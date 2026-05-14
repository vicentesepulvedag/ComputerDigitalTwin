# Computer Digital Twin (Red vs Blue Simulator)

Simulador de ciberseguridad automatizado que orquesta ataques Red Team y defensa Blue Team en entornos de máquinas virtuales, con análisis forense por IA.

## Arquitectura

```
main.py                     → Entry point (3 líneas)
cli/
  menu.py                   → Menú interactivo con rich
  display.py                → Paneles, tablas, colores, syntax highlighting
orchestrator/
  actions.py                → Lógica de simulación (sin prints)
  registry.py               → Registro de comandos (patrón dispatcher)
Agentes/
  Red/hacker_agent.py       → Orquestador de ataques (nmap, MS17-010)
  Blue/soc_agent.py         → Captura tcpdump + análisis con LLM
Infraestructura/
  network.py                → Captura de tráfico con tcpdump
  vm_manager.py             → Control de VMs (libvirt/virtualbox)
config/
  settings.py               → Configuración multi-SO y LLM
```

## Requisitos

- Linux (o WSL2 en Windows)
- Python 3.10+
- `nmap`, `tcpdump` instalados en el sistema
- Libvirt (recomendado) o VirtualBox
- Máquinas virtuales configuradas

## Sistemas operativos soportados

| SO          | VM           | Snapshot        | IP             |
|-------------|-------------|-----------------|----------------|
| Windows XP  | XP_Testing_1 | XP_Not_Firewall | 192.168.100.10 |
| Windows 7   | Win7_Testing  | Win7_FirewallOFF| 192.168.100.9  |
| Windows 10  | Win10_Testing | Win10_Clean     | 192.168.100.12 |

## Instalación

```bash
git clone <repo> && cd ComputerDigitalTwin
python -m venv .venv
source .venv/bin/activate
pip install -r requerimientos.txt
```

## Configuración

Crear `.env` en la raíz:

```env
# Obligatorio — clave del LLM (DeepSeek por defecto)
LLM_API_KEY="sk-tu-key"

# Opcional — modelo premium para recomendaciones
LLM_BETTER_API_KEY="sk-tu-key-pro"
LLM_BETTER_MODEL="deepseek-v4-pro"

# Opciones: "libvirt" (por defecto) o "virtualbox"
VM_PROVIDER="libvirt"
```

## Ejecución

**Opción recomendada** (sudo temporario, seguro):

```bash
./cdt.sh
```

Pide contraseña una vez, la mantiene en caché mientras corre el programa, y al salir restaura todo.

**Opción directa** (si ya tienes sudoers configurado):

```bash
source .venv/bin/activate
python main.py
```

## Flujo del programa

1. **Selección de SO** — eliges qué máquina virtual atacar
2. **Menú de acciones**:
   - Restaurar VM a snapshot limpio
   - Ataques Red Team individuales (básico, CVEs, MS17-010 checker, MS17-010 extracción)
   - Simulaciones completas (Red + Blue con análisis IA)
   - Volver a seleccionar SO o salir

## Modelos de IA

| Uso                     | Modelo por defecto      | Variable              |
|-------------------------|------------------------|-----------------------|
| Detección de amenazas   | `deepseek-v4-flash`    | `LLM_MODEL`           |
| Recomendaciones         | `deepseek-v4-pro`      | `LLM_BETTER_MODEL`    |

Compatible con OpenAI, Groq, OpenRouter y cualquier API compatible.

## Personalización

Agregar un nuevo SO: edita `OS_CONFIGS` en `config/settings.py` con el nombre de VM, snapshot e IP. El menú lo detecta automáticamente.

Agregar una nueva acción al menú: regístrala con `register("clave", handler_fn, "descripción")` en `cli/menu.py`.
