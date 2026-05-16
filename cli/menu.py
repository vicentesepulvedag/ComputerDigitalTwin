import sys
import subprocess

from rich.table import Table
from rich import box
from rich.prompt import Prompt

from cli.display import (
    console,
    banner,
    sub_banner,
    error,
    ok,
    info,
    separador,
    con_progreso,
    mostrar_resultado_ataque,
    mostrar_reporte_incidente,
)
from config.settings import OS_CONFIGS, set_os
from orchestrator.actions import (
    seleccionar_os,
    ejecutar_red_team,
    ejecutar_extraccion_ms17,
    restaurar_entorno,
    ejecutar_simulacion,
)

os_actual = "Windows XP"


def _simular(modo: str):
    global os_actual
    nombre = "Simulación Completa"
    if modo == "vuln":
        nombre += " (Evaluación CVEs)"
    elif modo == "ms17-010-extract":
        nombre += " (MS17-010)"

    banner(nombre)

    with con_progreso("Preparando infraestructura") as progress:
        progress.add_task("", total=None)

    separador("fase")
    sub_banner("Fase 1: Preparación de Infraestructura")
    info(f"Restaurando snapshot de '{os_actual}'...")

    with con_progreso("Restaurando y arrancando VM") as progress:
        progress.add_task("", total=None)

    result = ejecutar_simulacion(modo, os_actual)

    if result.status == "error":
        error(result.error_msg)
        separador("fin")
        return

    separador("fase")
    sub_banner("Fase 2: Ataque y Defensa Simultáneos")
    info(f"Red Team atacando '{result.os_name}'...")
    info("Blue Team monitoreando tráfico...")

    separador("fase")
    sub_banner("Fase 3: Análisis Forense (IA)")

    if result.status == "warning":
        info(result.error_msg)
        separador("fin")
        return

    mostrar_reporte_incidente(
        result.llm_response,
        result.cvss_score,
        result.cvss_nivel,
        result.os_name,
    )
    separador("fin")


def _red_team_solo(modo: str, titulo: str):
    global os_actual
    banner(titulo)
    result = ejecutar_red_team(modo, os_actual)
    mostrar_resultado_ataque(result)
    separador("fin")


# ----------------------------------------------------------------
# Menú principal: selección de SO
# ----------------------------------------------------------------
def _pantalla_seleccion_so() -> str | None:
    console.print("\n" * 2)
    banner("COMPUTER DIGITAL TWIN — Selección de Sistema Operativo")
    console.print()

    ops = list(OS_CONFIGS.keys())
    table = Table(box=box.SIMPLE_HEAD, border_style="cyan")
    table.add_column("#", style="bold yellow", width=3)
    table.add_column("Sistema Operativo", style="white")
    table.add_column("VM", style="dim")
    table.add_column("IP", style="dim")

    for i, nombre in enumerate(ops, 1):
        cfg = OS_CONFIGS[nombre]
        table.add_row(str(i), nombre, cfg["VM_NAME"], cfg["TARGET_IP"])

    table.add_row("0", "[bold red]Salir[/]", "", "")
    console.print(table)

    opcion = Prompt.ask(
        "\n[bold cyan]Elige un sistema operativo[/]", default="", show_default=False
    )

    if opcion == "0":
        sys.exit(0)

    try:
        idx = int(opcion)
        if 1 <= idx <= len(ops):
            nombre = ops[idx - 1]
            set_os(nombre)
            return nombre
    except ValueError:
        pass

    error("Opción inválida.")
    return None


# ----------------------------------------------------------------
# Menú de acciones (por SO)
# ----------------------------------------------------------------
_pantalla_accion_items: list[tuple[str, str]] = [
    ("1", "Restaurar todo (VM + limpiar datos extraídos)"),
    ("", "[bold]--- Ataques Red Team (individuales) ---[/]"),
    ("2", "Ataque Básico"),
    ("3", "Evaluación de Vulnerabilidades / CVEs"),
    ("4", "MS17-010 Checker (EternalBlue)"),
    ("5", "MS17-010 Extracción de Archivos"),
    ("", "[bold]--- Simulaciones Completas (Red + Blue) ---[/]"),
    ("6", "Ataque Básico + SOC"),
    ("7", "Ataque con CVEs + SOC"),
    ("8", "MS17-010 + SOC"),
    ("", "[bold]--- ---[/]"),
    ("9", "Volver (cambiar sistema operativo)"),
    ("0", "Salir"),
]


def _mostrar_pantalla_acciones():
    console.print("\n" * 2)
    banner(f"COMPUTER DIGITAL TWIN — [bold white]{os_actual}[/]")
    console.print()

    table = Table(box=box.SIMPLE_HEAD, border_style="cyan")
    table.add_column("#", style="bold yellow", width=3)
    table.add_column("Acción", style="white")

    for key, desc in _pantalla_accion_items:
        if not key:
            table.add_row("", f"[dim]{desc}[/]")
        else:
            table.add_row(key, desc)

    console.print(table)
    return Prompt.ask(
        "\n[bold cyan]Elige una opción[/]", default="", show_default=False
    )


def pantalla_acciones():
    global os_actual

    while True:
        opcion = _mostrar_pantalla_acciones()

        if opcion == "0":
            banner("Saliendo...", "bold red")
            sys.exit(0)

        elif opcion == "1":
            banner("Restauración del Entorno")
            with con_progreso("Restaurando VM") as progress:
                progress.add_task("", total=None)
            result = restaurar_entorno(os_actual)
            ok("Restauración completada.")
            separador("fin")

        elif opcion == "2":
            _red_team_solo("normal", "Red Team — Ataque Básico")
        elif opcion == "3":
            _red_team_solo("vuln", "Red Team — Evaluación de Vulnerabilidades")
        elif opcion == "4":
            _red_team_solo("ms17-010", "Red Team — MS17-010 Checker")
        elif opcion == "5":
            banner("Red Team — MS17-010 Extracción de Archivos")
            result = ejecutar_extraccion_ms17(os_actual)
            mostrar_resultado_ataque(result)
            separador("fin")

        elif opcion == "6":
            _simular("normal")
        elif opcion == "7":
            _simular("vuln")
        elif opcion == "8":
            _simular("ms17-010-extract")

        elif opcion == "9":
            nuevo = _pantalla_seleccion_so()
            if nuevo:
                os_actual = nuevo
                ok(f"SO cambiado a: {os_actual}")
            else:
                # reintentar selección
                pass

        else:
            error("Opción inválida. Intenta nuevamente.")


def menu_interactivo():
    global os_actual
    try:
        subprocess.run(["sudo", "-v"], check=True)
    except subprocess.CalledProcessError:
        error(
            "No se pudo validar sudo. Ejecutá './cdt.sh' para lanzar el programa con permisos temporales."
        )

    while True:
        seleccion = _pantalla_seleccion_so()
        if seleccion:
            os_actual = seleccion
            pantalla_acciones()
        # si no hay selección válida, el loop lo reintenta

from rich.console import Console
from rich.prompt import Prompt

console = Console()

def select_export_format():

    console.print("\n[bold cyan]Exportar reporte[/bold cyan]")

    console.print("[1] PDF")
    console.print("[2] CSV")
    console.print("[3] No exportar")

    option = Prompt.ask(
        "Seleccione formato",
        choices=["1", "2", "3"],
        default="1"
    )

    return option


