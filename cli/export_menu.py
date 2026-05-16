from rich.console import Console
from rich.prompt import Prompt

console = Console()


def select_export_format():

    console.print("\n[bold cyan]Exportar reporte del incidente[/]")
    console.print("  [1] PDF")
    console.print("  [2] CSV")
    console.print("  [3] Ambos (PDF + CSV)")
    console.print("  [4] No exportar")

    option = Prompt.ask(
        "[bold cyan]Selecciona formato[/]", choices=["1", "2", "3", "4"], default="4"
    )

    return option
