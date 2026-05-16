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
