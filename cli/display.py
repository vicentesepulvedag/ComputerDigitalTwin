from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.syntax import Syntax
from rich.markdown import Markdown
from rich import box

console = Console()


def banner(titulo: str, estilo: str = "bold cyan") -> None:
    console.print(Panel(f"[{estilo}]{titulo}[/]", box=box.HEAVY, expand=False))


def sub_banner(titulo: str, estilo: str = "bold yellow") -> None:
    console.print(Panel(f"[{estilo}]{titulo}[/]", box=box.ROUNDED, expand=False))


def error(msg: str) -> None:
    console.print(f"[bold red]✗[/] {msg}")


def ok(msg: str) -> None:
    console.print(f"[bold green]✓[/] {msg}")


def info(msg: str) -> None:
    console.print(f"[bold blue]ℹ[/] {msg}")


def separador(modo: str = "fase") -> None:
    if modo == "fase":
        console.rule("[bold cyan]FASE[/]", style="cyan")
    elif modo == "fin":
        console.rule("[bold red]FIN[/]", style="red")
    else:
        console.rule(style="dim")


def con_progreso(mensaje: str):
    return Progress(
        SpinnerColumn(),
        TextColumn(f"[bold blue]{mensaje}..."),
        console=console,
    )


def mostrar_resultado_ataque(resultado: dict) -> None:
    if resultado["status"] == "success":
        ok("Operación completada.")
        data = resultado.get("data", "")
        if data:
            panel = Panel(
                data[:1000] if len(data) > 1000 else data,
                title="[bold green]Resultado[/]",
                border_style="green",
                box=box.ROUNDED,
            )
            console.print(panel)
    else:
        error(f"Error: {resultado.get('message', 'Desconocido')}")


# ----------------------------------------------------------------
# Renderizado del reporte de incidente
# ----------------------------------------------------------------

_COMANDOS_INICIO = (
    "dism",
    "netsh",
    "wmic",
    "for ",
    "cd ",
    "MpCmdRun",
    "auditpol",
    "schtasks",
    "sc ",
    "Get-NetAdapter",
    "powershell",
    "reg ",
)


def _es_linea_comando(linea: str) -> bool:
    s = linea.strip()
    if not s:
        return False
    if any(s.lower().startswith(c) for c in _COMANDOS_INICIO):
        return True
    # También detectar líneas como "[Alta] netsh ..." o "[Media] sc ..."
    import re as _re

    m = _re.match(r"^\[(Alta|Media|Baja)\]\s+(\S.*)", s)
    if m:
        resto = m.group(2)
        return any(resto.lower().startswith(c) for c in _COMANDOS_INICIO)
    return False


def mostrar_reporte_incidente(
    llm_response: dict, score: float, nivel: str, os_name: str
) -> None:
    vulnerabilities = llm_response.get("vulnerabilities", [])
    if not vulnerabilities:
        info(
            "La IA determinó que el tráfico era benigno o no se encontraron vulnerabilidades."
        )
        return

    vuln = vulnerabilities[0]
    metrics = vuln.get("CVSS_metrics", {})

    table = Table(title="Reporte de Incidente", box=box.HEAVY_EDGE, border_style="red")
    table.add_column("Campo", style="bold yellow")
    table.add_column("Detalle", style="white")

    table.add_row("Amenaza", vuln.get("type", "Desconocido"))
    table.add_row("SO objetivo", os_name)
    table.add_row("Gravedad CVSS 3.1", f"{score} [{nivel}]")

    descripcion = vuln.get("description", "Sin descripción.")
    table.add_row("Descripción", descripcion)
    console.print(table)

    explanation = vuln.get("explanation", "")
    if explanation:
        md = Markdown(explanation)
        panel = Panel(
            md,
            title="[bold red]Explicación de la Vulnerabilidad[/]",
            border_style="red",
            box=box.ROUNDED,
        )
        console.print(panel)

    recs = vuln.get("recommendations")
    if recs:
        from rich.console import Group as RichGroup
        from rich.text import Text as RichText

        elements = []
        items = recs if isinstance(recs, list) else [recs]

        for i, item in enumerate(items):
            if i > 0:
                elements.append(RichText(""))

            lines = item.split("\n")
            pre_desc = []
            cmds = []
            post_desc = []
            destino = pre_desc

            for line in lines:
                if _es_linea_comando(line):
                    cmds.append(line.rstrip())
                    destino = post_desc
                else:
                    destino.append(line.rstrip())

            pre_text = "\n".join(pre_desc).strip()
            if pre_text:
                elements.append(Markdown(pre_text.replace("• ", "- ", 1)))

            if cmds:
                elements.append(RichText(""))
                elements.append(
                    Syntax("\n".join(cmds), "bash", theme="monokai", word_wrap=True)
                )
                elements.append(RichText(""))

            post_text = "\n".join(post_desc).strip()
            if post_text:
                elements.append(Markdown(f"  {post_text}"))

        panel = Panel(
            RichGroup(*elements),
            title="[bold green]Recomendaciones de Mitigación[/]",
            border_style="green",
            box=box.ROUNDED,
        )
        console.print(panel)
