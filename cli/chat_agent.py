from openai import OpenAI
from rich.prompt import Prompt
from rich.panel import Panel
from rich.markdown import Markdown
from rich import box

from cli.display import console, banner, ok, separador
from config.settings import LLM_API_KEY, LLM_BASE_URL, LLM_MODEL

if not LLM_API_KEY:
    raise ValueError("LLM_API_KEY no configurada")

client = OpenAI(api_key=LLM_API_KEY, base_url=LLM_BASE_URL)


def _build_system_context(report_data: dict) -> str:
    mitigations_text = ""
    for m in report_data.get("mitigations", []):
        mitigations_text += f"- [{m.get('severity','N/A')}] {m.get('description','')}\n"
        if m.get("command"):
            mitigations_text += f"  Comando: {m['command']}\n"
        if m.get("note"):
            mitigations_text += f"  Nota: {m['note']}\n"

    logs = report_data.get("logs", "")
    logs_preview = logs[:2000] if len(logs) > 2000 else logs

    return f"""Eres un analista SOC experto en ciberseguridad. Tu tarea es responder preguntas del usuario sobre el siguiente reporte de incidente generado por el sistema Computer Digital Twin.

Contexto del reporte:
- Amenaza: {report_data.get("threat", "N/A")}
- SO objetivo: {report_data.get("target_os", "N/A")}
- CVSS: {report_data.get("cvss", "N/A")}
- Descripción: {report_data.get("description", "N/A")}
- Explicación técnica: {report_data.get("technical_explanation", "N/A")}
- Recomendaciones:
{mitigations_text}
- Logs capturados:
{logs_preview}

Responde de forma clara, técnica y precisa. Si te preguntan algo fuera del contexto del reporte, indícalo amablemente. Puedes usar markdown para formatear tus respuestas."""


def iniciar_chat(report_data: dict):
    banner("Chat con el Agente SOC", "bold cyan")
    console.print(
        Panel(
            "[bold yellow]Puedes hacer preguntas sobre el reporte generado.[/]\n"
            "[dim]Escribe [bold]salir[/] o [bold]exit[/] para terminar el chat.[/]",
            box=box.ROUNDED,
            border_style="cyan",
        )
    )
    console.print()

    messages = [
        {"role": "system", "content": _build_system_context(report_data)},
        {
            "role": "assistant",
            "content": "Soy el analista SOC. He revisado el reporte de incidente. ¿Qué deseas consultar?",
        },
    ]

    while True:
        pregunta = Prompt.ask("[bold cyan]Tú[/]")
        if pregunta.strip().lower() in ("salir", "exit", "q", "quit"):
            ok("Chat finalizado.")
            separador("fin")
            break

        messages.append({"role": "user", "content": pregunta})

        try:
            with console.status("[bold yellow]Analizando consulta..."):
                response = client.chat.completions.create(
                    model=LLM_MODEL,
                    messages=messages,
                    temperature=0.3,
                )
            respuesta = response.choices[0].message.content.strip()
            messages.append({"role": "assistant", "content": respuesta})
            console.print(Panel(
                Markdown(respuesta),
                title="[bold green]Agente SOC[/]",
                border_style="green",
                box=box.ROUNDED,
            ))
        except Exception as e:
            console.print(f"[bold red]Error al consultar al agente: {e}[/]")
            break
