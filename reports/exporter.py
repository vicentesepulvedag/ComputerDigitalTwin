"""
Formato PDF del reporte:

- Título del incidente
- Resumen:
    * Amenaza
    * SO objetivo
    * CVSS
- Descripción
- Explicación técnica
- Recomendaciones de mitigación
- Logs originales del sistema
"""

from pathlib import Path
from datetime import datetime

from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Preformatted

from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.pagesizes import letter


class PDFExporter:

    @staticmethod
    def export(report_data):

        output_dir = Path("reports/output")
        output_dir.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        filename = output_dir / f"incident_report_{timestamp}.pdf"

        doc = SimpleDocTemplate(str(filename), pagesize=letter)

        styles = getSampleStyleSheet()

        elements = []

        title = Paragraph("Reporte de Incidente", styles["Title"])

        elements.append(title)
        elements.append(Spacer(1, 20))

        summary = f"""
        <b>Amenaza:</b> {report_data.get("threat", "N/A")}<br/>
        <b>SO Objetivo:</b> {report_data.get("target_os", "N/A")}<br/>
        <b>CVSS:</b> {report_data.get("cvss", "N/A")}<br/>
        """

        elements.append(Paragraph(summary, styles["BodyText"]))

        elements.append(Spacer(1, 15))

        elements.append(Paragraph("<b>Descripción</b>", styles["Heading2"]))

        elements.append(
            Paragraph(report_data.get("description", ""), styles["BodyText"])
        )

        elements.append(Spacer(1, 15))

        elements.append(
            Paragraph("<b>Explicación de la Vulnerabilidad</b>", styles["Heading2"])
        )

        elements.append(
            Paragraph(report_data.get("technical_explanation", ""), styles["BodyText"])
        )

        elements.append(Spacer(1, 15))

        elements.append(
            Paragraph("<b>Recomendaciones de Mitigación</b>", styles["Heading2"])
        )

        mitigations = report_data.get("mitigations", [])

        for mitigation in mitigations:

            text = f"""
            <b>[{mitigation.get("severity", "MEDIA")}]</b>
            {mitigation.get("description", "")}<br/><br/>

            <b>Comando:</b><br/>
            {mitigation.get("command", "")}<br/><br/>

            <b>Nota:</b><br/>
            {mitigation.get("note", "")}
            """

            elements.append(Paragraph(text, styles["BodyText"]))

            elements.append(Spacer(1, 12))

        elements.append(Paragraph("<b>Logs</b>", styles["Heading2"]))

        logs = report_data.get("logs", "")

        elements.append(Preformatted(logs, styles["Code"]))

        doc.build(elements)

        print(f"[+] PDF generado: {filename}")
