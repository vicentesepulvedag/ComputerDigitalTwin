"""
Formato CSV del reporte:

Columnas:
- Campo
- Detalle

Incluye:
- Amenaza
- SO objetivo
- CVSS
- Descripción
- Explicación técnica
- Mitigaciones
- Logs originales
"""

import csv

from pathlib import Path
from datetime import datetime


class CSVExporter:

    @staticmethod
    def export(report_data):

        output_dir = Path("reports/output")
        output_dir.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        filename = output_dir / f"incident_report_{timestamp}.csv"

        with open(filename, "w", newline="", encoding="utf-8") as csvfile:

            writer = csv.writer(csvfile)

            writer.writerow(["Campo", "Detalle"])

            writer.writerow(["Amenaza", report_data.get("threat", "")])

            writer.writerow(["SO Objetivo", report_data.get("target_os", "")])

            writer.writerow(["CVSS", report_data.get("cvss", "")])

            writer.writerow(["Descripción", report_data.get("description", "")])

            writer.writerow(
                ["Explicación Técnica", report_data.get("technical_explanation", "")]
            )

            writer.writerow([])

            writer.writerow(["Mitigaciones"])

            mitigations = report_data.get("mitigations", [])

            for mitigation in mitigations:

                writer.writerow([mitigation.get("severity", "")])

                writer.writerow([mitigation.get("description", "")])

                writer.writerow([mitigation.get("command", "")])

                writer.writerow([mitigation.get("note", "")])

                writer.writerow([])

            writer.writerow(["Logs"])

            writer.writerow([report_data.get("logs", "")])

        print(f"[+] CSV generado: {filename}")
