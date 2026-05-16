from reports.exporter import PDFExporter
from reports.csv_exporter import CSVExporter


report_data = {
    "threat": "Exfiltración SMB",
    "target_os": "Windows 7",
    "cvss": "7.05 [HIGH]",

    "description":
        "Se detectó tráfico SMB entre atacante y víctima.",

    "technical_explanation":
        "El atacante utilizó el recurso compartido C$.",

    "mitigations": [
        {
            "severity": "ALTA",
            "description": "Deshabilitar SMBv1",
            "command":
                "dism /online /disable-feature /featurename:SMB1Protocol",
            "note":
                "Reiniciar después de ejecutar."
        },

        {
            "severity": "MEDIA",
            "description": "Bloquear puerto 445",
            "command":
                "netsh advfirewall firewall add rule ...",
            "note":
                "Validar servicios legítimos."
        }
    ],

    "logs":
        """
SMB WRITE REQUEST
192.168.100.1 -> 192.168.100.9
STATUS_SUCCESS
FILE: cookies/index.dat
"""
}

PDFExporter.export(report_data)

CSVExporter.export(report_data)

print("\n[+] Reportes generados correctamente")
