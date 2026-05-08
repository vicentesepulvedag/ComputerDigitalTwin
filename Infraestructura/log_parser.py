def filter_relevant_logs(logs: list, max_lines: int = 10) -> list:
    """Filtra y devuelve un subconjunto de logs relevantes para el análisis."""
    if not logs:
        return []
    
    # Excluir mensajes informativos propios
    logs_filtrados = [log for log in logs if "No se capturó" not in log]
    
    # Limitar cantidad de lineas
    if len(logs_filtrados) > max_lines:
        return logs_filtrados[:max_lines]
        
    return logs_filtrados
