import string


def _is_printable_line(line: str, threshold: float = 0.85) -> bool:
    if not line:
        return False
    printable = sum(1 for c in line if c in string.printable)
    return (printable / max(1, len(line))) >= threshold


def normalize_tcpdump_logs(logs: list) -> list:
    """Une entradas multi-linea de tcpdump y descarta lineas no imprimibles."""
    normalizados = []

    for raw in logs:
        if not raw:
            continue

        line = raw.rstrip("\n")
        if not _is_printable_line(line):
            continue

        if line.startswith((" ", "\t")) and normalizados:
            normalizados[-1] = f"{normalizados[-1]} | {line.strip()}"
            continue

        normalizados.append(line)

    return normalizados


def _looks_like_packet(log: str) -> bool:
    if any(token in log for token in [" IP ", " IP6 ", "IP ", "IP6 "]):
        return True
    if "Flags [" in log:
        return True
    if " > " in log:
        return True
    if "proto" in log and "length" in log:
        return True
    return False


def filter_relevant_logs(logs: list, max_lines: int = 40) -> list:
    """Filtra y devuelve un subconjunto de logs relevantes para el análisis."""
    if not logs:
        return []

    logs_normalizados = normalize_tcpdump_logs(logs)

    # Excluir mensajes informativos propios
    logs_filtrados = [
        log
        for log in logs_normalizados
        if "No se capturó" not in log
        and "tcpdump:" not in log
        and _looks_like_packet(log)
    ]

    # Quedarnos con logs únicos para no saturar al LLM con paquetes repetidos (ej. retransmisiones)
    logs_unicos = []
    vistos = set()
    for log in logs_filtrados:
        if log not in vistos:
            vistos.add(log)
            logs_unicos.append(log)

    # Priorizar conexiones con datos reales (ignorar ACK/SYN vacíos si tenemos payloads)
    logs_con_datos = [log for log in logs_unicos if "length 0" not in log]
    
    # IMPORTANTE: A veces los paquetes de Nmap no tienen payload de datos (length 0) pero
    # sí son críticos (ej. SYN scans o ciertas banderas anómalas). 
    # Por tanto, no deberíamos descartarlos todos si resultan ser la mayoría del tráfico atacante.
    if len(logs_con_datos) > 10:
        seleccion = logs_con_datos
    else:
        # Mezclamos paquetes con datos y paquetes SYN/ACK vitales para el contexto del LLM
        seleccion = logs_unicos

    # Limitar cantidad de lineas (tomamos una muestra variada, partes del inicio y partes del final)
    if len(seleccion) > max_lines:
        head = max_lines // 2
        tail = max_lines - head - 1
        muestra = (
            seleccion[:head]
            + ["... [Tráfico intermedio omitido] ..."]
            + seleccion[-tail:]
        )

        # Aseguramos que se incluyan algunos paquetes con payload si existen
        payload_extra = [log for log in logs_con_datos if log not in muestra]
        for log in payload_extra[:3]:
            muestra.insert(0, log)
            if len(muestra) > max_lines:
                muestra.pop()

        return muestra

    return seleccion
