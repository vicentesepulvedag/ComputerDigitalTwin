import json
import re


def format_logs_for_prompt(logs: list) -> str:
    return "\n".join(f"{i + 1}. {log}" for i, log in enumerate(logs))


def summarize_logs(logs: list) -> dict:
    flags_counts = {}
    ttl_values = set()
    length_zero = 0
    length_nonzero = 0
    max_length = 0
    ports = set()
    src_ports = set()
    dst_ports = set()
    src_ips = set()
    dst_ips = set()
    timestamps = []
    smb_timestamps = []

    for log in logs:
        match = re.search(r"flags \[([^\]]+)\]", log, re.IGNORECASE)
        if match:
            flag = match.group(1).lower()
            flags_counts[flag] = flags_counts.get(flag, 0) + 1

        match = re.search(r"ttl (\d+)", log, re.IGNORECASE)
        if match:
            ttl_values.add(int(match.group(1)))

        match = re.search(r"length (\d+)", log, re.IGNORECASE)
        if match:
            length = int(match.group(1))
            if length == 0:
                length_zero += 1
            else:
                length_nonzero += 1
                if length > max_length:
                    max_length = length

        match = re.search(
            r"(\d+\.\d+\.\d+\.\d+)\.(\d+) > (\d+\.\d+\.\d+\.\d+)\.(\d+):",
            log,
        )
        if match:
            src_ip, src_port, dst_ip, dst_port = match.groups()
            src_ips.add(src_ip)
            dst_ips.add(dst_ip)
            src_ports.add(src_port)
            dst_ports.add(dst_port)
            ports.add(src_port)
            ports.add(dst_port)

        # Parse timestamp for burst analysis
        ts = re.match(r"(\d+:\d+:\d+\.\d+)", log)
        if ts:
            timestamps.append(ts.group(1))
            if ":445" in log or ".445 " in log:
                smb_timestamps.append(ts.group(1))

        for port in re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\.(\d{1,5})\b", log):
            ports.add(port)

    smb_port_445_count = 0
    smb_ports_count = 0
    payload_sizes = []
    for log in logs:
        match = re.search(r"(\d+\.\d+\.\d+\.\d+)\.(\d+) > (\d+\.\d+\.\d+\.\d+)\.(\d+):", log)
        if match:
            dst_port = match.group(4)
            if dst_port == "445":
                smb_port_445_count += 1
            if dst_port in ("139", "445"):
                smb_ports_count += 1
        
        m = re.search(r"length (\d+)", log, re.IGNORECASE)
        if m:
            payload_sizes.append(int(m.group(1)))
    payload_size_counts = {}
    for s in payload_sizes:
        payload_size_counts[s] = payload_size_counts.get(s, 0) + 1
    repeated_sizes = {k: v for k, v in payload_size_counts.items() if v >= 3 and k > 0}

    from datetime import datetime

    def _ts_to_sec(ts):
        try:
            parts = ts.split(":")
            h, m, s = int(parts[0]), int(parts[1]), float(parts[2])
            return h * 3600 + m * 60 + s
        except (IndexError, ValueError):
            return None

    burst_info = {}
    if len(smb_timestamps) >= 3:
        smb_secs = [t for t in (_ts_to_sec(t) for t in smb_timestamps) if t is not None]
        if len(smb_secs) >= 3:
            span = smb_secs[-1] - smb_secs[0]
            gaps = [smb_secs[i + 1] - smb_secs[i] for i in range(len(smb_secs) - 1)]
            max_gap = max(gaps)
            min_gap = min(gaps)
            burst_info = {
                "smb_total_seconds": round(span, 2),
                "smb_packet_count": len(smb_secs),
                "smb_packets_per_second": round(len(smb_secs) / max(span, 0.01), 1),
                "min_gap_seconds": round(min_gap, 4),
                "max_gap_seconds": round(max_gap, 2),
            }

    smb_pps = burst_info.get("smb_packets_per_second", 0)
    is_bursty = smb_pps > 10.0  # EternalBlue enviará ráfagas densas
    is_spaced = burst_info.get("max_gap_seconds", 0) > 0.5  # Nmap hace pausas

    indicadores = []
    if len(dst_ports) >= 5 and length_nonzero > 0:
        indicadores.append("multi_port_with_payload")
    if any(flag in flags_counts for flag in ["none", "fpu", "fin", "xmas"]):
        indicadores.append("stealth_flag_scan")
    if "syn" in flags_counts and len(dst_ports) >= 5:
        indicadores.append("syn_scan_pattern")
    if smb_ports_count >= 3 and length_nonzero > 10:
        indicadores.append("smb_heavy_traffic")
    
    # Hacer que MS17 sea estricto para las ráfagas densas
    if smb_port_445_count >= 10 and len(repeated_sizes) >= 2 and is_bursty:
        indicadores.append("ms17_grooming")
    
    # Hacer que escritura andX sea también atada a comportamientos sospechosos rápidos
    if smb_ports_count >= 3 and any("P" in str(flag) for flag in flags_counts):
        write_andx = sum(1 for s in payload_sizes if 18 <= s <= 168)
        if write_andx >= 5 and is_bursty:
            indicadores.append("ms17_writeandx_pipe")
            
    # Etiqueta amigable para escaneos espaciados como Nmap NSE
    if smb_ports_count >= 10 and is_spaced and not is_bursty:
        indicadores.append("nmap_nse_spaced_scan")

    return {
        "total_lines": len(logs),
        "flags": flags_counts,
        "payload_lengths": {
            "zero": length_zero,
            "non_zero": length_nonzero,
            "max": max_length,
        },
        "ttl_unique": sorted(ttl_values)[:12],
        "src_ips": sorted(src_ips)[:10],
        "dst_ips": sorted(dst_ips)[:10],
        "src_ports": sorted(src_ports)[:20],
        "dst_ports": sorted(dst_ports)[:20],
        "ports": sorted(ports)[:20],
        "indicators": indicadores,
        "burst": burst_info,
        "smb_traffic": {
            "port_445_packets": smb_port_445_count,
            "total_smb_packets": smb_ports_count,
            "write_like_ops": sum(1 for s in payload_sizes if 18 <= s <= 168),
        },
        "repeated_payload_sizes": dict(list(repeated_sizes.items())[:10]),
    }


def parse_llm_json(content: str) -> dict:
    text = content.strip()

    # Stripear bloques markdown ```json ... ``` y ``` ... ``` de cualquier posición
    text = re.sub(r"(?s)^.*?```(?:json)?\s*\n?", "", text, count=1)
    text = re.sub(r"(?s)```.*$", "", text, count=1)
    text = text.strip()

    # Stripear cualquier texto antes del primer { o después del último }
    first_brace = text.find("{")
    last_brace = text.rfind("}")
    if first_brace != -1 and last_brace != -1 and last_brace > first_brace:
        text = text[first_brace : last_brace + 1]

    # Intentar parse directo
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    # Buscar { } al nivel más externo
    brace_depth = 0
    start = -1
    for i, c in enumerate(text):
        if c == "{":
            if brace_depth == 0:
                start = i
            brace_depth += 1
        elif c == "}":
            brace_depth -= 1
            if brace_depth == 0 and start != -1:
                candidate = text[start : i + 1]
                try:
                    return json.loads(candidate)
                except json.JSONDecodeError:
                    # Intentar limpiar trailing commas
                    cleaned = re.sub(r",\s*}", "}", candidate)
                    cleaned = re.sub(r",\s*]", "]", cleaned)
                    try:
                        return json.loads(cleaned)
                    except json.JSONDecodeError:
                        pass

    raise ValueError("No se pudo extraer JSON valido del texto recibido")
