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

        for port in re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\.(\d{1,5})\b", log):
            ports.add(port)

    smb_port_445_count = sum(1 for p in dst_ports if p == "445")
    smb_ports = sum(1 for p in dst_ports if p in ("139", "445"))
    payload_sizes = []
    for log in logs:
        m = re.search(r"length (\d+)", log, re.IGNORECASE)
        if m:
            payload_sizes.append(int(m.group(1)))
    payload_size_counts = {}
    for s in payload_sizes:
        payload_size_counts[s] = payload_size_counts.get(s, 0) + 1
    repeated_sizes = {k: v for k, v in payload_size_counts.items() if v >= 3 and k > 0}

    indicadores = []
    if len(dst_ports) >= 5 and length_nonzero > 0:
        indicadores.append("multi_port_with_payload")
    if any(flag in flags_counts for flag in ["none", "fpu", "fin", "xmas"]):
        indicadores.append("stealth_flag_scan")
    if "syn" in flags_counts and len(dst_ports) >= 5:
        indicadores.append("syn_scan_pattern")
    if smb_ports >= 3 and length_nonzero > 10:
        indicadores.append("smb_heavy_traffic")
    if smb_port_445_count >= 5 and len(repeated_sizes) >= 2:
        indicadores.append("ms17_grooming")
    if smb_ports >= 3 and any("P" in str(flag) for flag in flags_counts):
        write_andx = sum(1 for s in payload_sizes if 18 <= s <= 168)
        if write_andx >= 5:
            indicadores.append("ms17_writeandx_pipe")

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
        "smb_traffic": {
            "port_445_packets": smb_port_445_count,
            "total_smb_packets": smb_ports,
            "write_like_ops": sum(1 for s in payload_sizes if 18 <= s <= 168),
        },
        "repeated_payload_sizes": dict(list(repeated_sizes.items())[:10]),
    }


def parse_llm_json(content: str) -> dict:
    text = content.strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?", "", text).strip()
        if text.endswith("```"):
            text = text[: -len("```")].strip()

    try:
        return json.loads(text)
    except json.JSONDecodeError:
        match = re.search(r"\{.*\}", text, re.DOTALL)
        if match:
            return json.loads(match.group(0))
        raise
