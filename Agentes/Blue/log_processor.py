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

    indicadores = []
    if len(dst_ports) >= 5 and length_nonzero > 0:
        indicadores.append("multi_port_with_payload")
    if any(flag in flags_counts for flag in ["none", "fpu", "fin", "xmas"]):
        indicadores.append("stealth_flag_scan")
    if "syn" in flags_counts and len(dst_ports) >= 5:
        indicadores.append("syn_scan_pattern")

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
