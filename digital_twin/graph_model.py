import json
from datetime import datetime

import networkx as nx

NODE_TYPES = ("vm", "service", "network", "user", "vulnerability", "attack_step", "file")
EDGE_TYPES = (
    "has_service", "on_network", "has_user",
    "has_vulnerability", "targets", "exploits",
    "exfiltrates", "next_step", "detected_by",
)


class DigitalTwinGraph:
    def __init__(self):
        self._graph = nx.DiGraph()

    @property
    def graph(self) -> nx.DiGraph:
        return self._graph

    def add_node(self, node_id: str, node_type: str, **attrs):
        attrs["node_type"] = node_type
        attrs["created_at"] = attrs.get("created_at", datetime.now().isoformat())
        self._graph.add_node(node_id, **attrs)

    def add_edge(self, u: str, v: str, edge_type: str, **attrs):
        attrs["edge_type"] = edge_type
        self._graph.add_edge(u, v, **attrs)

    def add_vm(self, vm_id: str, name: str, ip: str, os_version: str):
        self.add_node(vm_id, "vm", name=name, ip=ip, os_version=os_version)

    def add_service(self, service_id: str, name: str, port: int, protocol: str = "tcp"):
        self.add_node(service_id, "service", name=name, port=port, protocol=protocol)

    def add_network(self, net_id: str, cidr: str):
        self.add_node(net_id, "network", cidr=cidr)

    def add_user(self, user_id: str, username: str):
        self.add_node(user_id, "user", username=username)

    def add_vulnerability(self, vuln_id: str, cve: str, description: str, severity: str = ""):
        self.add_node(vuln_id, "vulnerability", cve=cve, description=description, severity=severity)

    def add_attack_step(self, step_id: str, attack_type: str, description: str, timestamp: str):
        self.add_node(
            step_id, "attack_step",
            attack_type=attack_type,
            description=description,
            timestamp=timestamp,
        )

    def add_file(self, file_id: str, path: str):
        self.add_node(file_id, "file", path=path)

    def link_vm_service(self, vm_id: str, service_id: str):
        self.add_edge(vm_id, service_id, "has_service")

    def link_vm_network(self, vm_id: str, net_id: str):
        self.add_edge(vm_id, net_id, "on_network")

    def link_vm_user(self, vm_id: str, user_id: str):
        self.add_edge(vm_id, user_id, "has_user")

    def link_service_vulnerability(self, service_id: str, vuln_id: str):
        self.add_edge(service_id, vuln_id, "has_vulnerability")

    def link_attack_target(self, step_id: str, target_id: str):
        self.add_edge(step_id, target_id, "targets")

    def link_attack_exploit(self, step_id: str, vuln_id: str):
        self.add_edge(step_id, vuln_id, "exploits")

    def link_attack_exfil(self, step_id: str, file_id: str):
        self.add_edge(step_id, file_id, "exfiltrates")

    def link_attack_detected(self, step_id: str, detection_id: str):
        self.add_edge(step_id, detection_id, "detected_by")

    def link_steps(self, prev_id: str, next_id: str):
        self.add_edge(prev_id, next_id, "next_step")

    def get_attack_path(self, start: str, end: str) -> list[str]:
        try:
            return nx.shortest_path(self._graph, source=start, target=end)
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            return []

    def get_attackers(self) -> list[str]:
        return [n for n, d in self._graph.nodes(data=True) if d.get("node_type") == "attack_step"]

    def get_vulnerable_services(self) -> list[tuple[str, str, str]]:
        result = []
        for u, v, d in self._graph.edges(data=True):
            if d.get("edge_type") == "has_vulnerability":
                vuln = self._graph.nodes[v]
                svc = self._graph.nodes[u]
                result.append((svc.get("name", u), vuln.get("cve", v), vuln.get("severity", "")))
        return result

    def get_affected_vms(self) -> list[str]:
        vuln_services = set()
        for u, v, d in self._graph.edges(data=True):
            if d.get("edge_type") == "has_vulnerability":
                vuln_services.add(u)
        affected = []
        for u, v, d in self._graph.edges(data=True):
            if d.get("edge_type") == "has_service" and v in vuln_services:
                affected.append(self._graph.nodes[u].get("name", u))
        return affected

    def summary(self) -> dict:
        counts = {}
        for _, d in self._graph.nodes(data=True):
            nt = d.get("node_type", "unknown")
            counts[nt] = counts.get(nt, 0) + 1
        edge_counts = {}
        for _, _, d in self._graph.edges(data=True):
            et = d.get("edge_type", "unknown")
            edge_counts[et] = edge_counts.get(et, 0) + 1
        return {
            "total_nodes": self._graph.number_of_nodes(),
            "total_edges": self._graph.number_of_edges(),
            "nodes_by_type": counts,
            "edges_by_type": edge_counts,
        }

    def to_json(self) -> str:
        data = nx.node_link_data(self._graph)
        return json.dumps(data, indent=2, default=str)

    def to_json_serializable(self) -> dict:
        data = nx.node_link_data(self._graph)
        return json.loads(json.dumps(data, default=str))

    @classmethod
    def from_json(cls, json_str: str) -> "DigitalTwinGraph":
        data = json.loads(json_str)
        dt = cls()
        dt._graph = nx.node_link_graph(data, directed=True, multigraph=False)
        return dt

    def __repr__(self):
        s = self.summary()
        return f"<DigitalTwinGraph: {s['total_nodes']} nodes, {s['total_edges']} edges>"
