from digital_twin.graph_model import DigitalTwinGraph
from digital_twin.builder import build_initial_graph

_twin: DigitalTwinGraph | None = None


def get_twin() -> DigitalTwinGraph:
    global _twin
    if _twin is None:
        _twin = DigitalTwinGraph()
    return _twin


def init_twin(os_configs: dict, os_name: str | None = None) -> DigitalTwinGraph:
    global _twin
    _twin = build_initial_graph(os_configs, os_name)
    return _twin


def reset_twin():
    global _twin
    _twin = None


__all__ = ["DigitalTwinGraph", "build_initial_graph", "get_twin", "init_twin", "reset_twin"]
