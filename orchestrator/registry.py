from typing import Callable, Optional

CommandFn = Callable[..., None]

_registry: dict[str, CommandFn] = {}
_metadata: dict[str, str] = {}


def register(key: str, fn: CommandFn, desc: str = "") -> None:
    _registry[key] = fn
    _metadata[key] = desc


def get(key: str) -> Optional[CommandFn]:
    return _registry.get(key)


def all_commands() -> dict[str, CommandFn]:
    return dict(_registry)


def description(key: str) -> str:
    return _metadata.get(key, "")
