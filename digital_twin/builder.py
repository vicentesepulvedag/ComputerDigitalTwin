from digital_twin.graph_model import DigitalTwinGraph


def build_initial_graph(os_configs: dict, os_name: str | None = None) -> DigitalTwinGraph:
    dt = DigitalTwinGraph()

    net_id = "net_0"
    dt.add_network(net_id, "192.168.100.0/24")

    atacante_id = "attack_origin"
    dt.add_node(atacante_id, "attack_origin", name="Atacante (Kali)")

    items = [(os_name, os_configs[os_name])] if os_name else os_configs.items()
    for os_name, cfg in items:
        vm_id = _vm_id(os_name)
        dt.add_vm(vm_id, cfg["VM_NAME"], cfg["TARGET_IP"], os_name)
        dt.link_vm_network(vm_id, net_id)

        svc_id = f"{vm_id}/smb"
        dt.add_service(svc_id, "SMB", 445)
        dt.link_vm_service(vm_id, svc_id)

        svc_id2 = f"{vm_id}/netbios"
        dt.add_service(svc_id2, "NetBIOS", 139)
        dt.link_vm_service(vm_id, svc_id2)

        if cfg.get("SMB_USER"):
            user_id = f"{vm_id}/{cfg['SMB_USER']}"
            dt.add_user(user_id, cfg["SMB_USER"])
            dt.link_vm_user(vm_id, user_id)

        paths = cfg.get("USER_PATH", "")
        if "{user}" in paths:
            for display_user in ("Administrator", "User"):
                file_id = f"{vm_id}/desktop_{display_user}"
                dt.add_file(
                    file_id,
                    f"C:\\{paths.replace('{user}', display_user)}\\Desktop",
                )

    return dt


def _vm_id(os_name: str) -> str:
    return os_name.lower().replace(" ", "_")
