import platform
import subprocess


def apply_rule(rule: dict, add: bool = True) -> None:
    """
    Cross-platform OS firewall execution.
    Silently fails if the process lacks required privileges (e.g. root/Admin).
    """
    system = platform.system()
    if system == "Linux":
        _apply_linux(rule, add)
    elif system == "Windows":
        _apply_windows(rule, add)
    # macOS pfctl is omitted as dynamically altering pf state is complex and error-prone


def _apply_linux(rule: dict, add: bool) -> None:
    target = "DROP" if rule["action"] == "DROP" else "ACCEPT"
    flag   = "-A" if add else "-D"
    cmd    = ["sudo", "iptables", flag, "INPUT"]
    
    if rule.get("ip"):
        cmd += ["-s", rule["ip"]]
    if rule.get("port") and rule.get("proto"):
        cmd += ["-p", rule["proto"].lower(), "--dport", str(rule["port"])]
        
    cmd += ["-j", target]
    
    try:
        res = subprocess.run(cmd, check=False, timeout=5, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if res.returncode == 0:
            # Persist rules across reboots
            save_cmd = ["sudo", "sh", "-c", "mkdir -p /etc/iptables && iptables-save > /etc/iptables/rules.v4"]
            subprocess.run(save_cmd, check=False, timeout=5, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass


def _apply_windows(rule: dict, add: bool) -> None:
    name = f"BlackWall_Rule_{rule['id']}"
    
    if add:
        action = "block" if rule["action"] == "DROP" else "allow"
        cmd = [
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={name}", "dir=in", f"action={action}"
        ]
        
        if rule.get("ip"):
            cmd.append(f"remoteip={rule['ip']}")
            
        if rule.get("port"):
            # netsh requires protocol to be specified if localport is used
            proto = rule.get("proto") or "TCP"
            cmd.append(f"protocol={proto}")
            cmd.append(f"localport={rule['port']}")
        elif rule.get("proto"):
            cmd.append(f"protocol={rule['proto']}")
            
    else:
        cmd = ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={name}"]
        
    try:
        # Requires Admin privileges to succeed, otherwise silently fails (which is handled gracefully)
        subprocess.run(cmd, check=False, timeout=5, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
