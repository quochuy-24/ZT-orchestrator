"""VyOS Firewall Service - Add/Remove ACL rules via SSH"""

import asyncio
import re
import threading
import uuid
import paramiko
import time

VYOS_HOST = "192.168.29.11"
VYOS_USER = "vyos"
VYOS_PASSWORD = "vyos"
VYOS_PORT = 22

MOCK_MODE = False

JIT_RULE_START = 20
JIT_RULE_END = 49
RESERVED_FORWARD_RULES = {1, 2, 50}
_used_rule_numbers = set()
_rule_number_lock = threading.Lock()


def _execute_vyos_commands(commands: list[str]) -> bool:
    """Execute commands on VyOS via SSH using paramiko"""
    output = _execute_vyos_commands_with_output(commands)
    if output is None:
        return False
    if "Invalid" in output or "Error" in output:
        print(f"Command execution had errors: {output}")
        return False
    return True


def _execute_vyos_commands_with_output(commands: list[str]) -> str | None:
    """Execute commands on VyOS via SSH and return shell output."""
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        client.connect(
            hostname=VYOS_HOST,
            port=VYOS_PORT,
            username=VYOS_USER,
            password=VYOS_PASSWORD,
            timeout=20,
            banner_timeout=20,
            auth_timeout=20,
        )

        shell = client.invoke_shell()
        shell.settimeout(20)
        time.sleep(0.5)

        if shell.recv_ready():
            shell.recv(4096)

        output = ""
        for cmd in commands:
            shell.send(cmd + "\n")
            time.sleep(1)
            while shell.recv_ready():
                output += shell.recv(4096).decode(errors="ignore")

        time.sleep(1)
        while shell.recv_ready():
            output += shell.recv(4096).decode(errors="ignore")

        shell.close()
        client.close()
        return output

    except Exception as e:
        print(f"SSH command execution failed: {e}")
        return None


def _get_existing_forward_rule_numbers() -> set[int]:
    if MOCK_MODE:
        return set()

    output = _execute_vyos_commands_with_output([
        'show configuration commands | match "firewall ipv4 forward filter rule"'
    ])
    if output is None:
        raise Exception("Failed to query existing VyOS forward rules")

    return {
        int(match.group(1))
        for match in re.finditer(r"firewall ipv4 forward filter rule (\d+)", output)
    }


def _allocate_rule_number() -> int:
    with _rule_number_lock:
        existing_rule_numbers = _get_existing_forward_rule_numbers()
        unavailable = RESERVED_FORWARD_RULES | _used_rule_numbers | existing_rule_numbers

        for num in range(JIT_RULE_START, JIT_RULE_END + 1):
            if num not in unavailable:
                _used_rule_numbers.add(num)
                return num
    raise Exception("No available JIT forward rule numbers")


def _free_rule_number(rule_number: int):
    with _rule_number_lock:
        _used_rule_numbers.discard(rule_number)


def _parse_rule_number(rule_id: str) -> int:
    parts = rule_id.split(":")
    if len(parts) >= 3 and parts[0] == "forward":
        return int(parts[1])
    if len(parts) == 2 and parts[0] == "forward":
        return int(parts[1].split("_")[0])
    return int(rule_id.split("_")[0])


def _validate_jit_rule_number(rule_number: int):
    if rule_number < JIT_RULE_START or rule_number > JIT_RULE_END:
        raise Exception(f"Refusing to modify non-JIT forward rule {rule_number}")
    if rule_number in RESERVED_FORWARD_RULES:
        raise Exception(f"Refusing to modify reserved forward rule {rule_number}")


def _safe_description_value(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.:-]", "_", value)


async def add_firewall_rule(source_ip: str, dest_ip: str, dest_port: int, username: str) -> str:
    """Add forward firewall rule to allow access from source_ip to dest_ip:dest_port"""

    if dest_ip == VYOS_HOST:
        raise Exception("VyOS is not a requestable JIT resource")

    rule_number = _allocate_rule_number()
    rule_id = f"forward:{rule_number}:{source_ip}:{dest_ip}:{uuid.uuid4().hex[:6]}" # Include IPs in rule_id

    safe_username = _safe_description_value(username)
    commands = [
        "configure",
        f"set firewall ipv4 forward filter rule {rule_number} action accept",
        f"set firewall ipv4 forward filter rule {rule_number} source address {source_ip}",
        f"set firewall ipv4 forward filter rule {rule_number} destination address {dest_ip}",
        f"set firewall ipv4 forward filter rule {rule_number} destination port {dest_port}",
        f"set firewall ipv4 forward filter rule {rule_number} protocol tcp",
        f"set firewall ipv4 forward filter rule {rule_number} description 'JIT-{safe_username}-{rule_id}'",
        "commit",
        "save",
        "exit"
    ]

    if MOCK_MODE:
        print(f"\n[MOCK] Adding VyOS forward firewall rule {rule_id} (rule number {rule_number}):")
        for cmd in commands:
            print(f"  {cmd}")
        return rule_id

    try:
        success = await asyncio.to_thread(_execute_vyos_commands, commands)

        if not success:
            _free_rule_number(rule_number)
            raise Exception("Failed to execute VyOS commands")

        print(f"Added VyOS forward rule {rule_id} (rule number {rule_number})")
        return rule_id

    except Exception as e:
        _free_rule_number(rule_number)
        print(f"Failed to add VyOS rule: {e}")
        raise


async def remove_firewall_rule(rule_id: str):
    """Remove forward firewall rule by rule_id"""

    rule_number = _parse_rule_number(rule_id)
    _validate_jit_rule_number(rule_number)

    # Extract IPs from rule_id to use in conntrack reset
    parts = rule_id.split(":")
    if len(parts) >= 4:
        source_ip = parts[2]
        dest_ip = parts[3]
        conntrack_cmd = f"reset conntrack source {source_ip} destination {dest_ip}"
    else:
        # Fallback if rule_id doesn't have IPs (e.g., from old database entries)
        print("Warning: Could not extract IPs from rule_id. Conntrack reset will not be performed.")
        conntrack_cmd = None

    commands = [
        "configure",
        f"delete firewall ipv4 forward filter rule {rule_number}",
        "commit",
        "save",
        "exit"
    ]
    
    if conntrack_cmd:
        commands.append(conntrack_cmd) # Add conntrack command AFTER exit

    if MOCK_MODE:
        print(f"\n[MOCK] Removing VyOS forward firewall rule {rule_id} (rule number {rule_number}):")
        for cmd in commands:
            print(f"  {cmd}")
        _free_rule_number(rule_number)
        return

    try:
        success = await asyncio.to_thread(_execute_vyos_commands, commands)

        if not success:
            print(f"Warning: Failed to remove VyOS rule {rule_id}, but freeing rule number anyway")

        _free_rule_number(rule_number)
        print(f"Removed VyOS forward rule {rule_id} (rule number {rule_number})")

    except Exception as e:
        print(f"Failed to remove VyOS rule: {e}")
        _free_rule_number(rule_number)
