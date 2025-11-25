#!/usr/bin/env python3

from proxmoxer import ProxmoxAPI
import paramiko
import socket
import os

PROXMOX_HOST = "10.0.10.11"
PROXMOX_USER = "root@pam"        # adjust if you use different user/realm
PROXMOX_PASSWORD = os.getenv('PROXMOX_PASSWORD') 

# SSH credentials to test on the VMs
VM_SSH_USER = "student"
VM_SSH_PASSWORD = os.getenv('VM_SSH_PASSWORD')

# Output inventory file
OUTPUT_INVENTORY = "inventory.ini"


def get_vm_ips_from_guest_agent(proxmox, node, vmid):
    """
    Use QEMU guest agent to get IP addresses for a VM.
    Returns a list of IPv4 addresses (no 127.0.0.1).
    """
    ips = []
    try:
        result = proxmox.nodes(node).qemu(vmid).agent("network-get-interfaces").get()
        for iface in result.get("result", []):
            for addr in iface.get("ip-addresses", []):
                ip = addr.get("ip-address")
                if addr.get("ip-address-type") == "ipv4" and not ip.startswith("127."):
                    ips.append(ip)
    except Exception as e:
        print(f"[WARN] Could not get IPs for VMID {vmid} on node {node}: {e}")
    return ips


def test_ssh(ip, username, password, timeout=3):
    """
    Try to SSH to ip with username/password.
    Return True if connection & auth succeed, False otherwise.
    """
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            ip,
            port=22,
            username=username,
            password=password,
            timeout=timeout,
            look_for_keys=False,
            allow_agent=False,
        )
        client.close()
        return True
    except (socket.error, paramiko.SSHException) as e:
        print(f"[INFO] SSH to {ip} failed: {e}")
        return False


def main():
    # Connect to Proxmox
    proxmox = ProxmoxAPI(
        PROXMOX_HOST,
        user=PROXMOX_USER,
        password=PROXMOX_PASSWORD,
        verify_ssl=False,
    )

    discovered_hosts = []

    # Iterate over all nodes and VMs
    for node in proxmox.nodes.get():
        node_name = node["node"]
        print(f"[INFO] Checking node: {node_name}")
        for vm in proxmox.nodes(node_name).qemu.get():
            vmid = vm["vmid"]
            name = vm.get("name", str(vmid))

            # Skip templates and stopped VMs
            if vm.get("template", 0) == 1:
                continue
            if vm.get("status") != "running":
                continue

            print(f"[INFO] VMID {vmid} ({name}) is running, trying to get IPs...")
            ips = get_vm_ips_from_guest_agent(proxmox, node_name, vmid)

            if not ips:
                print(f"[WARN] No IPs found for {name} ({vmid})")
                continue

            for ip in ips:
                print(f"[INFO] Trying SSH to {name} ({vmid}) at {ip}...")
                if test_ssh(ip, VM_SSH_USER, VM_SSH_PASSWORD):
                    print(f"[OK] {name} ({vmid}) at {ip} is reachable with given credentials")
                    discovered_hosts.append(ip)
                    # If one IP works, we don't need to try others for this VM
                    break

    # Write inventory.ini
    if not discovered_hosts:
        print("[WARN] No hosts discovered with the provided credentials.")
        return

    print(f"[INFO] Writing inventory to {OUTPUT_INVENTORY}")
    with open(OUTPUT_INVENTORY, "w") as f:
        f.write("[linux_servers]\n")
        for ip in discovered_hosts:
            f.write(f"{ip}\n")
        f.write("\n[linux_servers:vars]\n")
        f.write(f"ansible_user={VM_SSH_USER}\n")
        f.write(f"ansible_password={VM_SSH_PASSWORD}\n")
        f.write("ansible_become=yes\n")
        f.write("ansible_become_method=sudo\n")
        f.write("ansible_ssh_common_args='-o StrictHostKeyChecking=no'\n")

    print("[INFO] Inventory generation complete.")


if __name__ == "__main__":
    main()
