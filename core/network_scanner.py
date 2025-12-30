import subprocess
import uuid
from datetime import datetime
import xml.etree.ElementTree as ET


def run_nmap_scan(target_ip, ports_to_scan):
    """
    Executes Nmap scan using subprocess for maximum compatibility on Windows.
    Returns structured scan data or None if scan fails.
    """

    try:
        scan_id = str(uuid.uuid4())
        port_str = ",".join(map(str, ports_to_scan))

        # Nmap Command
        command = [
            "nmap",
            "-sV",         # Service and version detection
            "-T4",         # Faster execution
            "-Pn",         # Skip host discovery (important for firewalled hosts)
            "-oX", "-",    # Output as XML to stdout
            "-p", port_str,
            target_ip
        ]

        print(f"[Scanner] Running command: {' '.join(command)}")
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=120)

        if result.returncode != 0 or not result.stdout:
            print(f"[Scanner Error] {result.stderr}")
            return None

        # Parse XML output
        try:
            root = ET.fromstring(result.stdout)
            scan_details = parse_nmap_xml(root, target_ip)
        except ET.ParseError as e:
            print(f"[Scanner] XML Parse Error: {e}")
            return None

        # Return formatted scan results
        return {
            "scan_id": scan_id,
            "target": target_ip,
            "timestamp": datetime.utcnow(),
            "scan_details": scan_details
        }

    except subprocess.TimeoutExpired:
        print("[Scanner] Scan timeout")
        return None
    except Exception as e:
        print(f"[Scanner] Unexpected error: {e}")
        return None


def parse_nmap_xml(root, target_ip):
    """
    Parses Nmap XML output into a structured dictionary matching the expected format.
    Returns: {target_ip: {ports: {port_num: {name, version, state}}, hostname, os_details}}
    """
    scan_details = {}
    
    # Extract host information
    for host in root.findall('host'):
        host_data = {
            "ports": {},
            "hostname": "N/A",
            "os_details": "N/A"
        }

        # Extract hostname
        for address in host.findall('hostnames/hostname'):
            host_data["hostname"] = address.get('name', 'N/A')
            break

        # Extract OS information
        for osmatch in host.findall('os/osmatch'):
            host_data["os_details"] = osmatch.get('name', 'N/A')
            break

        # Extract port information
        for port in host.findall('ports/port'):
            port_num = port.get('portid', 'unknown')
            port_state = port.find('state')
            service = port.find('service')

            port_data = {
                "state": port_state.get('state', 'unknown') if port_state is not None else 'unknown',
                "name": service.get('name', 'unknown') if service is not None else 'unknown',
                "version": service.get('product', '') if service is not None else ''
            }

            if service is not None and service.get('extrainfo'):
                port_data['extrainfo'] = service.get('extrainfo')

            host_data["ports"][port_num] = port_data

        # Use the target IP as the key (or the actual host address if available)
        address_elem = host.find('address')
        host_ip = address_elem.get('addr') if address_elem is not None else target_ip
        
        scan_details[host_ip] = host_data

    # If no hosts were found, create an empty entry
    if not scan_details:
        scan_details[target_ip] = {
            "ports": {},
            "hostname": "N/A",
            "os_details": "N/A"
        }

    return scan_details


if __name__ == "__main__":
    # Local test run
    test_ip = "scanme.nmap.org"
    test_ports = [22, 80, 443, 9929, 31337]
    print("Testing local Nmap scan...")
    response = run_nmap_scan(test_ip, test_ports)
    if response:
        print("SUCCESS")
        print(response)
    else:
        print("FAILED")