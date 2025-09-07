import nmap
import socket
import json
import os
from datetime import datetime

SCAN_RESULTS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), '../data/scan_results.json')

def run_nmap_scan(target_ip, ports_to_scan):
    scan_id = datetime.now().strftime("%Y%m%d%H%M%S")
    nmap_scanner = nmap.PortScanner()

    ports_str = ','.join(map(str, ports_to_scan))

    print(f"[Nmap Scanner] Starting detailed scan on {target_ip} for ports {ports_str}...")

    nmap_scanner.scan(target_ip, ports=ports_str, arguments='-sV -O -T4')

    scan_results = {
        "scan_id": scan_id,
        "target_ip": target_ip,
        "ports_to_scan": ports_to_scan, # Save the ports that were scanned
        "timestamp": datetime.now().isoformat(),
        "scan_details": {}
    }

    if target_ip in nmap_scanner.all_hosts():
        host = target_ip
        scan_results["scan_details"][host] = {
            "hostname": nmap_scanner[host]['hostnames'][0]['name'] if 'hostnames' in nmap_scanner[host] and nmap_scanner[host]['hostnames'] else "N/A",
            "os_details": nmap_scanner[host]['osmatch'][0]['name'] if 'osmatch' in nmap_scanner[host] and nmap_scanner[host]['osmatch'] else "N/A",
            "ports": {}
        }
        if 'tcp' in nmap_scanner[host]:
            for port in nmap_scanner[host]['tcp']:
                port_info = nmap_scanner[host]['tcp'][port]
                scan_results["scan_details"][host]["ports"][port] = {
                    "state": port_info['state'],
                    "name": port_info['name'],
                    "product": port_info['product'],
                    "version": port_info['version']
                }

    all_scans = []
    if os.path.exists(SCAN_RESULTS_FILE) and os.path.getsize(SCAN_RESULTS_FILE) > 0:
        try:
            with open(SCAN_RESULTS_FILE, 'r') as f:
                all_scans = json.load(f)
        except json.JSONDecodeError:
            print("[Nmap Scanner] Warning: Existing scan_results.json is corrupt. Starting fresh.")

    all_scans.append(scan_results)

    with open(SCAN_RESULTS_FILE, 'w') as f:
        json.dump(all_scans, f, indent=4)

    print(f"[Nmap Scanner] Scan completed. Detailed results saved to {SCAN_RESULTS_FILE}")
    return scan_results

# This block is for direct testing
if __name__ == "__main__":
    print("Running network_scanner.py directly for testing...")
    test_ip = "127.0.0.1" 
    test_ports = [22, 80, 443, 8080, 21, 23, 53] 

    print(f"Testing Nmap scan on {test_ip} for ports {test_ports}")
    results = run_nmap_scan(test_ip, test_ports)
    print("\n--- Test Nmap Scan Results ---")
    if results['scan_details']:
        first_host_ip = next(iter(results['scan_details']))
        first_host_details = results['scan_details'][first_host_ip]
        print(f"Target IP: {first_host_ip}")
        print(f"Hostname: {first_host_details['hostname']}")
        print(f"OS Match: {first_host_details['os_details']}")
        print("Open Ports:")
        if first_host_details['ports']:
            for port, info in first_host_details['ports'].items():
                print(f"  - Port {port}: State={info['state']}, Service={info['name']}, Version={info['version']}")
        else:
            print("  None")
    else:
        print("No scan details found.")
    
    print("\n--- Content of scan_results.json after test ---")
    if os.path.exists(SCAN_RESULTS_FILE):
        with open(SCAN_RESULTS_FILE, 'r') as f:
            print(f.read())
