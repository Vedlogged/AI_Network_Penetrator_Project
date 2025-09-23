import nmap
import socket
import json
import os
from datetime import datetime

SCAN_RESULTS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), '../data/scan_results.json')

def run_nmap_scan(target_ip, ports_to_scan):
    """
    Runs a detailed Nmap scan and saves the results safely to a JSON file.
    Returns the scan results dictionary or None if a critical error occurs.
    """
    try:
        scan_id = datetime.now().strftime("%Y%m%d%H%M%S")
        nmap_scanner = nmap.PortScanner()
        ports_str = ','.join(map(str, ports_to_scan))

        print(f"[Nmap Scanner] Starting detailed scan on {target_ip} for ports {ports_str}...")
        
        # **CHANGE**: Added '-Pn' to skip host discovery (ping check). This is the main fix.
        # This forces Nmap to scan the ports even if the host appears to be offline.
        arguments = '-sV -O -T4 -Pn'
        nmap_scanner.scan(target_ip, ports=ports_str, arguments=arguments)

        scan_results = {
            "scan_id": scan_id,
            "target_ip": target_ip,
            "ports_to_scan": ports_to_scan,
            "timestamp": datetime.now().isoformat(),
            "scan_details": {}
        }

        if target_ip in nmap_scanner.all_hosts():
            host = target_ip
            scan_details_host = {}

            # Safely get hostname
            hostnames = nmap_scanner[host].get('hostnames', [])
            scan_details_host['hostname'] = hostnames[0]['name'] if hostnames else 'N/A'

            # Safely get OS details
            os_matches = nmap_scanner[host].get('osmatch', [])
            scan_details_host['os_details'] = os_matches[0]['name'] if os_matches else 'N/A'
            
            scan_details_host['ports'] = {}
            
            if 'tcp' in nmap_scanner[host]:
                for port, port_info in nmap_scanner[host]['tcp'].items():
                    scan_details_host['ports'][port] = {
                        "state": port_info.get('state', 'N/A'),
                        "name": port_info.get('name', 'N/A'),
                        "product": port_info.get('product', 'N/A'),
                        "version": port_info.get('version', 'N/A')
                    }
            
            scan_results["scan_details"][host] = scan_details_host
        else:
            print(f"[Nmap Scanner] Target host {target_ip} not found in scan results (may be down or firewalled).")

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

        print(f"[Nmap Scanner] Scan completed. Results saved to {SCAN_RESULTS_FILE}")
        return scan_results
        
    except nmap.PortScannerError:
        print("[Nmap Scanner] CRITICAL ERROR: Nmap not found. Please install it and ensure it's in your system's PATH.")
        return None
    except Exception as e:
        print(f"[Nmap Scanner] An unexpected error occurred: {e}")
        return None

# This block is for direct testing
if __name__ == "__main__":
    print("Running network_scanner.py directly for testing...")
    test_ip = "127.0.0.1" 
    test_ports = [22, 80, 443, 8080]

    results = run_nmap_scan(test_ip, test_ports)
    if results:
        print("\n--- Test Nmap Scan Results ---")
        print(json.dumps(results, indent=4))
    else:
        print("\n--- Test Nmap Scan Failed ---")