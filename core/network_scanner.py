# core/network_scanner.py
import socket
import json
import os
from datetime import datetime

# Define the path to the JSON file where scan results will be stored
# os.path.dirname(os.path.abspath(__file__)) gets the directory of the current script (network_scanner.py)
# then we go up one level (..) to the 'ai_network_penetrator' directory, and then into 'data'
SCAN_RESULTS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), '../data/scan_results.json')

def check_port(ip_address, port, timeout=1):
    """
    Checks if a specific port on an IP address is open.
    Returns True if open, False if closed or unreachable.
    """
    try:
        # Create a socket object:
        # socket.AF_INET for IPv4 addresses
        # socket.SOCK_STREAM for TCP connections
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Set a timeout for the connection attempt.
        # This prevents the scanner from hanging if a port is filtered or slow to respond.
        s.settimeout(timeout)

        # Attempt to connect to the target IP and port.
        # connect_ex() returns 0 if the connection is successful (port is open).
        # It returns an error indicator (non-zero) if the connection fails (port is closed/filtered).
        result = s.connect_ex((ip_address, port))

        return result == 0 # Returns True if 0 (open), False otherwise

    except (socket.gaierror, socket.error) as e:
        # Catch errors like 'hostname not found' (gaierror) or general socket errors
        print(f"[Scanner Error] Could not connect to {ip_address}:{port} - {e}")
        return False
    finally:
        # Ensure the socket is always closed, regardless of success or failure
        s.close()

def run_port_scan(target_ip, ports_to_scan):
    """
    Runs a port scan on the target IP for the given list of ports.
    Stores the results in the 'scan_results.json' file.
    """
    # Generate a unique ID for this scan based on the current timestamp
    scan_id = datetime.now().strftime("%Y%m%d%H%M%S")
    
    # Initialize a dictionary to store results for this specific scan
    scan_results = {
        "scan_id": scan_id,
        "target_ip": target_ip,
        "timestamp": datetime.now().isoformat(), # ISO format for easy reading and sorting
        "open_ports": [],
        "closed_ports": [] # We track closed ports to show scan completeness, though not strictly necessary for UI
    }

    print(f"[Scanner] Starting scan for {target_ip} on ports {ports_to_scan}")

    for port in ports_to_scan:
        if check_port(target_ip, port):
            scan_results["open_ports"].append(port)
            print(f"[Scanner] Port {port} OPEN")
        else:
            scan_results["closed_ports"].append(port)
            # print(f"[Scanner] Port {port} CLOSED/FILTERED") # Uncomment for more verbose output during scan

    # Load existing scan results from the JSON file
    all_scans = []
    if os.path.exists(SCAN_RESULTS_FILE):
        try:
            with open(SCAN_RESULTS_FILE, 'r') as f:
                # Load existing data. If file is empty or malformed, it will be handled.
                existing_data = f.read()
                if existing_data:
                    all_scans = json.loads(existing_data)
                else:
                    all_scans = [] # File exists but is empty
        except json.JSONDecodeError:
            print("[Scanner] Warning: Existing scan_results.json is corrupt or empty. Starting fresh.")
            all_scans = [] # Reset if file is not valid JSON

    # Add the current scan's results to the list of all scans
    all_scans.append(scan_results)

    # Save the updated list of all scans back to the JSON file
    with open(SCAN_RESULTS_FILE, 'w') as f:
        json.dump(all_scans, f, indent=4) # Use indent for pretty-printing JSON

    print(f"[Scanner] Scan completed for {target_ip}. Results saved to {SCAN_RESULTS_FILE}")
    return scan_results

# This block allows you to test the scanner directly by running this file
if __name__ == "__main__":
    print("Running network_scanner.py directly for testing...")
    # Test on your local machine (localhost)
    # IMPORTANT: Only scan IPs you have explicit permission to scan.
    # scanme.nmap.org is a server provided by Nmap for legal testing.
    # test_ip = "scanme.nmap.org"
    test_ip = "127.0.0.1" # Default to localhost for safest initial testing
    test_ports = [22, 80, 443, 8080, 21, 23, 53] # Common ports

    print(f"Testing scan on {test_ip} for ports {test_ports}")
    results = run_port_scan(test_ip, test_ports)
    print("\n--- Test Scan Results ---")
    print(f"Open Ports: {results['open_ports']}")
    print(f"Closed Ports Count: {len(results['closed_ports'])}")

    print("\n--- Content of scan_results.json after test ---")
    if os.path.exists(SCAN_RESULTS_FILE):
        with open(SCAN_RESULTS_FILE, 'r') as f:
            print(f.read())