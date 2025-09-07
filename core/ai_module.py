import json
import os

# Define the path to the JSON file where scan results are stored
SCAN_RESULTS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), '../data/scan_results.json')

def analyze_vulnerabilities(scan_data):
    """
    Placeholder for AI-based threat analysis.
    For this prototype, it simply identifies commonly vulnerable open ports
    and provides a rule-based analysis.
    """
    vulnerabilities = []
    recommendations = []

    # A dictionary mapping common port numbers to a brief description of potential vulnerabilities.
    # In a real AI system, this would be replaced by complex models trained on vast datasets.
    common_vulnerable_ports = {
        21: "FTP (File Transfer Protocol) - often allows anonymous access or weak credentials, data can be unencrypted.",
        23: "Telnet - transmits data in plain text, highly insecure; replace with SSH.",
        80: "HTTP (Hypertext Transfer Protocol) - unencrypted web traffic; sensitive info can be intercepted. Redirect to HTTPS.",
        445: "SMB (Server Message Block) - known for WannaCry/EternalBlue vulnerabilities; ensure patches are applied and restrict access.",
        3389: "RDP (Remote Desktop Protocol) - susceptible to brute-force attacks; use strong passwords, limit access, apply NLA.",
        22: "SSH (Secure Shell) - often targeted by brute-force; ensure strong passwords, use key-based authentication, limit root access.",
        53: "DNS (Domain Name System) - can be vulnerable to amplification attacks or cache poisoning if not properly secured."
    }

    if not scan_data or "scan_details" not in scan_data:
        return {"vulnerabilities": ["No valid scan data provided for analysis."], "recommendations": []}

    print(f"[AI Module] Analyzing scan results for {scan_data.get('target_ip', 'unknown IP')}...")

    # Iterate through the open ports identified by the scanner
    for host in scan_data["scan_details"]:
        for port in scan_data["scan_details"][host]["ports"]:
            port_info = scan_data["scan_details"][host]["ports"][port]
            if port_info["state"] == "open" and int(port) in common_vulnerable_ports:
                vulnerability_desc = common_vulnerable_ports[int(port)]
                vulnerabilities.append(f"Port {port} is OPEN: {vulnerability_desc}")
                recommendations.append(f"Secure Port {port}: Review access controls, disable unnecessary services, use stronger, encrypted alternatives (e.g., SSH over Telnet, HTTPS over HTTP).")

    print(f"[AI Module] Analysis complete. Found {len(vulnerabilities)} potential vulnerabilities based on open ports.")
    return {
        "vulnerabilities": vulnerabilities,
        "recommendations": recommendations,
        "ai_status": "Basic rule-based analysis (AI placeholder)"
    }

def get_latest_analysis():
    """
    Reads the latest scan results from the JSON file and performs a basic analysis.
    """
    if os.path.exists(SCAN_RESULTS_FILE) and os.path.getsize(SCAN_RESULTS_FILE) > 0:
        try:
            with open(SCAN_RESULTS_FILE, 'r') as f:
                all_scans = json.load(f)
                if all_scans:
                    latest_scan = all_scans[-1]
                    return analyze_vulnerabilities(latest_scan)
        except json.JSONDecodeError:
            print("[AI Module] Error: Could not decode scan results JSON. File might be empty or corrupt.")
            return {"vulnerabilities": ["Error loading scan data for analysis."], "recommendations": []}
    return {"vulnerabilities": ["No scan results file found."], "recommendations": []}

# This block allows for direct testing
if __name__ == "__main__":
    print("Running ai_module.py directly for testing...")
    
    analysis_results = get_latest_analysis()
    
    print("\n--- AI Analysis Summary ---")
    if analysis_results.get("vulnerabilities"):
        for vuln in analysis_results["vulnerabilities"]:
            print(f"Vulnerability: {vuln}")
    if analysis_results.get("recommendations"):
        for rec in analysis_results["recommendations"]:
            print(f"Recommendation: {rec}")
    print(f"AI Status: {analysis_results.get('ai_status', 'N/A')}")
