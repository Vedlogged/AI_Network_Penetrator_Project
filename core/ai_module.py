# core/ai_module.py
import json
import os

SCAN_RESULTS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), '../data/scan_results.json')

def analyze_vulnerabilities(scan_data):
    """
    Placeholder for AI-based threat analysis.
    For now, it simply identifies commonly vulnerable open ports.
    """
    vulnerabilities = []
    recommendations = []

    common_vulnerable_ports = {
        21: "FTP (File Transfer Protocol) - often allows anonymous access or weak credentials.",
        23: "Telnet - transmits data in plain text, highly insecure.",
        80: "HTTP (Hypertext Transfer Protocol) - often needs HTTPS redirection, sensitive info disclosure.",
        445: "SMB (Server Message Block) - known for WannaCry/EternalBlue vulnerabilities.",
        3389: "RDP (Remote Desktop Protocol) - susceptible to brute-force attacks.",
        22: "SSH (Secure Shell) - often targeted by brute-force, ensure strong credentials and key-based auth."
    }

    if not scan_data or "open_ports" not in scan_data:
        return {"vulnerabilities": [], "recommendations": []}

    print(f"[AI Module] Analyzing scan results for {scan_data['target_ip']}...")

    for port in scan_data.get("open_ports", []):
        if port in common_vulnerable_ports:
            vulnerability_desc = common_vulnerable_ports[port]
            vulnerabilities.append(f"Port {port} is OPEN: {vulnerability_desc}")
            recommendations.append(f"Secure Port {port}: Review access controls, disable unnecessary services, use stronger encryption (e.g., SSH over Telnet, HTTPS over HTTP).")

    # In a real AI, this is where a trained model would classify traffic or identify anomalies.
    # For example:
    # ml_model = load_trained_model("path/to/your/model.pkl")
    # features = extract_features_from_network_traffic(live_traffic_data)
    # prediction = ml_model.predict(features)
    # if prediction == "malicious":
    #     vulnerabilities.append("AI detected anomalous traffic pattern (e.g., brute-force attempt).")


    print(f"[AI Module] Analysis complete. Found {len(vulnerabilities)} potential vulnerabilities.")
    return {
        "vulnerabilities": vulnerabilities,
        "recommendations": recommendations,
        "ai_status": "Basic rule-based analysis (AI placeholder)"
    }

def get_latest_analysis():
    """
    Reads the latest scan results and performs a basic analysis.
    """
    if os.path.exists(SCAN_RESULTS_FILE):
        try:
            with open(SCAN_RESULTS_FILE, 'r') as f:
                all_scans = json.load(f)
                if all_scans:
                    latest_scan = all_scans[-1] # Get the most recent scan
                    return analyze_vulnerabilities(latest_scan)
        except json.JSONDecodeError:
            print("[AI Module] Error: Could not decode scan results JSON.")
    return {"vulnerabilities": ["No scan data available for analysis."], "recommendations": []}


if __name__ == "__main__":
    # Example usage for direct testing
    # First, ensure network_scanner.py has run at least once to create scan_results.json
    print("Attempting to analyze latest scan results...")
    analysis = get_latest_analysis()
    print("\n--- AI Analysis Summary ---")
    if analysis.get("vulnerabilities"):
        for vuln in analysis["vulnerabilities"]:
            print(f"Vulnerability: {vuln}")
    if analysis.get("recommendations"):
        for rec in analysis["recommendations"]:
            print(f"Recommendation: {rec}")
    print(f"AI Status: {analysis.get('ai_status', 'N/A')}")