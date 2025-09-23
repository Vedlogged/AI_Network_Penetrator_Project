import os
import joblib
import pandas as pd
import warnings

warnings.filterwarnings("ignore", category=UserWarning, module='sklearn')

# --- 1. LOAD YOUR MODEL ---
MODEL_DIR = os.path.dirname(__file__)
MODEL_PATH = os.path.join(MODEL_DIR, "model", "threat_detector_unified_model.joblib")

try:
    with open(MODEL_PATH, 'rb') as f:
        model = joblib.load(f)
    print("[AI Module] Custom model 'threat_detector_unified_model.joblib' loaded successfully.")
except FileNotFoundError:
    print(f"[AI Module] CRITICAL ERROR: Model file not found at {MODEL_PATH}")
    model = None

# --- NEW: ENHANCED VULNERABILITY DATABASE ---
PORT_VULNERABILITIES = {
    21: {
        "threat": "Unencrypted FTP (Port 21)",
        "description": "The File Transfer Protocol (FTP) transmits data, including usernames and passwords, in plaintext. This makes it highly susceptible to eavesdropping and credential theft.",
        "exploitation_scenario": "An attacker on the same network (e.g., public Wi-Fi) can use a packet sniffer like Wireshark to intercept login credentials as they are transmitted, gaining full access to the FTP server.",
        "mitigation_steps": [
            "**Disable FTP:** If not essential, disable the FTP service entirely.",
            "**Use Encrypted Alternatives:** Replace FTP with SFTP (SSH File Transfer Protocol on port 22) or FTPS (FTP over SSL/TLS).",
            "**Enforce Strong Credentials:** If FTP must be used, enforce complex passwords and disable anonymous access."
        ]
    },
    22: {
        "threat": "Exposed SSH (Port 22)",
        "description": "Secure Shell (SSH) is a secure protocol, but if exposed to the internet, it is a primary target for automated brute-force attacks where attackers try thousands of common passwords.",
        "exploitation_scenario": "Automated bots constantly scan the internet for open SSH ports. If they guess a weak password (like 'admin', 'password123'), they gain full command-line access to the server.",
        "mitigation_steps": [
            "**Use Key-Based Authentication:** Disable password-based authentication and use SSH keys, which are far more secure.",
            "**Use a Firewall:** Restrict access to Port 22 to only trusted IP addresses.",
            "**Install Fail2Ban:** This tool automatically blocks IPs that fail to log in multiple times."
        ]
    },
    80: {
        "threat": "Unencrypted HTTP (Port 80)",
        "description": "The Hypertext Transfer Protocol (HTTP) does not encrypt web traffic. Attackers can intercept sensitive information submitted by users, such as login credentials or personal data.",
        "exploitation_scenario": "An attacker on a public Wi-Fi network can perform a 'Man-in-the-Middle' attack, intercepting the connection between a user and your website to steal session cookies or login details.",
        "mitigation_steps": [
            "**Implement TLS/SSL:** Obtain and install a TLS/SSL certificate on your web server.",
            "**Enforce HTTPS:** Configure your web server to automatically redirect all HTTP traffic to HTTPS (port 443).",
            "**Enable HSTS:** Implement the HSTS (HTTP Strict Transport Security) header to ensure browsers only connect to your site via HTTPS."
        ]
    },
    3389: {
        "threat": "Exposed RDP (Port 3389)",
        "description": "The Remote Desktop Protocol (RDP) is a frequent target for brute-force attacks and has been an entry point for numerous ransomware campaigns.",
        "exploitation_scenario": "Attackers buy lists of credentials from data breaches and use automated tools to try them against any open RDP ports they find, hoping for a match to gain full graphical control of the machine.",
        "mitigation_steps": [
            "**Restrict Access:** Never expose RDP directly to the internet. Require users to connect via a secure VPN first.",
            "**Enable Network Level Authentication (NLA):** This requires authentication before a full RDP session is established, mitigating some attacks.",
            "**Use Strong Passwords & Account Lockout:** Enforce complex passwords and configure an account lockout policy to thwart brute-force attempts."
        ]
    }
}

# --- 2. FEATURE EXTRACTION LOGIC ---
def extract_features(scan_data):
    common_features = ['dst_port', 'protocol', 'duration', 'total_fwd_packets', 'total_bwd_packets', 'total_len_fwd_packets', 'total_len_bwd_packets']
    feature_dict = {feature: 0 for feature in common_features}
    if not scan_data or not scan_data.get("scan_details"): return None
    try:
        host_ip = next(iter(scan_data["scan_details"]))
        details = scan_data["scan_details"][host_ip]
        ports = details.get("ports", {})
        if ports:
            first_port = next(iter(ports))
            feature_dict['dst_port'] = int(first_port)
            protocol_name = ports[first_port].get('name', 'tcp').lower()
            proto_map = {'tcp': 6, 'udp': 17, 'icmp': 1}
            feature_dict['protocol'] = proto_map.get(protocol_name, 6)
        return pd.DataFrame([feature_dict], columns=common_features)
    except Exception as e:
        print(f"[AI Module] Error during feature extraction: {e}")
        return None

# --- 3. MAIN ANALYSIS FUNCTION (ENHANCED) ---
def analyze_vulnerabilities(scan_data):
    if model is None:
        return {"risk_level": "Error", "findings": [{"threat": "AI Model Not Loaded", "description": "The custom AI model file could not be loaded.", "exploitation_scenario": "N/A", "mitigation_steps": ["Ensure the .joblib file is in the core/model directory."]}]}

    analysis_result = {"risk_level": "Unknown", "findings": []}
    try:
        features = extract_features(scan_data)
        if features is not None:
            prediction = model.predict(features)[0]
            risk_map = {0: "Normal", 1: "Potential Threat", 2: "High Risk"}
            analysis_result["risk_level"] = risk_map.get(prediction, "Unknown")
        
        scan_details = scan_data.get("scan_details", {})
        if scan_details:
            host_ip = next(iter(scan_details))
            ports = scan_details[host_ip].get("ports", {})
            for port_num_str in ports:
                port_num = int(port_num_str)
                if ports[port_num_str].get('state') == 'open' and port_num in PORT_VULNERABILITIES:
                    analysis_result["findings"].append(PORT_VULNERABILITIES[port_num])
        
        if not analysis_result["findings"]:
             analysis_result["findings"].append({
                 "threat": "No Common Vulnerabilities Found",
                 "description": "The scan did not find any of the common high-risk ports that are pre-configured in the tool's database. The AI model has assessed the overall risk based on its training.",
                 "exploitation_scenario": "N/A",
                 "mitigation_steps": ["This is a good sign, but always practice defense-in-depth. Ensure all running services are necessary and fully patched."]
             })
        
        return analysis_result
    except Exception as e:
        print(f"[AI Module] An error during analysis: {e}")
        return {"risk_level": "Error", "findings": [{"threat": "Analysis Error", "description": "An unexpected error occurred while analyzing the scan data.", "exploitation_scenario": "N/A", "mitigation_steps": ["Check the Flask server logs for a detailed error traceback."]}]}