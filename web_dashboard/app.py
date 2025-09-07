from flask import Flask, render_template, request, jsonify, send_file, session, redirect, url_for, flash
import sys
import os
import json
import io
import csv
from datetime import datetime
import nmap

# Add the parent directory to the system path to import core modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.network_scanner import run_nmap_scan, SCAN_RESULTS_FILE
from core.ai_module import get_latest_analysis, analyze_vulnerabilities

app = Flask(__name__,
            template_folder='templates',
            static_folder='static')
app.secret_key = 'your_secret_key_here' # IMPORTANT: Change this to a strong, random key

# Ensure the directory for scan results exists
os.makedirs(os.path.dirname(SCAN_RESULTS_FILE), exist_ok=True)

## ----------------- CORE WEB PAGES ----------------- ##

@app.route('/')
def landing():
    """
    Renders the landing page.
    """
    return render_template('landing.html')

@app.route('/dashboard')
def dashboard():
    """
    Renders the main dashboard page after a successful login.
    """
    if not session.get('logged_in'):
        flash('You need to be logged in to view this page.', 'warning')
        return redirect(url_for('landing'))

    latest_scan = None
    all_scans = []

    if os.path.exists(SCAN_RESULTS_FILE) and os.path.getsize(SCAN_RESULTS_FILE) > 0:
        try:
            with open(SCAN_RESULTS_FILE, 'r') as f:
                all_scans = json.load(f)
                if all_scans:
                    latest_scan = all_scans[-1]
        except json.JSONDecodeError:
            print("[Web] Warning: scan_results.json is empty or corrupt.")
            all_scans = []

    analysis = analyze_vulnerabilities(latest_scan) if latest_scan else get_latest_analysis()

    return render_template('dashboard.html',
                           latest_scan=latest_scan,
                           all_scans=reversed(all_scans),
                           analysis=analysis)

## ----------------- AUTHENTICATION ----------------- ##

@app.route('/login', methods=['POST'])
def handle_login():
    """
    Handles the login form submission from the landing page modal.
    """
    email = request.form.get('email')
    password = request.form.get('password')
    
    # Simple email/password check for demonstration
    if email == 'admin@example.com' and password == 'password':
        session['logged_in'] = True
        session['user_email'] = email
        flash('You have successfully logged in!', 'success')
        return redirect(url_for('dashboard'))
    else:
        # If login fails, flash an error and redirect back to the landing page
        flash('Invalid email or password. Please try again.', 'danger')
        return redirect(url_for('landing'))

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    session.pop('user_email', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('landing'))

## ----------------- API & DATA ENDPOINTS ----------------- ##

@app.route('/scan', methods=['POST'])
def scan_network():
    if not session.get('logged_in'):
        return jsonify({"status": "error", "message": "Unauthorized"}), 401
    
    target_ip = request.form.get('target_ip')
    if not target_ip:
        return jsonify({"status": "error", "message": "Target IP cannot be empty!"}), 400

    # For simplicity, using default ports. A future feature could allow user input.
    ports_to_scan = [21, 22, 80, 443, 8080]

    scan_results = run_nmap_scan(target_ip, ports_to_scan)
    analysis = get_latest_analysis()

    return jsonify({
        "status": "success",
        "message": "Scan completed.",
        "scan_results": scan_results,
        "analysis": analysis
    })

@app.route('/get_latest_data', methods=['GET'])
def get_latest_data_api():
    if not session.get('logged_in'):
        return jsonify({"status": "error", "message": "Unauthorized"}), 401
    
    latest_scan = None
    all_scans = []

    if os.path.exists(SCAN_RESULTS_FILE) and os.path.getsize(SCAN_RESULTS_FILE) > 0:
        try:
            with open(SCAN_RESULTS_FILE, 'r') as f:
                all_scans = json.load(f)
                if all_scans:
                    latest_scan = all_scans[-1]
        except json.JSONDecodeError:
            print("[Web] Error: Could not decode scan_results.json for API.")
            all_scans = []

    analysis = get_latest_analysis()

    return jsonify({
        "latest_scan": latest_scan,
        "all_scans": list(reversed(all_scans)),
        "analysis": analysis
    })

@app.route('/generate_report', methods=['GET'])
def generate_report():
    if not session.get('logged_in'):
        return jsonify({"status": "error", "message": "Unauthorized"}), 401

    latest_scan = None
    if os.path.exists(SCAN_RESULTS_FILE) and os.path.getsize(SCAN_RESULTS_FILE) > 0:
        try:
            with open(SCAN_RESULTS_FILE, 'r') as f:
                all_scans = json.load(f)
                if all_scans:
                    latest_scan = all_scans[-1]
        except json.JSONDecodeError:
            pass

    analysis = get_latest_analysis()
    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow(["AI Network Penetrator Scan Report"])
    writer.writerow(["Generated On:", datetime.now().isoformat()])
    writer.writerow([])

    if latest_scan:
        writer.writerow(["--- Latest Scan Details ---"])
        writer.writerow(["Scan ID:", latest_scan.get("scan_id", "N/A")])
        writer.writerow(["Target IP:", latest_scan.get("target_ip", "N/A")])
        writer.writerow(["Timestamp:", latest_scan.get("timestamp", "N/A")])
        writer.writerow([])

        if latest_scan.get("scan_details"):
            for host_ip, details in latest_scan["scan_details"].items():
                writer.writerow(["Host:", host_ip])
                writer.writerow(["Hostname:", details.get("hostname", "N/A")])
                writer.writerow(["OS Details:", details.get("os_details", "N/A")])
                writer.writerow(["--- Open Ports ---"])
                writer.writerow(["Port", "State", "Service", "Version"])
                if details.get("ports"):
                    for port, port_info in details["ports"].items():
                        if port_info.get("state") == "open":
                            writer.writerow([
                                port,
                                port_info.get("state", "N/A"),
                                port_info.get("name", "N/A"),
                                port_info.get("version", "N/A")
                            ])
                else:
                    writer.writerow(["No open ports found."])
                writer.writerow([])
        else:
            writer.writerow(["No detailed scan information available."])
        writer.writerow([])

    if analysis and (analysis.get("vulnerabilities") or analysis.get("recommendations")):
        writer.writerow(["--- AI Threat Analysis ---"])
        writer.writerow(["AI Status:", analysis.get("ai_status", "N/A")])
        writer.writerow([])
        if analysis.get("vulnerabilities"):
            writer.writerow(["Potential Vulnerabilities:"])
            for vuln in analysis["vulnerabilities"]:
                writer.writerow([vuln])
            writer.writerow([])
        if analysis.get("recommendations"):
            writer.writerow(["Recommendations:"])
            for rec in analysis["recommendations"]:
                writer.writerow([rec])
            writer.writerow([])
    else:
        writer.writerow(["No AI analysis or vulnerabilities detected."])

    output.seek(0)
    return send_file(io.BytesIO(output.getvalue().encode('utf-8')),
                     mimetype='text/csv',
                     as_attachment=True,
                     download_name='scan_report.csv')

## ----------------- RUN APPLICATION ----------------- ##

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=8000)