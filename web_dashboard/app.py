# web_dashboard/app.py
from flask import Flask, render_template, request, jsonify
import sys
import os
import json

# Add the parent directory (ai_network_penetrator) to Python's system path.
# This allows us to import modules from the 'core' package.
# os.path.dirname(__file__) gets the directory of 'app.py' (web_dashboard)
# os.path.abspath(os.path.join(..., '..')) goes up one level to 'ai_network_penetrator'
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Now we can import from core modules
from core.network_scanner import run_port_scan, SCAN_RESULTS_FILE
from core.ai_module import get_latest_analysis

app = Flask(__name__,
            template_folder='templates', # Specify template folder explicitely
            static_folder='static')      # Specify static folder explicitely

# Ensure the 'data' directory exists for scan_results.json
# This creates the 'data' folder if it doesn't already exist.
os.makedirs(os.path.dirname(SCAN_RESULTS_FILE), exist_ok=True)

@app.route('/')
def index():
    """
    Renders the main dashboard page.
    It attempts to load the latest scan results and AI analysis to display on load.
    """
    latest_scan = None
    all_scans = []
    
    # Check if the scan results file exists and has content
    if os.path.exists(SCAN_RESULTS_FILE) and os.path.getsize(SCAN_RESULTS_FILE) > 0:
        try:
            with open(SCAN_RESULTS_FILE, 'r') as f:
                all_scans = json.load(f)
                if all_scans:
                    latest_scan = all_scans[-1] # Get the most recent scan (last item in list)
        except json.JSONDecodeError:
            print("[Web] Warning: scan_results.json is empty or corrupt. Starting fresh for display.")
            all_scans = [] # Reset to empty list if file is invalid JSON

    analysis = get_latest_analysis() # Get analysis for the latest scan

    # Render the HTML template, passing data to it
    return render_template('index.html',
                           latest_scan=latest_scan,
                           # Pass all scans, reversed to show newest first in the "Previous Scans" section
                           all_scans=reversed(all_scans),
                           analysis=analysis)

@app.route('/scan', methods=['POST'])
def scan_network():
    """
    Handles the network scan request sent from the web dashboard via AJAX.
    It retrieves target IP and ports from the form, initiates the scan, and returns JSON.
    """
    target_ip = request.form.get('target_ip')
    ports_str = request.form.get('ports_to_scan')

    # Basic validation for target IP
    if not target_ip:
        return jsonify({"status": "error", "message": "Target IP cannot be empty!"}), 400

    ports_to_scan = []
    if ports_str:
        try:
            # Parse comma-separated ports, ensuring they are valid numbers
            ports_to_scan = [int(p.strip()) for p in ports_str.split(',') if p.strip().isdigit()]
            if not ports_to_scan: # If no valid numbers were parsed
                 return jsonify({"status": "error", "message": "No valid ports provided. Use comma-separated numbers."}), 400
        except ValueError:
            return jsonify({"status": "error", "message": "Invalid port format. Use comma-separated numbers."}), 400
    else:
        # Default ports if no specific ports are provided in the form
        ports_to_scan = [21, 22, 23, 80, 443, 8080] # Automated Network Vulnerability Scanning using tools like Nmap and Scapy.

    # Run the port scan using the imported network_scanner function.
    # In a real-world application, for long-running tasks like scans,
    # you would typically offload this to a background job (e.g., using Celery with Redis/RabbitMQ)
    # to keep the web server responsive. For this prototype, it runs synchronously.
    scan_results = run_port_scan(target_ip, ports_to_scan) # This directly saves to JSON file.

    # After scanning, re-run the AI analysis to get updated insights based on the new scan.
    analysis = get_latest_analysis()

    # Return a JSON response indicating success and providing latest data
    return jsonify({
        "status": "success",
        "message": "Scan completed. Dashboard will update.",
        "scan_results": scan_results, # Return the specific scan results
        "analysis": analysis         # Return the latest analysis results
    })

@app.route('/get_latest_data', methods=['GET'])
def get_latest_data_api():
    """
    API endpoint to fetch the latest scan and analysis data.
    This is called by the JavaScript on the frontend to update the dashboard dynamically.
    """
    latest_scan = None
    all_scans = []
    
    if os.path.exists(SCAN_RESULTS_FILE) and os.path.getsize(SCAN_RESULTS_FILE) > 0:
        try:
            with open(SCAN_RESULTS_FILE, 'r') as f:
                all_scans = json.load(f)
                if all_scans:
                    latest_scan = all_scans[-1]
        except json.JSONDecodeError:
            print("[Web] Error: Could not decode scan_results.json for API. File might be empty or corrupt.")
            all_scans = []

    analysis = get_latest_analysis() # Get latest analysis based on the data in the JSON file

    # Return data as JSON
    return jsonify({
        "latest_scan": latest_scan,
        # Ensure all_scans is a list and reversed for displaying newest first
        "all_scans": list(reversed(all_scans)),
        "analysis": analysis
    })

if __name__ == '__main__':
    # Run the Flask development server.
    # debug=True allows for auto-reloading code changes and detailed error messages.
    # host='0.0.0.0' makes the server accessible from other devices on your network
    # (useful for testing on another machine), though you'll typically access via 127.0.0.1 (localhost).
    app.run(debug=True, host='0.0.0.0', port=8000) 