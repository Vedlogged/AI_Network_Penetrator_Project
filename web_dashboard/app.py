from flask import Flask, render_template, request, session, redirect, url_for, flash, Response
from weasyprint import HTML  # <<< KEY CHANGE: This is required for PDF generation
import sys
import os
import json
from werkzeug.security import generate_password_hash, check_password_hash

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.ai_module import analyze_vulnerabilities
from core.network_scanner import run_nmap_scan, SCAN_RESULTS_FILE

app = Flask(__name__, template_folder='templates', static_folder='static')
app.secret_key = 'your_super_secret_key_change_in_production'

os.makedirs(os.path.dirname(SCAN_RESULTS_FILE), exist_ok=True)
users = {}

@app.route('/')
def landing():
    return render_template('landing.html')

@app.route('/dashboard')
def dashboard():
    if not session.get('logged_in'):
        flash('You must be logged in to view the dashboard.', 'warning')
        return redirect(url_for('landing'))
    latest_scan, all_scans, analysis = None, [], None
    if os.path.exists(SCAN_RESULTS_FILE) and os.path.getsize(SCAN_RESULTS_FILE) > 0:
        try:
            with open(SCAN_RESULTS_FILE, 'r') as f:
                all_scans = json.load(f)
                if all_scans:
                    latest_scan = all_scans[-1]
                    analysis = analyze_vulnerabilities(latest_scan)
        except json.JSONDecodeError: print("[Web App] Warning: scan_results.json is corrupt.")
    return render_template('dashboard.html', latest_scan=latest_scan, all_scans=reversed(all_scans), analysis=analysis)

@app.route('/signup', methods=['POST'])
def signup():
    name = request.form.get('name')
    email = request.form.get('email')
    password = request.form.get('password')
    if email in users:
        flash('An account with this email already exists. Please log in.', 'danger')
        return redirect(url_for('landing'))
    users[email] = { "name": name, "password": generate_password_hash(password) }
    flash('Account created successfully! Please log in.', 'success')
    return redirect(url_for('landing'))

@app.route('/login', methods=['POST'])
def handle_login():
    email = request.form.get('email')
    password = request.form.get('password')
    user = users.get(email)
    if user and check_password_hash(user['password'], password):
        session['logged_in'] = True
        session['user_email'] = email
        flash('You have successfully logged in!', 'success')
        return redirect(url_for('dashboard'))
    else:
        flash('Invalid email or password. Please try again.', 'danger')
        return redirect(url_for('landing'))

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been successfully logged out.', 'info')
    return redirect(url_for('landing'))

@app.route('/scan', methods=['POST'])
def scan_network():
    if not session.get('logged_in'): return redirect(url_for('landing'))
    target_ip = request.form.get('target_ip', '').strip()
    if not target_ip:
        flash('Target IP cannot be empty!', 'danger')
        return redirect(url_for('dashboard'))
    ports_to_scan = [21, 22, 23, 53, 80, 443, 3306, 3389, 8080]
    try:
        scan_results = run_nmap_scan(target_ip, ports_to_scan)
        if scan_results is None:
            flash(f"Scan failed to execute. Check logs and ensure Nmap is installed.", 'danger')
        elif not scan_results.get("scan_details"):
            flash(f"Scan for {target_ip} completed, but host appears to be down.", 'warning')
        else:
            flash(f"Scan for {target_ip} completed successfully!", 'success')
    except Exception as e:
        print(f"[Web App] An unexpected error during scan route: {e}")
        flash(f"An unexpected server error occurred during the scan.", 'danger')
    return redirect(url_for('dashboard'))

# --- THIS IS THE CORRECTED PDF VERSION OF THE FUNCTION ---
@app.route('/download_report')
def download_report():
    if not session.get('logged_in'): return redirect(url_for('landing'))
    if not os.path.exists(SCAN_RESULTS_FILE) or os.path.getsize(SCAN_RESULTS_FILE) == 0:
        flash('No scan report available to download.', 'warning')
        return redirect(url_for('dashboard'))

    try:
        with open(SCAN_RESULTS_FILE, 'r') as f:
            all_scans = json.load(f)
            if not all_scans: raise ValueError("No scans in file.")
            latest_scan = all_scans[-1]
            analysis = analyze_vulnerabilities(latest_scan)
    except (json.JSONDecodeError, ValueError, IndexError):
        flash('Could not read scan data to generate report.', 'danger')
        return redirect(url_for('dashboard'))

    # Render the HTML template with the scan and analysis data
    html_out = render_template('report_template.html', latest_scan=latest_scan, analysis=analysis)
    
    # Convert the rendered HTML to a PDF in memory
    pdf_out = HTML(string=html_out).write_pdf()

    return Response(
        pdf_out,
        mimetype="application/pdf", # <<< KEY CHANGE: Specifies the file is a PDF
        headers={"Content-Disposition": f"attachment;filename=argus_security_report_{latest_scan.get('scan_id')}.pdf"} # <<< KEY CHANGE: Filename ends in .pdf
    )

if __name__ == '__main__':
    app.run(debug=True)