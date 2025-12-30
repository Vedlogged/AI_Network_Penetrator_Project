from flask import Flask, render_template, request, session, redirect, url_for, flash, Response
from weasyprint import HTML
import sys
import os
import json
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.ai_module import analyze_vulnerabilities
from core.network_scanner import run_nmap_scan
from config import Config  # MongoDB config
from pymongo import MongoClient

app = Flask(__name__, template_folder='templates', static_folder='static')
app.secret_key = 'your_super_secret_key'

# MongoDB Connection
client = MongoClient(Config.MONGO_URI)
db = client[Config.DB_NAME]
users_collection = db[Config.USERS_COLLECTION]
scans_collection = db[Config.SCANS_COLLECTION]


@app.route('/')
def landing():
    return render_template('landing.html')


@app.route('/dashboard')
def dashboard():
    if not session.get('logged_in'):
        flash('You must be logged in to view the dashboard.', 'warning')
        return redirect(url_for('landing'))

    user_email = session.get('user_email')
    user_scans = list(scans_collection.find({"user_email": user_email}).sort("_id", -1))

    latest_scan = None
    analysis = None

    # Filter valid scans only
    valid_scans = [scan for scan in user_scans if isinstance(scan.get("scan_details"), dict)]

    if valid_scans:
        latest_scan = valid_scans[0]
        try:
            analysis = analyze_vulnerabilities(latest_scan)
        except Exception as e:
            print("[AI Analysis] Failed:", e)

    return render_template(
        'dashboard.html',
        latest_scan=latest_scan,
        all_scans=valid_scans,
        analysis=analysis
    )


@app.route('/signup', methods=['POST'])
def signup():
    name = request.form.get('name')
    email = request.form.get('email')
    password = request.form.get('password')

    if users_collection.find_one({"email": email}):
        flash('Account already exists. Login instead.', 'danger')
        return redirect(url_for('landing'))

    users_collection.insert_one({
        "name": name,
        "email": email,
        "password": generate_password_hash(password)
    })

    flash('Signup successful! Please login.', 'success')
    return redirect(url_for('landing'))


@app.route('/login', methods=['POST'])
def handle_login():
    email = request.form.get('email')
    password = request.form.get('password')

    user = users_collection.find_one({"email": email})
    if user and check_password_hash(user["password"], password):
        session['logged_in'] = True
        session['user_email'] = email
        flash('Login successful!', 'success')
        return redirect(url_for('dashboard'))

    flash('Invalid credentials.', 'danger')
    return redirect(url_for('landing'))


@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out.', 'info')
    return redirect(url_for('landing'))


@app.route('/scan', methods=['POST'])
def scan_network():
    if not session.get('logged_in'):
        return redirect(url_for('landing'))

    target_ip = request.form.get('target_ip', '').strip()

    if not target_ip:
        flash('Target IP required.', 'danger')
        return redirect(url_for('dashboard'))

    ports = [21, 22, 23, 53, 80, 443, 3306, 3389, 8080]

    scan_results = run_nmap_scan(target_ip, ports)

    if scan_results is not None:
        scan_results["user_email"] = session.get('user_email')
        scan_results["timestamp"] = datetime.utcnow()
        scans_collection.insert_one(scan_results)
        flash(f'Scan completed for {target_ip}', 'success')
    else:
        flash(f'Nmap failed or host unreachable for {target_ip}', 'danger')

    return redirect(url_for('dashboard'))


@app.route('/download_report')
def download_report():
    if not session.get('logged_in'):
        return redirect(url_for('landing'))

    user_email = session.get('user_email')
    scan = scans_collection.find_one({"user_email": user_email}, sort=[("_id", -1)])

    if not scan:
        flash("No scan report found!", "warning")
        return redirect(url_for('dashboard'))

    analysis = analyze_vulnerabilities(scan)

    # Safely get the primary host from scan_details
    primary_host = None
    primary_host_details = None
    scan_details = scan.get("scan_details")
    if isinstance(scan_details, dict) and scan_details:
        primary_host = next(iter(scan_details))
        primary_host_details = scan_details[primary_host]

    html_out = render_template(
        'report_template.html',
        latest_scan=scan,
        analysis=analysis,
        primary_host=primary_host,
        primary_host_details=primary_host_details
    )
    pdf_out = HTML(string=html_out).write_pdf()

    return Response(
        pdf_out,
        mimetype="application/pdf",
        headers={"Content-Disposition": "attachment;filename=security_report.pdf"}
    )


if __name__ == '__main__':
    app.run(debug=True)
