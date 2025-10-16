# AI Network Penetrator Project (ARGUS)

ARGUS is an AI-assisted penetration testing tool designed to analyze network security. This functional prototype integrates automated network scanning with AI-based threat detection, presented through a user-friendly web dashboard. It is designed to identify vulnerabilities, analyze potential threats, and provide actionable mitigation steps.

## Key Features

*   **Automated Network Scanning:** Utilizes Nmap to perform detailed scans on target IPs, identifying open ports, running services, versions, and operating system details.
*   **AI-Powered Threat Analysis:** Employs a dual-pronged approach for analysis:
    1.  A pre-trained `scikit-learn` model assesses the overall risk level based on scan data.
    2.  A detailed vulnerability database provides in-depth information on common misconfigurations (e.g., exposed FTP, SSH, RDP), including descriptions, exploitation scenarios, and mitigation steps.
*   **Interactive Web Dashboard:** A modern, responsive web interface built with Flask allows users to:
    *   Create an account and log in securely.
    *   Initiate scans on specified targets.
    *   View detailed results from the latest scan.
    *   Review a history of previous scans.
    *   See the AI-generated threat analysis and recommended actions.
*   **PDF Report Generation:** Generates professional, downloadable PDF security reports summarizing scan results and detailed findings for easy sharing and documentation.

## Project Structure

```
├── core/
│   ├── ai_module.py           # Handles AI analysis and vulnerability lookups
│   ├── network_scanner.py     # Nmap scanning logic
│   └── model/
│       └── threat_detector_unified_model.joblib # Pre-trained ML model
├── data/
│   └── scan_results.json      # Stores historical scan results
└── web_dashboard/
    ├── app.py                 # Main Flask application
    ├── static/                # CSS and JavaScript files
    └── templates/             # HTML templates for the UI
```

## Technologies Used

*   **Backend:** Python, Flask, Gunicorn
*   **Scanning:** `python-nmap`, Nmap
*   **AI & Data:** `scikit-learn`, `pandas`
*   **Frontend:** HTML, CSS, JavaScript, Bootstrap 5
*   **PDF Generation:** `WeasyPrint`

## Setup and Installation

### Prerequisites

*   Python 3.8+
*   **Nmap:** Must be installed on your system and accessible via the system's PATH. You can download it from [nmap.org](https://nmap.org/download.html).
*   **Git LFS:** The machine learning model is stored using Git LFS. Install it from [git-lfs.github.com](https://git-lfs.github.com/).
*   **WeasyPrint Dependencies:** `WeasyPrint` requires GTK+ libraries. Follow the platform-specific installation instructions from the [WeasyPrint documentation](https://doc.weasyprint.org/stable/first_steps.html#installation).

### Installation Steps

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/vedlogged/ai_network_penetrator_project.git
    cd ai_network_penetrator_project
    ```

2.  **Pull the Git LFS files:**
    ```bash
    git lfs pull
    ```
    This will download the `threat_detector_unified_model.joblib` file.

3.  **Install Python dependencies:**
    *(Note: `weasyprint` is required for PDF reports but is not listed in `requirements.txt`)*
    ```bash
    pip install -r requirements.txt
    pip install weasyprint
    ```

4.  **Run the Flask application:**
    ```bash
    python web_dashboard/app.py
    ```

5.  Access the application by navigating to `http://127.0.0.1:5000` in your web browser.

## Usage

1.  **Create an Account:** On the landing page, click "Get Started" or "Login / Sign Up" to open the authentication modal. Create a new account.
2.  **Log In:** Use your credentials to log in. You will be redirected to the dashboard.
3.  **Initiate a Scan:**
    *   On the dashboard, locate the "Scan Controls" panel.
    *   Enter a target IP address or hostname (e.g., `127.0.0.1` or `scanme.nmap.org`).
    *   Click "Start Scan". The scan may take a few moments.
4.  **View Results:**
    *   Once the scan completes, the page will refresh.
    *   The "Latest Scan Results" panel will display open ports and service information.
    *   The "AI Threat Analysis" section will show detailed findings and mitigation advice for any detected vulnerabilities.
    *   The "Scan History" panel will be updated with your latest scan.
5.  **Download Report:**
    *   If a scan has been completed, a "Download Report" button will appear above the latest results.
    *   Click this button to generate and download a comprehensive PDF report of the findings.
