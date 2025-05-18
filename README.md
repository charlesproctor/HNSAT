# 🛡️ Home Network Security Audit Tool (HSNAT)

A Python tool for scanning and auditing devices on your home or small office network. It detects open ports, enumerates services, checks for known vulnerabilities (CVEs), and highlights weak credentials — all through a GUI built with CustomTkinter.

---

##  Features

-  **Network & Port Scanning**: Uses `nmap` to discover live hosts and open ports.
-  **Service Detection**: Identifies running services and software versions.
-  **CVE Lookup**: Fetches known vulnerabilities from the [NVD API](https://nvd.nist.gov/developers/vulnerabilities), with:
    - CVE ID
    - Description
    - CVSS severity and score
    - Suggested remediation
-  **Weak Credential Scanning**: Attempts default/common credentials using `Hydra`.
-  **Geolocation**: Displays estimated location and ISP info using external IP data.
-  **Network Map Visualization**: Interactive map of devices and their topology.
-  **Reports**: Generates HTML and JSON reports for auditing and tracking.
-  **Offline Mode**: Skip CVE checks for air-gapped or firewalled environments.

---

## GUI Snapshot

https://github.com/charlesproctor/HNSAT/blob/main/GUI%20Preview.md

Powered by `CustomTkinter`, the GUI offers:

- IP/Subnet scan entry
- Quick or aggressive scan mode
- Real-time progress and results
- Tabbed interface for current and previous scans
- Embedded network map using `matplotlib`

---


## Download

⬇️ Download the latest version(
https://github.com/charlesproctor/HNSAT/releases/latest)


---

## Requirements

HNSAT depends on several external tools in addition to Python packages. Installation steps vary by operating system.

###  Windows

   **[Nmap for Windows](https://nmap.org/download.html#windows)**
   - Download the Windows installer from the Nmap website.
   - Make sure to check **"Add Nmap to PATH"** during installation or manually add the install directory (e.g., `C:\Program Files (x86)\Nmap`) to your system PATH.

   **Python 3.10+**
   - Download from [python.org](https://www.python.org/downloads/windows/)
   - Ensure `Add Python to PATH` is checked during installation.


Install dependencies:
```
pip install -r windowsCMD-requirements.txt
```

### Linux (Debian/Ubuntu-based)

   **Nmap**
 ```
sudo apt update
sudo apt install nmap
 ```

   **Hyrdra**
```
sudo apt install hydra
 ```

   **Python 3.10+ and pip**
```
sudo apt install python3 python3-pip
 ```

   **Python Dependencies**
```
pip install -r linux-requirements.txt
```

### API Key Setup

To use HNSAT, you need an NVD API key for accessing CVE vulnerability data. This key must be stored in a .env file in the root of the hnsat folder.

Steps:

Get your API key:

 Visit the [NVD API Key Registration page](https://nvd.nist.gov/developers/request-an-api-key)

 Request a key and copy it from your email or the confirmation screen.

 Create a .env file:

 In your terminal, navigate to the hnsat folder and run:
    
    nano .env
    
Then add this line (replacing the value with your actual key):

    NVD_API_KEY=your_actual_key_here

### Installation

   **Clone the repository**
   ```
   git clone https://github.com/charlesproctor/HNSAT.git
   cd HNSAT
 ```
 
    python hnsat.py
 
