# 🛡️ Home Network Security Audit Tool (HSNAT)

A powerful Python-based tool for scanning and auditing devices on your home or small office network. It detects open ports, enumerates services, checks for known vulnerabilities (CVEs), and highlights weak credentials — all through a GUI built with CustomTkinter.

---

##  Features

- 🔍 **Network & Port Scanning**: Uses `nmap` to discover live hosts and open ports.
- 📡 **Service Detection**: Identifies running services and software versions.
- ⚠️ **CVE Lookup**: Fetches known vulnerabilities from the [NVD API](https://nvd.nist.gov/developers/vulnerabilities), with:
  - CVE ID
  - Description
  - CVSS severity and score
  - Suggested remediation
- 🔑 **Weak Credential Scanning**: Attempts default/common credentials using `Hydra`.
- 🧠 **Delta Comparison**: Highlights new ports, services, or CVEs since your last scan.
- 🌍 **Geolocation**: Displays estimated location and ISP info using external IP data.
- 🗺️ **Network Map Visualization**: Interactive map of devices and their topology.
- 🧾 **Reports**: Generates HTML and JSON reports for auditing and tracking.
- 🌐 **Offline Mode**: Skip CVE checks for air-gapped or firewalled environments.

---

## 🖥️ GUI Snapshot

Powered by `CustomTkinter`, the GUI offers:

- IP/Subnet scan entry
- Quick or aggressive scan mode
- Real-time progress and results
- Tabbed interface for current and previous scans
- Embedded network map using `matplotlib`

---

## 🛠️ Requirements

- Python 3.8+
- `nmap` installed and available in PATH
- External tools: `Hydra`, `ftp`, `smbclient`, `snmpwalk`
- Python libraries:
  - `customtkinter`
  - `requests`
  - `aiohttp`
  - `jinja2`
  - `scapy`
  - `matplotlib`
  - `networkx`

Install dependencies:
```bash
pip install -r requirements.txt
