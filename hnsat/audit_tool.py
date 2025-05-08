import subprocess
import requests
import re
import datetime
import threading
import time
import ctypes
import asyncio
import aiohttp
import json
import os
import difflib
from config import NVD_API_KEY
from scapy.all import ARP, Ether, srp
from jinja2 import Environment, FileSystemLoader
import platform

CURRENT_OS = platform.system().lower()
OUI_DB = {}
CVE_CACHE_DIR = "cve_cache"
STOP_SCAN_FLAG = False
SCAN_DATA_DIR = "scan_data"

def is_admin():
    if platform.system() == "Windows":
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False
    else:
        return os.geteuid() == 0

def load_oui_db(path="oui.txt"):
    global OUI_DB
    oui_dict = {}
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                if "(hex)" in line:
                    parts = line.strip().split("(hex)")
                    mac_prefix = parts[0].strip().replace("-", ":").lower()
                    vendor = parts[1].strip()
                    oui_dict[mac_prefix] = vendor
    except FileNotFoundError:
        print("[!] OUI database not found")
    OUI_DB = oui_dict

def scan_ports(ip, mode="default"):
    global STOP_SCAN_FLAG

    if mode == "quick":
        base_cmd = ["nmap", "-T4", "-F", ip]
    elif mode == "aggressive":
        base_cmd = ["nmap", "-T4", "-A", "-p-", ip]
    else:
        base_cmd = ["nmap", "-T4", "-p-", "-sV", "--min-rate", "1000", "--max-retries", "1", ip]

    if CURRENT_OS != "windows":
        if os.geteuid() == 0:
            base_cmd.insert(1, "-sS")
            base_cmd.insert(4, "-O")
        else:
            base_cmd.insert(1, "-sT")
    else:
        base_cmd.insert(1, "-sT")

    try:
        result = subprocess.run(base_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if STOP_SCAN_FLAG:
            return "Scan stopped by user"
        return result.stdout.decode("utf-8")
    except subprocess.CalledProcessError as e:
        if STOP_SCAN_FLAG:
            return "Scan stopped by user"
        return f"Error: {e.output.decode('utf-8')}"
    
def scan_network(subnet):
    global STOP_SCAN_FLAG
    try:
        result = subprocess.run(["nmap", "-sn", subnet], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if STOP_SCAN_FLAG:
            return []
        output = result.stdout.decode('utf-8')
        live_ips = []
        for line in output.splitlines():
            if STOP_SCAN_FLAG:
                return []
            if "Nmap scan report for" in line:
                ip = line.split()[-1]
                live_ips.append(ip)
        return live_ips
    except subprocess.CalledProcessError as e:
        if STOP_SCAN_FLAG:
            return []
        return []

def extract_services(nmap_output):
    services = []
    for line in nmap_output.splitlines():
        match = re.search(r"(\d+/tcp)\s+open\s+([^\s]+)\s+(.*)", line)
        if match:
            port, service, version = match.groups()
            services.append({"port": port, "service": service, "version": version.strip()})
    return services

def detect_mac_vendor(ip):
    mac = "Unknown"
    vendor = "Unknown"
    try:
        arp = ARP(pdst=ip)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp
        result = srp(packet, timeout=2, verbose=0)[0]
        if result:
            mac = result[0][1].hwsrc
    except Exception as e:
        print(f"[!] ARP scan failed: {e}")

    if mac != "Unknown":
        oui_prefix = mac.lower()[0:8]
        vendor = OUI_DB.get(oui_prefix.replace("-", ":").replace(".", ""), "Unknown")
    return mac, vendor

async def fetch(session, url, parser):
    try:
        async with session.get(url, timeout=5) as response:
            if response.status == 200:
                data = await response.json()
                return parser(data)
    except Exception as e:
        print(f"[!] Error fetching {url}: {e}")
    return None

def parse_ipapi(data):
    return {
        "city": data.get("city", "Unknown"),
        "region": data.get("region", "Unknown"),
        "country": data.get("country_name", "Unknown"),
        "org": data.get("org", "Unknown")
    }

def parse_ipinfo(data):
    return {
        "city": data.get("city", "Unknown"),
        "region": data.get("region", "Unknown"),
        "country": data.get("country", "Unknown"),
        "org": data.get("org", "Unknown")
    }

def parse_ipwho(data):
    if data.get("success", False):
        return {
            "city": data.get("city", "Unknown"),
            "region": data.get("region", "Unknown"),
            "country": data.get("country", "Unknown"),
            "org": data.get("connection", {}).get("org", "Unknown")
        }
    return None

async def get_geo_info_async(ip=None):
    geo_info = {
        "public_ip": ip or "Unknown",
        "city": "Unknown",
        "region": "Unknown",
        "country": "Unknown",
        "org": "Unknown"
    }
    if not ip:
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get("https://api.ipify.org", timeout=5) as response:
                    ip = (await response.text()).strip()
                    geo_info["public_ip"] = ip
        except Exception as e:
            print(f"[!] Public IP fetch failed: {e}")
            return geo_info

    urls = [
        (f"https://ipapi.co/{ip}/json", parse_ipapi),
        (f"https://ipinfo.io/{ip}/json", parse_ipinfo),
        (f"https://ipwho.is/{ip}", parse_ipwho)
    ]

    async with aiohttp.ClientSession() as session:
        tasks = [asyncio.create_task(fetch(session, url, parser)) for url, parser in urls]
        done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for task in done:
            result = task.result()
            if result:
                geo_info.update(result)
                break
        for task in pending:
            task.cancel()
    return geo_info


def load_cached_cve(service_key):
    path = os.path.join(CVE_CACHE_DIR, f"{service_key}.json")
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    return None

def save_cached_cve(service_key, data):
    os.makedirs(CVE_CACHE_DIR, exist_ok=True)
    path = os.path.join(CVE_CACHE_DIR, f"{service_key}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f)

def get_cves_for_service(service_name, product, version):
    cves = []
    query = f"{product} {version}"
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {
        "keywordSearch": query,
        "resultsPerPage": 5
    }
    headers = {
        "User-Agent": "HomeNetworkAuditTool/1.0"
    }

    try:
        response = requests.get(url, params=params, headers=headers, timeout=10)
        if response.status_code == 200:
            data = response.json()
            for item in data.get("vulnerabilities", []):
                cve = item.get("cve", {})
                desc = cve.get("descriptions", [{}])[0].get("value", "No description")

                metrics = cve.get("metrics", {})
                cvss = metrics.get("cvssMetricV31", [{}])[0].get("cvssData", {})
                score = cvss.get("baseScore", "N/A")
                severity = cvss.get("baseSeverity", "Unknown")

                remediation = "Follow vendor advisory for mitigation."
                if "patch" in desc.lower():
                    remediation = "Apply the latest vendor patch."
                elif "default credentials" in desc.lower() or "password" in desc.lower():
                    remediation = "Change default credentials and enforce strong authentication."

                cves.append({
                    "id": cve.get("id", "Unknown"),
                    "description": desc,
                    "severity": severity,
                    "score": score,
                    "remediation": remediation
                })
    except Exception as e:
        print(f"Error fetching CVEs for {query}: {e}")

    return cves


def full_audit(ip, offline=False, previous_data=None, scan_mode="default"):
    load_oui_db()
    nmap_output = scan_ports(ip, mode=scan_mode)
    services = extract_services(nmap_output)
    mac, vendor = detect_mac_vendor(ip)
    geo_info = asyncio.run(get_geo_info_async(ip))
    for svc in services:
        svc["cves"] = get_cves_for_service(svc["service"], svc["service"], svc["version"])
    data = {
        "ip": ip,
        "mac": mac,
        "vendor": vendor,
        "geo": geo_info,
        "services": services,
        "weak_creds": [],
        "enumeration": []
    }
    return data

# --- Weak Credential Checking ---
def check_web_logins(ip):
    results = []
    for port in [80, 443, 8080]:
        try:
            url = f"http://{ip}:{port}/"
            r = requests.get(url, timeout=3, verify=False, allow_redirects=True)
            if "login" in r.text.lower() or "password" in r.text.lower():
                for user in ["admin", "root"]:
                    for pwd in ["admin", "root", "1234", "password"]:
                        login = requests.post(url, data={"username": user, "password": pwd}, timeout=3)
                        if login.status_code == 200 and "logout" in login.text.lower():
                            results.append(f"Web login on port {port} accepted weak creds: {user}/{pwd}")
        except:
            continue
    return results


def check_weak_credentials(ip, services):
  results = check_web_logins(ip)
  if CURRENT_OS == "windows":
      print("[!] Skipping hydra brute force on Windows")
      return results
  for svc in services:
      if svc["service"] in ["ssh", "ftp"]:
          hydra_cmd = ["hydra", "-L", "common_users.txt", "-P", "common_passwords.txt", ip, svc["service"]]
          try:
              result = subprocess.run(hydra_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
              out = result.stdout.decode("utf-8")
              if "login:" in out:
                  results.append(f"Hydra found weak credentials for {svc['service']}:\n{out}")
          except Exception as e:
              results.append(f"Error running hydra: {e}")
  return results


# --- Service Enumeration ---
def enumerate_services(ip, services):
    findings = []
    for svc in services:
        port = svc["port"]
        if svc["service"] == "ftp":
            try:
                r = subprocess.run(["ftp", ip], input="anonymous\n\n", text=True, stdout=subprocess.PIPE, timeout=5)
                if "230" in r.stdout:
                    findings.append("FTP allows anonymous login.")
            except:
                continue
        elif svc["service"] == "smb":
            try:
                r = subprocess.run(["smbclient", "-L", f"//{ip}/", "-N"], stdout=subprocess.PIPE)
                if "Sharename" in r.stdout.decode():
                    findings.append("SMB share(s) accessible:")
            except:
                continue
        elif svc["service"] == "snmp":
            try:
                r = subprocess.run(["snmpwalk", "-v1", "-c", "public", ip], stdout=subprocess.PIPE, timeout=5)
                if r.stdout:
                    findings.append("SNMP accessible with community string 'public'.")
            except:
                continue
    return findings


# --- Delta Comparison ---
def compare_scans(old, new):
    changes = {"new_ports": [], "new_services": [], "new_cves": []}
    old_services = {(svc["port"], svc["service"]): svc for svc in old["services"]}
    for svc in new["services"]:
        key = (svc["port"], svc["service"])
        if key not in old_services:
            changes["new_ports"].append(key)
        else:
            old_cves = {c["id"] for c in old_services[key].get("cves", [])}
            for c in svc.get("cves", []):
                if c["id"] not in old_cves:
                    changes["new_cves"].append(c)
    return changes

def generate_html_report(all_scan_data, filename=None):
    os.makedirs(SCAN_DATA_DIR, exist_ok=True)
    if not filename:
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = os.path.join(SCAN_DATA_DIR, f"network_audit_report_{timestamp}.html")
    env = Environment(loader=FileSystemLoader(os.path.dirname(__file__)))
    template = env.from_string("""
    <html>
    <head><title>Home Network Security Audit</title></head>
    <body style="font-family: sans-serif;">
    <h1>🔐 Home Network Security Audit Report</h1>
    <p><b>Date:</b> {{ date }}</p>

    {% for device in devices %}
    <hr>
    <h2>🖥 Scanned Device: {{ device.ip }}</h2>

    <h3>MAC Address: {{ device.mac }}</h3>
    <h3>Vendor: {{ device.vendor }}</h3>

    <h3>📡 Open Ports & Services</h3>
    <ul>
        {% for svc in device.services %}
        <li>{{ svc.port }} - {{ svc.service }} ({{ svc.version }})</li>
        {% endfor %}
    </ul>

    <h3>🚨 CVEs Found</h3>
    {% for svc in device.services %}
        <h4>{{ svc.service }} {{ svc.version }}</h4>
        {% if svc.cves %}
            <ul>
            {% for cve in svc.cves %}
                <li>
                    <b>{{ cve.id }}</b>: {{ cve.description }}<br>
                    <b>Severity:</b> {{ cve.severity }} (Score: {{ cve.score }})<br>
                    <b>Remediation:</b> {{ cve.remediation }}
                </li>
            {% endfor %}
            </ul>
        {% else %}
            <p>No CVEs found.</p>
        {% endif %}
    {% endfor %}
                               
    <h3>🔑 Weak Credential Scan</h3>
    {% if device.weak_creds %}
        <ul>
        {% for cred in device.weak_creds %}
            <li>{{ cred }}</li>
        {% endfor %}
        </ul>
    {% else %}
        <p>No weak credentials found.</p>
    {% endif %}

    {% endfor %}
    </body>
    </html>
    """)
    html_content = template.render(devices=all_scan_data, date=datetime.datetime.now().strftime("%Y-%m-%d %H:%M"))
    with open(filename, "w", encoding="utf-8") as f:
        f.write(html_content)
    print(f"[✔] Report saved: {filename}")
    return filename

    
