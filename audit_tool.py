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

async def get_geo_info_async(ip=None):
    geo_info = {
        "public_ip": ip or "Unknown",
        "city": "Unknown",
        "region": "Unknown",
        "country": "Unknown",
        "org": "Unknown"
    }
    return geo_info

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

    {% endfor %}
    </body>
    </html>
    """)
    html_content = template.render(devices=all_scan_data, date=datetime.datetime.now().strftime("%Y-%m-%d %H:%M"))
    with open(filename, "w", encoding="utf-8") as f:
        f.write(html_content)
    print(f"[✔] Report saved: {filename}")
    return filename
