import os
import json
import requests
from dotenv import load_dotenv
from datetime import datetime

# Load API keys from .env
load_dotenv()
SHODAN_KEY = os.getenv("SHODAN_KEY")
VT_KEY = os.getenv("VIRUSTOTAL_KEY")
OTX_KEY = os.getenv("OTX_KEY")

# Ensure data directory exists
DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "data")
os.makedirs(DATA_DIR, exist_ok=True)

def save_result(source: str, ip: str, data: dict):
    """Save results to data/{source}_{ip}_{date}.json"""
    date = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{source}_{ip}_{date}.json"
    path = os.path.join(DATA_DIR, filename)
    try:
        with open(path, "w") as f:
            json.dump(data, f, indent=2)
    except Exception as e:
        print(f"[!] Failed to save {source} data: {e}")

# ------------------ SHODAN ------------------ #
def shodan_host(ip: str):
    url = f"https://api.shodan.io/shodan/host/{ip}?key={SHODAN_KEY}"
    try:
        r = requests.get(url, timeout=10)
        if r.status_code == 401:
            return {"error": "🚫 Invalid Shodan API key."}
        if r.status_code == 403:
            return {"error": "🚫 Shodan API requires Membership plan for host lookups."}

        r.raise_for_status()
        data = r.json()

        summary = {
            "IP": data.get("ip_str"),
            "Organization": data.get("org"),
            "ISP": data.get("isp"),
            "OS": data.get("os"),
            "Hostnames": data.get("hostnames", []),
            "Country": data.get("country_name"),
            "City": data.get("city"),
            "Open Ports": data.get("ports", []),
            "Services": [],
            "SSL Info": []
        }

        for item in data.get("data", []):
            service = {
                "Port": item.get("port"),
                "Transport": item.get("_transport"),
                "Product": item.get("product"),
                "Version": item.get("version"),
                "Timestamp": item.get("timestamp")
            }
            summary["Services"].append(service)
            if "ssl" in item:
                ssl_data = item["ssl"].get("cert", {})
                summary["SSL Info"].append({
                    "Issued To": ssl_data.get("subject", {}),
                    "Issuer": ssl_data.get("issuer", {}),
                    "Expiry": ssl_data.get("expired"),
                })

        save_result("shodan", ip, summary)
        return summary

    except Exception as e:
        return {"error": f"Shodan error: {e}"}

# ------------------ VIRUSTOTAL ------------------ #
def virustotal_ip(ip: str):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": VT_KEY}
    try:
        r = requests.get(url, headers=headers, timeout=10)
        if r.status_code == 401:
            return {"error": "🚫 Invalid VirusTotal API key."}
        if r.status_code == 403:
            return {"error": "🚫 VirusTotal API quota exceeded."}

        r.raise_for_status()
        attributes = r.json().get("data", {}).get("attributes", {})
        last_analysis_stats = attributes.get("last_analysis_stats", {})

        summary = {
            "IP": ip,
            "Reputation": attributes.get("reputation"),
            "ASN": attributes.get("asn"),
            "Country": attributes.get("country"),
            "Owner": attributes.get("as_owner"),
            "Total Reports": sum(last_analysis_stats.values()),
            "Detections": last_analysis_stats,
            "Categories": attributes.get("categories", {}),
            "Last Analysis Date": attributes.get("last_analysis_date")
        }

        save_result("virustotal", ip, summary)
        return summary

    except Exception as e:
        return {"error": f"VirusTotal error: {e}"}

# ------------------ OTX ------------------ #
def otx_pulses_ip(ip: str):
    url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
    headers = {"X-OTX-API-KEY": OTX_KEY}
    try:
        r = requests.get(url, headers=headers, timeout=10)
        if r.status_code == 401:
            return {"error": "🚫 Invalid OTX API key."}
        if r.status_code == 403:
            return {"error": "🚫 OTX quota exceeded."}

        r.raise_for_status()
        data = r.json()

        summary = {
            "IP": ip,
            "ASN": data.get("asn"),
            "Country": data.get("country_name"),
            "Continent": data.get("continent_code"),
            "Reputation": data.get("reputation"),
            "WHOIS": data.get("whois"),
            "Pulse Count": data.get("pulse_info", {}).get("count", 0),
            "False Positive": [
                {"assessment": fp.get("assessment"), "date": fp.get("assessment_date")}
                for fp in data.get("false_positive", [])
            ],
            "Validation": [
                {"source": v.get("source"), "message": v.get("message")}
                for v in data.get("validation", [])
            ],
            "Coordinates": {
                "lat": data.get("latitude"),
                "lon": data.get("longitude"),
                "accuracy_radius": data.get("accuracy_radius")
            }
        }

        save_result("otx", ip, summary)
        return summary

    except Exception as e:
        return {"error": f"OTX error: {e}"}
