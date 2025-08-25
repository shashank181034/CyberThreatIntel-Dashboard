# 🛰️ Cyber Threat Intelligence Dashboard  

A **Streamlit-based dashboard** for analyzing IP addresses using:  
- 🔎 **Shodan** → Open ports, services, SSL details  
- 🧪 **VirusTotal** → Reputation, malware detections, categories  
- 🛰️ **AlienVault OTX** → Threat pulses, reputation, false positives  

This project demonstrates **API integration, data visualization, and threat intelligence workflows**.  

---

## ✨ Features  

✅ Real-time API lookups (Shodan, VirusTotal, OTX)  
✅ Cached JSON results for offline demo (📂 `data/`)  
✅ Interactive dashboard with charts & tables  
✅ Threat Score (0–100) based on detections, ports, and pulses  
🚧 **Work in Progress**: PDF report export for analysts  

---

## ⚠️ Limitations  

- **Shodan Free Tier** → Only works reliably for popular/public IP ranges. Host lookups for specific IPs require a **paid membership**.  
- **VirusTotal Free Tier** → Rate-limited (4 requests/min). Bulk scans require premium.  
- **OTX** → Community-powered data, may not always cover all IPs.  

👉 Despite these limits, the tool is ideal for **learning, demos, and SOC analyst workflows**.  

---

## 🎯 SOC Use Case  

- **Analyst Triage** → Quickly enrich suspicious IPs with threat intel.  
- **Incident Response** → Check if an IP is malicious, scanned, or part of threat pulses.  
- **Reporting** → Generate dashboards & (soon) PDF reports for management.  
- **Enrichment Layer** → Can be integrated into SIEM/SOAR pipelines as an enrichment tool.

---

## ⚙️ Setup  

### 1. Clone the repo  
    ```bash
    git clone https://github.com/yourusername/CyberThreatIntel-Dashboard.git
    cd CyberThreatIntel-Dashboard
### 2. Install dependencies
    ```bash
    pip install -r requirements.txt
### 3. Add your API keys
### Create a .env file in the project root:
    ```bash
    SHODAN_KEY=your_shodan_api_key
    VIRUSTOTAL_KEY=your_virustotal_api_key
    OTX_KEY=your_otx_api_key
### 4. Run the dashboard
    ```bash
    streamlit run dashboard/app.py
### 🎯 Example

Enter an IP (e.g., 8.8.8.8) and fetch intel:

Shodan → open ports & services

VirusTotal → malicious detections

OTX → reputation & pulses

### 👤 Author

Built by MVS Shashank
🔗 https://www.linkedin.com/in/shashank-mvs-115630266
🔗 https://github.com/shashank181034


    
