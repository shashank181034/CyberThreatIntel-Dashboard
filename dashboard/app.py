import os
import time
import json
import pandas as pd
import streamlit as st
from dotenv import load_dotenv
from glob import glob

# Ensure project root is importable
import sys
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

# Our data fetchers + PDF
from scripts.feeds import shodan_host, virustotal_ip, otx_pulses_ip
from scripts.report import export_pdf  # 📄 PDF generator

# -------------------- App Setup -------------------- #
st.set_page_config(
    page_title="Cyber Threat Intel Dashboard",
    page_icon="🛰️",
    layout="wide",
)

load_dotenv()
SHODAN_KEY = os.getenv("SHODAN_KEY")
VT_KEY = os.getenv("VIRUSTOTAL_KEY")
OTX_KEY = os.getenv("OTX_KEY")

DATA_DIR = os.path.join(ROOT, "data")

# -------------------- Threat Score -------------------- #
def calculate_threat_score(vt, otx, shodan):
    score = 0
    if vt and "Detections" in vt and isinstance(vt.get("Detections"), dict):
        score += vt["Detections"].get("malicious", 0) * 10
    if otx:
        score += (otx.get("Pulse Count", 0) or 0) * 5
    if shodan:
        score += len(shodan.get("Open Ports", [])) * 2
    return min(score, 100)

# Sidebar
st.sidebar.title("⚙️ Settings")
st.sidebar.write("**API Keys**")
st.sidebar.caption(
    f"Shodan: {'✅' if SHODAN_KEY else '❌'} · VirusTotal: {'✅' if VT_KEY else '❌'} · OTX: {'✅' if OTX_KEY else '❌'}"
)
st.sidebar.markdown("---")

default_ip = st.sidebar.text_input("Target IP", value="8.8.8.8")

# ⚡ Mode toggle: Live vs Cached
mode = st.sidebar.radio("Mode", ["Live API", "Cached Data"])
go = st.sidebar.button("Fetch Intel")

st.title("🛰️ Cyber Threat Intelligence — IP Overview")
st.caption("Shodan · VirusTotal · AlienVault OTX")

# -------------------- Cache helpers -------------------- #
def load_cached(source: str, ip: str):
    """Load the latest cached JSON file for a source + IP"""
    pattern = os.path.join(DATA_DIR, f"{source}_{ip}_*.json")
    files = sorted(glob(pattern))
    if not files:
        return {"error": f"No cached {source} data for {ip}."}
    latest = files[-1]  # last file = newest
    with open(latest, "r") as f:
        return json.load(f)

# -------------------- Fetch wrappers -------------------- #
def fetch_shodan(ip: str):
    return shodan_host(ip) if mode == "Live API" else load_cached("shodan", ip)

def fetch_vt(ip: str):
    return virustotal_ip(ip) if mode == "Live API" else load_cached("virustotal", ip)

def fetch_otx(ip: str):
    return otx_pulses_ip(ip) if mode == "Live API" else load_cached("otx", ip)

# -------------------- Helper UI funcs -------------------- #
def k(value):
    if value is None:
        return "—"
    if isinstance(value, (list, dict)):
        return value if value else "—"
    return value

def metric_row(cols, pairs):
    for col, (label, value) in zip(cols, pairs):
        col.metric(label, value if value not in (None, "", []) else "—")

def show_json_expander(label, obj):
    with st.expander(label):
        st.code(json.dumps(obj, indent=2, ensure_ascii=False))

# -------------------- Main body -------------------- #
if go:
    ip = default_ip.strip()

    # Fetch once for scoring + reporting
    shodan = fetch_shodan(ip)
    vt = fetch_vt(ip)
    otx = fetch_otx(ip)

    # Top summary
    top1, top2, top3 = st.columns(3)
    with top1:
        st.subheader("Target")
        st.write(f"**{ip}**")

    with top2:
        st.subheader("API Coverage")
        st.write(
            f"Shodan {'✅' if SHODAN_KEY else '❌'} · VirusTotal {'✅' if VT_KEY else '❌'} · OTX {'✅' if OTX_KEY else '❌'}"
        )
    with top3:
        st.subheader("Run")
        st.write(time.strftime("%Y-%m-%d %H:%M:%S"))
        st.caption(f"Mode: **{mode}**")

    # Threat Score
    threat_score = calculate_threat_score(vt, otx, shodan)
    if threat_score < 30:
        st.success(f"🟢 Threat Score: {threat_score}/100 (Low Risk)")
    elif threat_score < 70:
        st.warning(f"🟡 Threat Score: {threat_score}/100 (Medium Risk)")
    else:
        st.error(f"🔴 Threat Score: {threat_score}/100 (High Risk)")

    tabs = st.tabs(["Shodan", "VirusTotal", "OTX"])

    # -------------------- Shodan Tab -------------------- #
    with tabs[0]:
        st.markdown("## 🔎 Shodan")
        if "error" in shodan:
            st.error(shodan["error"])
        else:
            c1, c2, c3, c4 = st.columns(4)
            metric_row(
                (c1, c2, c3, c4),
                [
                    ("Organization", k(shodan.get("Organization"))),
                    ("Country", k(shodan.get("Country"))),
                    ("City", k(shodan.get("City"))),
                    ("Open Ports", len(shodan.get("Open Ports", []))),
                ],
            )
            ports = shodan.get("Open Ports", []) or []
            if ports:
                st.markdown("#### Open Ports")
                st.write(", ".join(str(p) for p in sorted(ports)))

            services = shodan.get("Services", []) or []
            if services:
                st.markdown("#### Services")
                df_services = pd.DataFrame(services)
                st.dataframe(df_services, use_container_width=True)
                df_ports = df_services.groupby("Port")["Port"].count().to_frame("Count")
                st.bar_chart(df_ports)

            sslinfo = shodan.get("SSL Info", []) or []
            if sslinfo:
                st.markdown("#### SSL Certificates (parsed)")
                df_ssl = pd.json_normalize(sslinfo, max_level=1)
                st.dataframe(df_ssl, use_container_width=True)

            show_json_expander("Raw Shodan JSON", shodan)

    # -------------------- VirusTotal Tab -------------------- #
    with tabs[1]:
        st.markdown("## 🧪 VirusTotal")
        if "error" in vt:
            st.error(vt["error"])
        else:
            c1, c2, c3, c4 = st.columns(4)
            detections = vt.get("Detections") or {}
            harmless = detections.get("harmless", 0)
            malicious = detections.get("malicious", 0)
            suspicious = detections.get("suspicious", 0)
            total_reports = vt.get("Total Reports") or (harmless + malicious + suspicious)

            metric_row(
                (c1, c2, c3, c4),
                [
                    ("Reputation", k(vt.get("Reputation"))),
                    ("ASN", k(vt.get("ASN"))),
                    ("Country", k(vt.get("Country"))),
                    ("Total Reports", total_reports),
                ],
            )

            st.markdown("#### Detection Breakdown")
            df_det = pd.DataFrame(
                [{"Status": k, "Count": v} for k, v in detections.items()]
            )
            if not df_det.empty:
                st.bar_chart(df_det.set_index("Status"))

            info_cols = st.columns(2)
            with info_cols[0]:
                st.markdown("#### Ownership / Network")
                st.table(
                    pd.DataFrame.from_dict(
                        {
                            "Owner": [k(vt.get("Owner"))],
                            "ASN": [k(vt.get("ASN"))],
                            "Country": [k(vt.get("Country"))],
                        }
                    )
                )
            with info_cols[1]:
                st.markdown("#### Categories")
                cats = vt.get("Categories") or {}
                if cats:
                    st.table(pd.DataFrame({"Category": list(cats.keys())}))
                else:
                    st.info("No categories reported.")

            show_json_expander("Raw VirusTotal JSON (summarized)", vt)

    # -------------------- OTX Tab -------------------- #
    with tabs[2]:
        st.markdown("## 🛰️ AlienVault OTX")
        if "error" in otx:
            st.error(otx["error"])
        else:
            c1, c2, c3, c4 = st.columns(4)
            metric_row(
                (c1, c2, c3, c4),
                [
                    ("Reputation", k(otx.get("Reputation"))),
                    ("Pulse Count", k(otx.get("Pulse Count"))),
                    ("Country", k(otx.get("Country"))),
                    ("Continent", k(otx.get("Continent"))),
                ],
            )

            cols = st.columns(2)
            with cols[0]:
                st.markdown("#### Validation")
                val = otx.get("Validation") or []
                if val:
                    st.table(pd.DataFrame(val))
                else:
                    st.info("No validation notices.")

            with cols[1]:
                st.markdown("#### False Positives")
                fps = otx.get("False Positive") or []
                if fps:
                    st.table(pd.DataFrame(fps))
                else:
                    st.info("No false-positive notes.")

            coords = otx.get("Coordinates") or {}
            lat, lon = coords.get("lat"), coords.get("lon")
            if isinstance(lat, (int, float)) and isinstance(lon, (int, float)):
                st.markdown("#### Geo (approx.)")
                st.map(pd.DataFrame([{"lat": lat, "lon": lon}]))
            else:
                st.caption("No coordinates available for map.")

            if otx.get("WHOIS"):
                st.markdown(f"[WHOIS link]({otx['WHOIS']})")

            show_json_expander("Raw OTX JSON (summarized)", otx)

    # -------------------- PDF Export -------------------- #
    if st.button("Generate PDF Report"):
        pdf_path = export_pdf(ip, vt, otx, shodan, threat_score)
        st.success(f"✅ PDF Report generated: {pdf_path}")

        with open(pdf_path, "rb") as f:
            st.download_button(
                label="⬇️ Download PDF",
                data=f,
                file_name=os.path.basename(pdf_path),
                mime="application/pdf"
            )

else:
    st.info("Enter an IP in the sidebar, pick a mode, and click **Fetch Intel**.")
