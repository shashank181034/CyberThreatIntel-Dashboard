from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
import os, time

def export_pdf(ip, vt, otx, shodan, score, outdir="reports"):
    if not os.path.exists(outdir):
        os.makedirs(outdir)

    filename = os.path.join(outdir, f"report_{ip}.pdf")
    c = canvas.Canvas(filename, pagesize=A4)
    width, height = A4

    # Title
    c.setFont("Helvetica-Bold", 18)
    c.drawString(50, height - 50, f"Cyber Threat Intel Report — {ip}")

    c.setFont("Helvetica", 12)
    c.drawString(50, height - 80, f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}")

    # Threat Score
    c.setFont("Helvetica-Bold", 14)
    c.drawString(50, height - 120, f"Threat Score: {score}/100")

    # VirusTotal
    c.setFont("Helvetica-Bold", 12)
    c.drawString(50, height - 160, "VirusTotal Summary:")
    c.setFont("Helvetica", 10)
    c.drawString(70, height - 175, f"Reputation: {vt.get('Reputation')}")
    c.drawString(70, height - 190, f"Detections: {str(vt.get('Detections'))}")

    # OTX
    c.setFont("Helvetica-Bold", 12)
    c.drawString(50, height - 220, "AlienVault OTX Summary:")
    c.setFont("Helvetica", 10)
    c.drawString(70, height - 235, f"Pulse Count: {otx.get('Pulse Count')}")
    c.drawString(70, height - 250, f"Validation: {str(otx.get('Validation'))}")

    # Shodan
    c.setFont("Helvetica-Bold", 12)
    c.drawString(50, height - 280, "Shodan Summary:")
    c.setFont("Helvetica", 10)
    c.drawString(70, height - 295, f"Organization: {shodan.get('Organization')}")
    c.drawString(70, height - 310, f"Open Ports: {str(shodan.get('Open Ports'))}")

    c.showPage()
    c.save()
    return filename
