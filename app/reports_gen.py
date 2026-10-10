import os
import csv
from io import StringIO
from app.database import get_db_connection, now_string
from app.paths import data_path

try:
    from reportlab.pdfgen import canvas as pdf_canvas
    from reportlab.lib.pagesizes import A4
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False

try:
    import fitz  # PyMuPDF
    PYMUPDF_AVAILABLE = True
except ImportError:
    PYMUPDF_AVAILABLE = False

def generate_pdf_report(source_type: str = "REAL"):
    if not REPORTLAB_AVAILABLE and not PYMUPDF_AVAILABLE:
        raise RuntimeError("Neither ReportLab nor PyMuPDF is installed for PDF generation.")

    conn = get_db_connection()
    where_clause = ""
    params = []
    if source_type and source_type != "ALL":
        where_clause = "WHERE source_type = ?"
        params.append(source_type)

    stats = conn.execute(f"""
    SELECT
        COUNT(*) AS events,
        COUNT(DISTINCT device) AS devices,
        SUM(CASE WHEN severity='CRITICAL' THEN 1 ELSE 0 END) AS critical,
        SUM(CASE WHEN severity='HIGH' THEN 1 ELSE 0 END) AS high,
        SUM(CASE WHEN severity='MEDIUM' THEN 1 ELSE 0 END) AS medium,
        AVG(risk) AS avg_risk
    FROM events
    {where_clause}
    """, params).fetchone()

    inc_where = ""
    inc_params = []
    if source_type and source_type != "ALL":
        inc_where = "WHERE source_type = ?"
        inc_params.append(source_type)

    incidents_count = conn.execute(f"SELECT COUNT(*) FROM incidents {inc_where}", inc_params).fetchone()[0]
    resolved_count = conn.execute(f"SELECT COUNT(*) FROM incidents {inc_where} AND status='RESOLVED'" if inc_where else "SELECT COUNT(*) FROM incidents WHERE status='RESOLVED'", inc_params).fetchone()[0]

    reports_dir = data_path("reports")
    os.makedirs(reports_dir, exist_ok=True)
    report_filename = str(
        reports_dir / f"SentinelX_Report_{now_string().replace(':', '-').replace(' ', '_')}.pdf"
    )

    top_devices = conn.execute(f"""
    SELECT device, AVG(risk) as avg_risk, COUNT(*) as ev_count
    FROM events
    {where_clause}
    GROUP BY device
    ORDER BY avg_risk DESC
    LIMIT 5
    """, params).fetchall()

    report_lines = [
        f"Generated: {now_string()}",
        "--------------------------------------------------------------------------------",
        f"Total Network Events: {stats['events'] or 0}",
        f"Observed Endpoint Devices: {stats['devices'] or 0}",
        f"Critical Events: {stats['critical'] or 0}",
        f"High Risk Events: {stats['high'] or 0}",
        f"Medium Risk Events: {stats['medium'] or 0}",
        f"Average System Risk Score: {(stats['avg_risk'] or 0):.2f}%",
        f"Total Security Incidents: {incidents_count}",
        f"Resolved Security Incidents: {resolved_count}",
        "--------------------------------------------------------------------------------",
        "",
        "Top Risk Endpoint Devices:"
    ]

    if REPORTLAB_AVAILABLE:
        c = pdf_canvas.Canvas(report_filename, pagesize=A4)
        width, height = A4
        y = height - 50

        c.setFont("Helvetica-Bold", 20)
        c.drawString(50, y, "SENTINEL-X 2.0")

        y -= 25
        c.setFont("Helvetica-Bold", 12)
        c.drawString(50, y, "AI Security Operations Center Executive Summary")

        y -= 30
        c.setFont("Helvetica", 10)
        for line in report_lines:
            c.drawString(50, y, line)
            y -= 18

        for dev in top_devices:
            c.drawString(70, y, f"• {dev['device']} - Avg Risk: {dev['avg_risk']:.1f}% ({dev['ev_count']} events)")
            y -= 16

        c.save()
    elif PYMUPDF_AVAILABLE:
        doc = fitz.open()
        page = doc.new_page(width=595, height=842) # A4
        y = 50
        page.insert_text((50, y), "SENTINEL-X 2.0", fontsize=20)
        y += 25
        page.insert_text((50, y), "AI Security Operations Center Executive Summary", fontsize=12)
        y += 30
        for line in report_lines:
            page.insert_text((50, y), line, fontsize=10)
            y += 18
        for dev in top_devices:
            page.insert_text((70, y), f"• {dev['device']} - Avg Risk: {dev['avg_risk']:.1f}% ({dev['ev_count']} events)", fontsize=10)
            y += 16
        doc.save(report_filename)
        doc.close()

    return report_filename

def generate_csv_report(source_type: str = "REAL"):
    conn = get_db_connection()
    where_clause = ""
    params = []
    if source_type and source_type != "ALL":
        where_clause = "WHERE source_type = ?"
        params.append(source_type)

    events = conn.execute(f"SELECT * FROM events {where_clause} ORDER BY id DESC LIMIT 1000", params).fetchall()
    
    output = StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "ID", "Timestamp", "Device", "Source IP", "Destination IP",
        "Port", "Protocol", "Packets", "Traffic (MB)", "Connections",
        "Risk", "Severity", "AI Score", "Factors", "Source Type"
    ])
    
    for row in events:
        writer.writerow([
            row["id"], row["timestamp"], row["device"], row["source_ip"], row["destination_ip"],
            row["port"], row["protocol"], row["packets"], row["traffic"], row["connections"],
            row["risk"], row["severity"], row["ai_score"], row["factors"], row["source_type"]
        ])
        
    output.seek(0)
    return output.getvalue()
