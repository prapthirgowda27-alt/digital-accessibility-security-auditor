import os
import socket
import tempfile
from ipaddress import ip_address
from urllib.parse import urlparse
from xml.sax.saxutils import escape

import gradio as gr
import requests
from bs4 import BeautifulSoup
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle


def validate_url(raw_url):
    url = (raw_url or "").strip()
    if not url:
        raise ValueError("Please enter a website URL.")
    if "://" not in url:
        url = "https://" + url

    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("Enter a valid public HTTP or HTTPS URL.")
    if parsed.username or parsed.password:
        raise ValueError("URLs containing usernames or passwords are not allowed.")

    try:
        addresses = socket.getaddrinfo(parsed.hostname, None)
        for item in addresses:
            address = ip_address(item[4][0])
            if not address.is_global:
                raise ValueError("Only publicly accessible websites can be scanned.")
    except socket.gaierror:
        raise ValueError("The website address could not be found.")
    return url


def create_pdf(sections):
    file_handle = tempfile.NamedTemporaryFile(delete=False, suffix=".pdf")
    pdf_path = file_handle.name
    file_handle.close()

    styles = getSampleStyleSheet()
    doc = SimpleDocTemplate(
        pdf_path, pagesize=A4,
        rightMargin=36, leftMargin=36, topMargin=36, bottomMargin=36
    )
    story = [
        Paragraph("Digital Accessibility &amp; Security Auditor", styles["Title"]),
        Spacer(1, 12)
    ]

    for heading, rows in sections:
        story.append(Paragraph(escape(heading), styles["Heading2"]))
        data = []
        for row_index, row in enumerate(rows):
            style = "BodyText"
            data.append([Paragraph(escape(str(cell)), styles[style]) for cell in row])

        table = Table(data, repeatRows=1, colWidths=[doc.width * 0.62, doc.width * 0.38])
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#243B55")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ]))
        story.extend([table, Spacer(1, 10)])

    story.append(Paragraph(
        "Preliminary automated audit only. This is not official WCAG certification "
        "or a complete security assessment. Manual testing is also necessary.",
        styles["Italic"]
    ))
    doc.build(story)
    return pdf_path


def create_donut_charts(access_pass, access_fail, security_pass, security_fail):
    overall_pass = access_pass + security_pass
    overall_fail = access_fail + security_fail

    def make_chart(title, passed, failed):
        total = passed + failed
        percentage = (passed / total * 100) if total else 0
        circumference = 2 * 3.14159 * 42
        dash = circumference * percentage / 100

        return f"""
        <div style="text-align:center; padding:18px;
                    background:#111827; border-radius:16px;">
            <h3 style="color:white;">{title}</h3>
            <svg viewBox="0 0 120 120" width="150">
                <circle cx="60" cy="60" r="42"
                    fill="none" stroke="#EF4444" stroke-width="12"/>
                <circle cx="60" cy="60" r="42"
                    fill="none" stroke="#168BFF" stroke-width="12"
                    stroke-dasharray="{dash} {circumference}"
                    transform="rotate(-90 60 60)"/>
                <text x="60" y="56" fill="white"
                    text-anchor="middle" font-size="17"
                    font-weight="bold">{percentage:.0f}%</text>
                <text x="60" y="72" fill="white"
                    text-anchor="middle" font-size="9">TRUE</text>
            </svg>
            <p style="color:#60A5FA;">TRUE: {passed}</p>
            <p style="color:#F87171;">FALSE: {failed}</p>
        </div>
        """

    return f"""
    <div style="display:grid; grid-template-columns:
                repeat(auto-fit,minmax(200px,1fr)); gap:15px;">
        {make_chart("Accessibility", access_pass, access_fail)}
        {make_chart("Security", security_pass, security_fail)}
        {make_chart("Overall TRUE / FALSE", overall_pass, overall_fail)}
    </div>
    """

def scan_website(raw_url):
    try:
        url = validate_url(raw_url)
        response = requests.get(
            url,
            timeout=20,
            allow_redirects=True,
            headers={"User-Agent": "AccessibilityStudentAuditor/1.0"}
        )
        response.raise_for_status()
        final_url = validate_url(response.url)
        soup = BeautifulSoup(response.text, "html.parser")
        headers = response.headers

        # Image checks
        images = soup.find_all("img")
        missing_alt = [img for img in images if img.get("alt") is None]
        empty_alt = [
            img for img in images
            if img.has_attr("alt") and not img.get("alt", "").strip()
        ]

        # Link accessible-name checks
        links = soup.find_all("a")
        missing_links = []
        for link in links:
            visible_text = link.get_text(" ", strip=True)
            aria_label = (link.get("aria-label") or "").strip()
            title = (link.get("title") or "").strip()
            image_alt = any(
                (img.get("alt") or "").strip()
                for img in link.find_all("img")
            )
            if not (visible_text or aria_label or title or image_alt):
                missing_links.append(link)

        # Form-label checks
        controls = soup.find_all(["input", "textarea", "select"])
        missing_labels = []
        for control in controls:
            control_type = (control.get("type") or "").lower()
            if control_type in ["hidden", "submit", "button", "reset", "image"]:
                continue

            control_id = control.get("id")
            labelled = bool(
                (control_id and soup.find("label", attrs={"for": control_id}))
                or control.find_parent("label")
                or control.get("aria-label")
                or control.get("aria-labelledby")
            )
            if not labelled:
                missing_labels.append(control)

        # Heading structure
        heading_counts = {
            f"H{i}": len(soup.find_all(f"h{i}"))
            for i in range(1, 7)
        }

        # Security checks
        security_headers = {
            "Content-Security-Policy": "CSP",
            "X-Content-Type-Options": "MIME Sniffing Protection",
            "Strict-Transport-Security": "HSTS",
        }
        present = [name for name in security_headers if name in headers]
        csp_value = headers.get("Content-Security-Policy", "")
        clickjacking = (
            "frame-ancestors" in csp_value.lower()
            or bool(headers.get("X-Frame-Options"))
        )
        missing_security = [
            label for name, label in security_headers.items()
            if name not in headers
        ]
        if clickjacking:
            present.append("Clickjacking Protection")
        else:
            missing_security.append("Clickjacking Protection")

        # Chart calculations
        access_total = len(images) + len(links) + len(controls)
        access_issues = (
            len(missing_alt)
            + len(missing_links)
            + len(missing_labels)
        )

        access_pass = max(0, access_total - access_issues)
        access_fail = access_issues

        security_pass = len(present)
        if final_url.startswith("https://"):
            security_pass += 1

        security_fail = 5 - security_pass

        # Prototype scores
        total_checks = len(images) + len(links) + len(controls)
        total_issues = len(missing_alt) + len(missing_links) + len(missing_labels)
        accessibility_score = (
            max(0, (total_checks - total_issues) / total_checks * 100)
            if total_checks else None
        )
        security_score = (
            (len(present) + int(final_url.startswith("https://"))) / 5 * 100
        )

        access_score_text = (
            f"{accessibility_score:.1f}/100"
            if accessibility_score is not None
            else "Not enough data to calculate"
        )

        access_rows = [
            ["Accessibility check", "Result"],
            ["Total images", len(images)],
            ["Missing ALT text", len(missing_alt)],
            ["Empty ALT text", len(empty_alt)],
            ["Total links", len(links)],
            ["Links without detected names", len(missing_links)],
            ["Form controls", len(controls)],
            ["Controls without detected labels", len(missing_labels)],
        ]
        heading_rows = [["Heading", "Count"]] + [
            [name, count] for name, count in heading_counts.items()
        ]
        security_rows = [
            ["Security check", "Result"],
            ["HTTPS", "Present" if final_url.startswith("https://") else "Not used"],
            ["CSP", "Present" if "Content-Security-Policy" in headers else "Not detected"],
            ["MIME Sniffing Protection", "Present" if "X-Content-Type-Options" in headers else "Not detected"],
            ["HSTS", "Present" if "Strict-Transport-Security" in headers else "Not detected"],
            ["Clickjacking Protection", "Present" if clickjacking else "Not detected"],
        ]

        recommendations = []
        if missing_alt:
            recommendations.append("Review images missing ALT attributes.")
        if empty_alt:
            recommendations.append(
                "Review empty ALT attributes; decorative images may correctly use empty ALT."
            )
        if missing_links:
            recommendations.append("Review links without detected accessible names.")
        if missing_labels:
            recommendations.append("Review form controls without detected labels.")
        if missing_security:
            recommendations.append(
                "Review missing security protections: " + ", ".join(missing_security)
            )
        if not recommendations:
            recommendations.append(
                "No issues were detected by these basic checks. Manual review is still recommended."
            )

        report = f"""# Digital Accessibility & Security Audit Report

**Website:** {escape(final_url)}

**HTTP Status:** {response.status_code}

## 1. Accessibility Results

| Test | Result |
|---|---:|
""" + "\n".join(
            f"| {escape(str(row[0]))} | {escape(str(row[1]))} |"
            for row in access_rows[1:]
        ) + f"""

### Heading Structure

| Heading | Count |
|---|---:|
""" + "\n".join(
            f"| {name} | {count} |"
            for name, count in heading_counts.items()
        ) + f"""

**Prototype Accessibility Score: {access_score_text}**

## 2. Security Results

| Security check | Result |
|---|---|
""" + "\n".join(
            f"| {escape(str(row[0]))} | {escape(str(row[1]))} |"
            for row in security_rows[1:]
        ) + f"""

**Prototype Security Configuration Score: {security_score:.1f}/100**

## 3. Recommendations

""" + "\n".join(
            f"- {escape(item)}"
            for item in recommendations
        ) + """

---

*This is a preliminary automated audit, not official WCAG certification or a complete security assessment. Manual testing is also necessary.*
"""

        pdf_path = create_pdf([
            ("Website information", [["Website", final_url], ["HTTP status", response.status_code]]),
            ("Accessibility results", access_rows),
            ("Heading structure", heading_rows),
            ("Security results", security_rows),
            ("Recommendations", [["Recommendation", "Action"]] + [[item, "Review"] for item in recommendations]),
        ])
                charts_html = create_donut_charts(
            access_pass, access_fail,
            security_pass, security_fail
        )

        return report, pdf_path, charts_html

    except Exception as error:
        return (
            "## Scan could not be completed\n\n"
            + escape(str(error))
            + "\n\nCheck the URL and try again.",
            None,
            ""
        )



with gr.Blocks(
    title="Digital Accessibility & Security Auditor",
    theme=gr.themes.Soft()
) as app:

    gr.Markdown(
        """
        # 🛡️ Digital Accessibility & Security Auditor

        ### Making the web safer and more accessible.

        Evaluate public websites for accessibility issues
        and basic security configurations.

        ---
        """
    )

    with gr.Row():
        with gr.Column():
            gr.Markdown(
                """
                ### ♿ Accessibility Audit
                - Image ALT text checks
                - Form label checks
                - Link accessibility
                - Heading structure
                """
            )

        with gr.Column():
            gr.Markdown(
                """
                ### 🔒 Security Audit
                - HTTPS verification
                - Security header checks
                - Clickjacking protection
                - Security recommendations
                """
            )

    gr.Markdown("## 🔍 Start Your Website Audit")

    website_url = gr.Textbox(
        label="Enter Website URL",
        placeholder="https://www.example.com"
    )

    scan_button = gr.Button(
        "🔍 Scan Website",
        variant="primary"
    )
    charts = gr.HTML(label="Audit Charts")
    results = gr.Markdown(label="Audit Report")

    pdf_download = gr.File(
        label="Download PDF Audit Report"
    )

    scan_button.click(
        fn=scan_website,
        inputs=website_url,
        outputs=[results, pdf_download, charts]
    )

    gr.Markdown(
        """
        ---
        ### About This Project

        This tool performs a preliminary automated audit
        of website accessibility and basic security settings.

        **Note:** This is not official WCAG certification
        or a complete security assessment. Manual testing
        is also necessary.
        """
    )



if __name__ == "__main__":
    app.launch(
        server_name="0.0.0.0",
        server_port=int(os.environ.get("PORT", 7860))
    )

