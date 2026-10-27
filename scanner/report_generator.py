"""
Report Generator for Web Shield
Generates downloadable PDF reports with ReportLab (or pure-Python PDF fallback).
"""

import io
import re
import html
from datetime import datetime

try:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.colors import HexColor, white, black
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
        HRFlowable, KeepTogether, PageBreak
    )
    from reportlab.lib.units import cm, mm
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False


SEVERITY_COLORS = {
    'critical': '#FF2D55',
    'high':     '#FF6B35',
    'medium':   '#FFD60A',
    'low':      '#30D158',
    'info':     '#0A84FF',
}

RISK_COLORS = {
    'Critical': '#FF2D55',
    'High':     '#FF6B35',
    'Medium':   '#FFD60A',
    'Low':      '#30D158',
}


def safe_text(val):
    """Escape XML characters for ReportLab Paragraphs and clean Unicode."""
    if val is None:
        return ''
    s = str(val)
    # Strip emojis that Helvetica cannot render
    s = s.encode('ascii', 'xmlcharrefreplace').decode('ascii')
    return html.escape(s, quote=False)


def generate_pdf_report(scan_job, findings, summary):
    """
    Generate a PDF vulnerability report for a scan.
    Returns bytes of a valid PDF file.
    """
    if REPORTLAB_AVAILABLE:
        try:
            return _generate_reportlab_pdf(scan_job, findings, summary)
        except Exception as e:
            # Fall back to pure-Python PDF if ReportLab encounters any layout/font issue
            return _generate_pure_pdf(scan_job, findings, summary)
    else:
        return _generate_pure_pdf(scan_job, findings, summary)


def _generate_reportlab_pdf(scan_job, findings, summary):
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=1.8*cm,
        leftMargin=1.8*cm,
        topMargin=1.8*cm,
        bottomMargin=1.8*cm,
        title=f'Web Shield Report - {scan_job.target_url}',
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Title'],
        fontSize=24,
        textColor=HexColor('#0A84FF'),
        spaceAfter=4,
        fontName='Helvetica-Bold',
        alignment=TA_LEFT,
    )
    subtitle_style = ParagraphStyle(
        'Subtitle',
        parent=styles['Normal'],
        fontSize=11,
        textColor=HexColor('#888888'),
        spaceAfter=16,
    )
    section_style = ParagraphStyle(
        'Section',
        parent=styles['Heading1'],
        fontSize=15,
        textColor=HexColor('#1C1C1E'),
        spaceBefore=16,
        spaceAfter=8,
        fontName='Helvetica-Bold',
    )
    body_style = ParagraphStyle(
        'Body',
        parent=styles['Normal'],
        fontSize=9,
        textColor=HexColor('#3A3A3C'),
        spaceAfter=4,
        leading=13,
    )
    small_style = ParagraphStyle(
        'Small',
        parent=styles['Normal'],
        fontSize=8,
        textColor=HexColor('#636366'),
        spaceAfter=2,
        leading=11,
    )

    story = []

    # ── COVER / HEADER ──────────────────────────────
    story.append(Paragraph('Web Shield', title_style))
    story.append(Paragraph('Automated Vulnerability Assessment Report', subtitle_style))
    story.append(HRFlowable(width='100%', thickness=2, color=HexColor('#0A84FF'), spaceAfter=14))

    # Target info table
    user_name = scan_job.user.get_full_name() or scan_job.user.username if scan_job.user else 'Anonymous'
    scan_date = scan_job.created_at.strftime('%B %d, %Y %H:%M') if scan_job.created_at else '-'
    score_str = f"{scan_job.security_score:.1f} / 100" if scan_job.security_score is not None else '-'
    risk_str = scan_job.risk_level or 'Unknown'

    cover_data = [
        ['Target URL', Paragraph(safe_text(scan_job.target_url), body_style)],
        ['Scan Date', scan_date],
        ['Security Score', score_str],
        ['Risk Level', risk_str],
        ['Scanned By', user_name],
        ['Report Generated', datetime.now().strftime('%B %d, %Y %H:%M')],
    ]
    cover_table = Table(cover_data, colWidths=[4.5*cm, 12.5*cm])
    cover_table_style = [
        ('BACKGROUND', (0, 0), (0, -1), HexColor('#F2F2F7')),
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('LEFTPADDING', (0, 0), (-1, -1), 8),
        ('RIGHTPADDING', (0, 0), (-1, -1), 8),
        ('GRID', (0, 0), (-1, -1), 0.5, HexColor('#E5E5EA')),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
    ]
    for row_i in range(len(cover_data)):
        bg = white if row_i % 2 == 0 else HexColor('#FAFAFA')
        cover_table_style.append(('BACKGROUND', (1, row_i), (1, row_i), bg))

    cover_table.setStyle(TableStyle(cover_table_style))
    story.append(cover_table)
    story.append(Spacer(1, 0.4*cm))

    # ── EXECUTIVE SUMMARY ───────────────────────────
    story.append(Paragraph('Executive Summary', section_style))
    story.append(HRFlowable(width='100%', thickness=1, color=HexColor('#E5E5EA'), spaceAfter=8))

    severity_summary = summary.get('severity_summary', {})
    if not severity_summary and findings:
        severity_summary = {
            'critical': sum(1 for f in findings if f.get('severity') == 'critical'),
            'high': sum(1 for f in findings if f.get('severity') == 'high'),
            'medium': sum(1 for f in findings if f.get('severity') == 'medium'),
            'low': sum(1 for f in findings if f.get('severity') == 'low'),
            'info': sum(1 for f in findings if f.get('severity') == 'info'),
        }

    summary_data = [
        ['Severity Level', 'Findings Count'],
        ['CRITICAL', str(severity_summary.get('critical', 0))],
        ['HIGH', str(severity_summary.get('high', 0))],
        ['MEDIUM', str(severity_summary.get('medium', 0))],
        ['LOW', str(severity_summary.get('low', 0))],
        ['INFO', str(severity_summary.get('info', 0))],
        ['Total Findings', str(sum(severity_summary.values()))],
    ]
    sum_table = Table(summary_data, colWidths=[8*cm, 9*cm])
    sum_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), HexColor('#0A84FF')),
        ('TEXTCOLOR', (0, 0), (-1, 0), white),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('TOPPADDING', (0, 0), (-1, -1), 5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
        ('LEFTPADDING', (0, 0), (-1, -1), 8),
        ('RIGHTPADDING', (0, 0), (-1, -1), 8),
        ('BACKGROUND', (0, 1), (-1, 1), HexColor('#FFF0F2')),
        ('BACKGROUND', (0, 2), (-1, 2), HexColor('#FFF5EE')),
        ('BACKGROUND', (0, 3), (-1, 3), HexColor('#FFFFF0')),
        ('BACKGROUND', (0, 4), (-1, 4), HexColor('#F0FFF4')),
        ('BACKGROUND', (0, 5), (-1, 5), HexColor('#F0F7FF')),
        ('BACKGROUND', (0, -1), (-1, -1), HexColor('#1C1C1E')),
        ('TEXTCOLOR', (0, -1), (-1, -1), white),
        ('FONTNAME', (0, -1), (-1, -1), 'Helvetica-Bold'),
        ('GRID', (0, 0), (-1, -1), 0.5, HexColor('#E5E5EA')),
        ('ALIGN', (1, 0), (1, -1), 'CENTER'),
    ]))
    story.append(sum_table)
    story.append(Spacer(1, 0.4*cm))

    # ── DETAILED FINDINGS ───────────────────────────
    story.append(PageBreak())
    story.append(Paragraph('Detailed Findings', section_style))
    story.append(HRFlowable(width='100%', thickness=1, color=HexColor('#E5E5EA'), spaceAfter=8))

    severity_order = ['critical', 'high', 'medium', 'low', 'info']
    grouped = {s: [] for s in severity_order}
    for f in findings:
        sev = f.get('severity', 'info')
        if sev in grouped:
            grouped[sev].append(f)

    finding_num = 0
    for sev in severity_order:
        sev_findings = grouped[sev]
        if not sev_findings:
            continue

        sev_header = Paragraph(
            f'<font color="{SEVERITY_COLORS.get(sev, "#888888")}"><b>{sev.upper()} ({len(sev_findings)} findings)</b></font>',
            ParagraphStyle('SevHeader', parent=styles['Heading2'], fontSize=12,
                           fontName='Helvetica-Bold', spaceBefore=12, spaceAfter=6)
        )
        story.append(sev_header)

        for f in sev_findings:
            finding_num += 1
            block = []

            # Finding title bar
            title_color = SEVERITY_COLORS.get(sev, '#888888')
            safe_title = safe_text(f.get('title', 'Security Finding'))
            title_p = Paragraph(
                f'<b>#{finding_num} [{sev.upper()}] {safe_title}</b>',
                ParagraphStyle('FTitle', parent=styles['Normal'], fontSize=9,
                               fontName='Helvetica-Bold', textColor=white)
            )
            finding_header = Table([[title_p]], colWidths=[17*cm])
            finding_header.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, -1), HexColor(title_color)),
                ('TOPPADDING', (0, 0), (-1, -1), 5),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
                ('LEFTPADDING', (0, 0), (-1, -1), 8),
                ('RIGHTPADDING', (0, 0), (-1, -1), 8),
            ]))
            block.append(finding_header)

            # Details table
            details_data = []
            if f.get('description'):
                details_data.append(['Description', Paragraph(safe_text(f['description']), body_style)])
            if f.get('impact'):
                details_data.append(['Impact', Paragraph(safe_text(f['impact']), body_style)])
            if f.get('remediation'):
                details_data.append(['Remediation', Paragraph(safe_text(f['remediation']), body_style)])
            if f.get('evidence'):
                evidence_text = safe_text(str(f['evidence'])[:400])
                details_data.append(['Evidence', Paragraph(f'<code>{evidence_text}</code>', small_style)])
            if f.get('plugin'):
                details_data.append(['Module', Paragraph(safe_text(f['plugin']), small_style)])

            if details_data:
                details_table = Table(details_data, colWidths=[3.2*cm, 13.8*cm])
                details_table.setStyle(TableStyle([
                    ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, -1), 8),
                    ('TOPPADDING', (0, 0), (-1, -1), 4),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                    ('LEFTPADDING', (0, 0), (-1, -1), 6),
                    ('RIGHTPADDING', (0, 0), (-1, -1), 6),
                    ('BACKGROUND', (0, 0), (0, -1), HexColor('#F2F2F7')),
                    ('GRID', (0, 0), (-1, -1), 0.5, HexColor('#E5E5EA')),
                    ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ]))
                block.append(details_table)

            block.append(Spacer(1, 0.3*cm))
            story.append(KeepTogether(block))

    # ── FOOTER ──────────────────────────────────────
    story.append(Spacer(1, 0.8*cm))
    story.append(HRFlowable(width='100%', thickness=1, color=HexColor('#E5E5EA'), spaceAfter=6))
    story.append(Paragraph(
        'Generated by Web Shield Vulnerability Scanner | Confidential Security Report',
        ParagraphStyle('Footer', parent=styles['Normal'], fontSize=8,
                       textColor=HexColor('#8E8E93'), alignment=TA_CENTER)
    ))

    doc.build(story)
    return buffer.getvalue()


def _escape_pdf_text(s):
    """Escape text for PDF stream syntax."""
    if s is None:
        return ''
    s = str(s).encode('ascii', 'replace').decode('ascii')
    return s.replace('\\', '\\\\').replace('(', '\\(').replace(')', '\\)')


def _generate_pure_pdf(scan_job, findings, summary):
    """
    Robust pure-Python PDF generator that produces valid PDF-1.4 documents
    without any third-party dependencies (like ReportLab).
    """
    pages = []
    
    # Calculate summary
    crit_count = sum(1 for f in findings if f.get('severity') == 'critical')
    high_count = sum(1 for f in findings if f.get('severity') == 'high')
    med_count = sum(1 for f in findings if f.get('severity') == 'medium')
    low_count = sum(1 for f in findings if f.get('severity') == 'low')
    info_count = sum(1 for f in findings if f.get('severity') == 'info')
    
    date_str = scan_job.created_at.strftime('%Y-%m-%d %H:%M') if scan_job.created_at else '-'
    score_str = f"{scan_job.security_score:.1f}/100" if scan_job.security_score is not None else '-'
    risk_str = scan_job.risk_level or 'Unknown'
    user_name = scan_job.user.username if scan_job.user else 'Anonymous'

    # ── PAGE 1: Overview ────────────────────────────
    p1 = []
    # Header bar
    p1.append("0.039 0.518 1.000 rg 40 780 515 45 re f")  # Blue header
    p1.append("BT /F2 20 Tf 1 1 1 rg 55 795 Td (Web Shield - Security Assessment Report) Tj ET")
    
    # Target Overview Box
    p1.append("0.95 0.95 0.97 rg 40 640 515 120 re f")
    p1.append("0.85 0.85 0.88 RG 1 w 40 640 515 120 re s")
    
    p1.append("BT /F2 13 Tf 0.1 0.1 0.1 rg 55 735 Td (TARGET OVERVIEW) Tj ET")
    p1.append(f"BT /F1 10 Tf 0.2 0.2 0.2 rg 55 715 Td (Target URL:      {_escape_pdf_text(scan_job.target_url)[:65]}) Tj ET")
    p1.append(f"BT /F1 10 Tf 0.2 0.2 0.2 rg 55 698 Td (Scan Date:       {_escape_pdf_text(date_str)}) Tj ET")
    p1.append(f"BT /F1 10 Tf 0.2 0.2 0.2 rg 55 681 Td (Security Score:  {_escape_pdf_text(score_str)}    Risk Level: {_escape_pdf_text(risk_str)}) Tj ET")
    p1.append(f"BT /F1 10 Tf 0.2 0.2 0.2 rg 55 664 Td (Scanned By:      {_escape_pdf_text(user_name)}) Tj ET")

    # Executive Summary Box
    p1.append("0.95 0.95 0.97 rg 40 480 515 140 re f")
    p1.append("0.85 0.85 0.88 RG 1 w 40 480 515 140 re s")
    p1.append("BT /F2 13 Tf 0.1 0.1 0.1 rg 55 595 Td (EXECUTIVE SUMMARY) Tj ET")
    p1.append(f"BT /F2 10 Tf 1 0.18 0.33 rg 55 575 Td (  Critical Vulnerabilities:  {crit_count}) Tj ET")
    p1.append(f"BT /F2 10 Tf 1 0.42 0.21 rg 55 558 Td (  High Vulnerabilities:      {high_count}) Tj ET")
    p1.append(f"BT /F2 10 Tf 1 0.84 0.04 rg 55 541 Td (  Medium Vulnerabilities:    {med_count}) Tj ET")
    p1.append(f"BT /F2 10 Tf 0.19 0.82 0.35 rg 55 524 Td (  Low Vulnerabilities:       {low_count}) Tj ET")
    p1.append(f"BT /F2 10 Tf 0.04 0.52 1 rg 55 507 Td (  Informational Notes:       {info_count}) Tj ET")
    p1.append(f"BT /F2 10 Tf 0.1 0.1 0.1 rg 55 490 Td (  Total Issues Discovered:   {len(findings)}) Tj ET")

    # Methodology info
    p1.append("BT /F2 11 Tf 0.1 0.1 0.1 rg 40 440 Td (Testing Methodology) Tj ET")
    p1.append("BT /F1 9 Tf 0.3 0.3 0.3 rg 40 420 Td (Web Shield performs non-destructive, passive and heuristic security testing across 10 core modules) Tj ET")
    p1.append("BT /F1 9 Tf 0.3 0.3 0.3 rg 40 405 Td (including HTTP headers, SSL/TLS certificates, open ports, cookie security flags, and input reflection.) Tj ET")

    # Footer
    p1.append("0.85 0.85 0.88 RG 1 w 40 50 515 0 re s")
    p1.append("BT /F1 8 Tf 0.5 0.5 0.5 rg 180 38 Td (Generated by Web Shield Vulnerability Scanner | Confidential Report) Tj ET")
    pages.append("\n".join(p1))

    # ── PAGE 2+: Findings ───────────────────────────
    lines_per_page = 24
    curr_y = 780
    curr_page = []

    def start_new_findings_page():
        nonlocal curr_page, curr_y
        curr_page = []
        curr_page.append("0.039 0.518 1.000 rg 40 790 515 25 re f")
        curr_page.append("BT /F2 12 Tf 1 1 1 rg 55 798 Td (Web Shield - Detailed Findings Continued) Tj ET")
        curr_page.append("0.85 0.85 0.88 RG 1 w 40 50 515 0 re s")
        curr_page.append("BT /F1 8 Tf 0.5 0.5 0.5 rg 180 38 Td (Generated by Web Shield Vulnerability Scanner | Confidential Report) Tj ET")
        curr_y = 760

    start_new_findings_page()

    finding_idx = 0
    for f in findings:
        finding_idx += 1
        sev = f.get('severity', 'info').upper()
        title = _escape_pdf_text(f.get('title', 'Security Finding'))[:70]
        desc = _escape_pdf_text(f.get('description', ''))[:95]
        remed = _escape_pdf_text(f.get('remediation', ''))[:95]

        # Check space
        if curr_y < 120:
            pages.append("\n".join(curr_page))
            start_new_findings_page()

        # Severity banner
        sev_color = "1 0.18 0.33" if sev == 'CRITICAL' else "1 0.42 0.21" if sev == 'HIGH' else "1 0.84 0.04" if sev == 'MEDIUM' else "0.19 0.82 0.35" if sev == 'LOW' else "0.04 0.52 1"
        curr_page.append(f"{sev_color} rg 40 {curr_y - 18} 515 18 re f")
        curr_page.append(f"BT /F2 9 Tf 1 1 1 rg 50 {curr_y - 13} Td (#{finding_idx} [{sev}] {title}) Tj ET")
        curr_y -= 22

        if desc:
            curr_page.append(f"BT /F1 8 Tf 0.2 0.2 0.2 rg 50 {curr_y - 10} Td (Description: {desc}) Tj ET")
            curr_y -= 14
        if remed:
            curr_page.append(f"BT /F1 8 Tf 0.1 0.4 0.1 rg 50 {curr_y - 10} Td (Fix:         {remed}) Tj ET")
            curr_y -= 14

        curr_y -= 8

    if curr_page:
        pages.append("\n".join(curr_page))

    # Assemble PDF Objects
    num_pages = len(pages)
    out = io.BytesIO()
    
    # 1: Catalog
    # 2: Pages
    # 3: Font F1 (Helvetica)
    # 4: Font F2 (Helvetica-Bold)
    # Page i: 4 + 2*i - 1
    # Content i: 4 + 2*i
    
    page_objs = []
    content_objs = []
    for i in range(num_pages):
        page_objs.append(5 + i * 2)
        content_objs.append(6 + i * 2)

    total_objs = 4 + num_pages * 2

    # Write header
    out.write(b"%PDF-1.4\n")
    offsets = [0] * (total_objs + 1)

    # Obj 1: Catalog
    offsets[1] = out.tell()
    out.write(b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n")

    # Obj 2: Pages
    kids_str = " ".join([f"{p} 0 R" for p in page_objs])
    offsets[2] = out.tell()
    out.write(f"2 0 obj\n<< /Type /Pages /Kids [{kids_str}] /Count {num_pages} >>\nendobj\n".encode('ascii'))

    # Obj 3: Font F1
    offsets[3] = out.tell()
    out.write(b"3 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n")

    # Obj 4: Font F2
    offsets[4] = out.tell()
    out.write(b"4 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>\nendobj\n")

    # Pages and Streams
    for i in range(num_pages):
        p_obj = page_objs[i]
        c_obj = content_objs[i]
        content_bytes = pages[i].encode('ascii', 'replace')

        # Page obj
        offsets[p_obj] = out.tell()
        out.write(
            f"{p_obj} 0 obj\n"
            f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595.28 841.89] "
            f"/Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> "
            f"/Contents {c_obj} 0 R >>\nendobj\n".encode('ascii')
        )

        # Content obj
        offsets[c_obj] = out.tell()
        out.write(
            f"{c_obj} 0 obj\n<< /Length {len(content_bytes)} >>\nstream\n".encode('ascii')
            + content_bytes
            + b"\nendstream\nendobj\n"
        )

    # xref
    xref_pos = out.tell()
    out.write(f"xref\n0 {total_objs + 1}\n0000000000 65535 f \n".encode('ascii'))
    for obj_i in range(1, total_objs + 1):
        out.write(f"{offsets[obj_i]:010d} 00000 n \n".encode('ascii'))

    # Trailer
    out.write(
        f"trailer\n<< /Size {total_objs + 1} /Root 1 0 R >>\nstartxref\n{xref_pos}\n%%EOF\n".encode('ascii')
    )

    return out.getvalue()
