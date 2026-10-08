"""
Report Generator for Web Shield
Generates downloadable PDF reports using ReportLab.
"""

import io
import os
from datetime import datetime

try:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.colors import (
        HexColor, white, black, Color
    )
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


def generate_pdf_report(scan_job, findings, summary):
    """
    Generate a PDF vulnerability report for a scan.
    Returns bytes of the PDF file.
    """
    if not REPORTLAB_AVAILABLE:
        return _generate_text_report(scan_job, findings, summary)

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=2*cm,
        leftMargin=2*cm,
        topMargin=2*cm,
        bottomMargin=2*cm,
        title=f'Web Shield Security Report - {scan_job.target_url}',
    )

    styles = getSampleStyleSheet()

    # Custom styles
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Title'],
        fontSize=26,
        textColor=HexColor('#0A84FF'),
        spaceAfter=6,
        fontName='Helvetica-Bold',
    )
    subtitle_style = ParagraphStyle(
        'Subtitle',
        parent=styles['Normal'],
        fontSize=12,
        textColor=HexColor('#888888'),
        spaceAfter=20,
    )
    section_style = ParagraphStyle(
        'Section',
        parent=styles['Heading1'],
        fontSize=16,
        textColor=HexColor('#1C1C1E'),
        spaceBefore=20,
        spaceAfter=10,
        fontName='Helvetica-Bold',
    )
    body_style = ParagraphStyle(
        'Body',
        parent=styles['Normal'],
        fontSize=10,
        textColor=HexColor('#3A3A3C'),
        spaceAfter=6,
        leading=14,
    )
    finding_title_style = ParagraphStyle(
        'FindingTitle',
        parent=styles['Normal'],
        fontSize=11,
        fontName='Helvetica-Bold',
        spaceAfter=4,
    )
    small_style = ParagraphStyle(
        'Small',
        parent=styles['Normal'],
        fontSize=9,
        textColor=HexColor('#636366'),
        spaceAfter=4,
    )

    story = []

    # ── COVER PAGE ──────────────────────────────────
    story.append(Spacer(1, 1*cm))
    story.append(Paragraph('🛡️ Web Shield', title_style))
    story.append(Paragraph('Vulnerability Assessment Report', subtitle_style))
    story.append(HRFlowable(width='100%', thickness=2, color=HexColor('#0A84FF')))
    story.append(Spacer(1, 0.5*cm))

    # Target info table
    risk_color = RISK_COLORS.get(scan_job.risk_level, '#888888')
    cover_data = [
        ['Target URL', scan_job.target_url],
        ['Scan Date', scan_job.created_at.strftime('%B %d, %Y %H:%M') if scan_job.created_at else '-'],
        ['Security Score', f'{scan_job.security_score:.1f} / 100' if scan_job.security_score is not None else '-'],
        ['Risk Level', scan_job.risk_level or '-'],
        ['Scanned By', scan_job.user.get_full_name() or scan_job.user.username],
        ['Report Generated', datetime.now().strftime('%B %d, %Y %H:%M')],
    ]
    cover_table = Table(cover_data, colWidths=[5*cm, 12*cm])
    cover_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, -1), HexColor('#F2F2F7')),
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('PADDING', (0, 0), (-1, -1), 8),
        ('ROWBACKGROUNDS', (1, 0), (1, -1), [white, HexColor('#FAFAFA')]),
        ('GRID', (0, 0), (-1, -1), 0.5, HexColor('#E5E5EA')),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
    ]))
    story.append(cover_table)
    story.append(Spacer(1, 0.5*cm))

    # ── EXECUTIVE SUMMARY ───────────────────────────
    story.append(Paragraph('Executive Summary', section_style))
    story.append(HRFlowable(width='100%', thickness=1, color=HexColor('#E5E5EA')))
    story.append(Spacer(1, 0.3*cm))

    severity_summary = summary.get('severity_summary', {})
    summary_data = [
        ['Severity', 'Count'],
        ['🔴 Critical', str(severity_summary.get('critical', 0))],
        ['🟠 High', str(severity_summary.get('high', 0))],
        ['🟡 Medium', str(severity_summary.get('medium', 0))],
        ['🟢 Low', str(severity_summary.get('low', 0))],
        ['ℹ️ Info', str(severity_summary.get('info', 0))],
        ['Total Findings', str(sum(severity_summary.values()))],
    ]
    sum_table = Table(summary_data, colWidths=[8*cm, 9*cm])
    sum_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), HexColor('#0A84FF')),
        ('TEXTCOLOR', (0, 0), (-1, 0), white),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('PADDING', (0, 0), (-1, -1), 8),
        ('ROWBACKGROUNDS', (0, 1), (-1, -2), [white, HexColor('#F2F2F7')]),
        ('BACKGROUND', (0, -1), (-1, -1), HexColor('#1C1C1E')),
        ('TEXTCOLOR', (0, -1), (-1, -1), white),
        ('FONTNAME', (0, -1), (-1, -1), 'Helvetica-Bold'),
        ('GRID', (0, 0), (-1, -1), 0.5, HexColor('#E5E5EA')),
        ('ALIGN', (1, 0), (1, -1), 'CENTER'),
    ]))
    story.append(sum_table)
    story.append(Spacer(1, 0.5*cm))

    # ── DETAILED FINDINGS ───────────────────────────
    story.append(PageBreak())
    story.append(Paragraph('Detailed Findings', section_style))
    story.append(HRFlowable(width='100%', thickness=1, color=HexColor('#E5E5EA')))
    story.append(Spacer(1, 0.3*cm))

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

        sev_color = HexColor(SEVERITY_COLORS.get(sev, '#888888'))
        sev_header = Paragraph(
            f'<font color="#{SEVERITY_COLORS.get(sev, "888888")[1:]}">'
            f'{sev.upper()} ({len(sev_findings)} findings)</font>',
            ParagraphStyle('SevHeader', parent=styles['Heading2'], fontSize=13,
                           fontName='Helvetica-Bold', spaceBefore=15, spaceAfter=8)
        )
        story.append(sev_header)

        for f in sev_findings:
            if sev == 'info':
                continue
            finding_num += 1
            block = []

            # Finding title bar
            title_color = SEVERITY_COLORS.get(sev, '#888888')
            finding_data = [[
                Paragraph(
                    f'<b>#{finding_num} {f.get("title", "Finding")}</b>',
                    ParagraphStyle('FTitle', parent=styles['Normal'], fontSize=10,
                                   fontName='Helvetica-Bold', textColor=white)
                )
            ]]
            finding_header = Table(finding_data, colWidths=[17*cm])
            finding_header.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, -1), HexColor(title_color)),
                ('PADDING', (0, 0), (-1, -1), 8),
                ('ROUNDEDCORNERS', [4, 4, 0, 0]),
            ]))
            block.append(finding_header)

            # Details table
            details_data = []
            if f.get('description'):
                details_data.append(['Description', Paragraph(f['description'], body_style)])
            if f.get('impact'):
                details_data.append(['Impact', Paragraph(f['impact'], body_style)])
            if f.get('remediation'):
                details_data.append(['Remediation', Paragraph(f['remediation'], body_style)])
            if f.get('evidence'):
                details_data.append(['Evidence', Paragraph(f'<i>{f["evidence"]}</i>', small_style)])
            if f.get('plugin'):
                details_data.append(['Plugin', Paragraph(f['plugin'], small_style)])

            if details_data:
                details_table = Table(details_data, colWidths=[3.5*cm, 13.5*cm])
                details_table.setStyle(TableStyle([
                    ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, -1), 9),
                    ('PADDING', (0, 0), (-1, -1), 6),
                    ('BACKGROUND', (0, 0), (0, -1), HexColor('#F2F2F7')),
                    ('GRID', (0, 0), (-1, -1), 0.5, HexColor('#E5E5EA')),
                    ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ]))
                block.append(details_table)

            block.append(Spacer(1, 0.4*cm))
            story.append(KeepTogether(block))

    # ── FOOTER ──────────────────────────────────────
    story.append(Spacer(1, 1*cm))
    story.append(HRFlowable(width='100%', thickness=1, color=HexColor('#E5E5EA')))
    story.append(Paragraph(
        'Generated by Web Shield Vulnerability Scanner | For authorized use only',
        ParagraphStyle('Footer', parent=styles['Normal'], fontSize=8,
                       textColor=HexColor('#8E8E93'), alignment=TA_CENTER)
    ))

    doc.build(story)
    return buffer.getvalue()


def _generate_text_report(scan_job, findings, summary):
    """Fallback text report if ReportLab is not available."""
    lines = [
        '=' * 60,
        'WEB SHIELD - VULNERABILITY ASSESSMENT REPORT',
        '=' * 60,
        f'Target: {scan_job.target_url}',
        f'Date: {scan_job.created_at}',
        f'Score: {scan_job.security_score}/100',
        f'Risk Level: {scan_job.risk_level}',
        '=' * 60,
        'FINDINGS:',
    ]
    for f in findings:
        if f.get('severity') != 'info':
            lines.append(f"\n[{f['severity'].upper()}] {f.get('title', '')}")
            lines.append(f"  {f.get('description', '')}")
            lines.append(f"  Remediation: {f.get('remediation', '')}")

    return '\n'.join(lines).encode('utf-8')
