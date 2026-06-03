"""
pdf_exporter.py
Generates a professional PhishGuard PDF analysis report using ReportLab.

The report includes:
  - Cover header with tool branding and scan metadata
  - Risk score gauge bar and level badge
  - Threat classifications with MITRE ATT&CK references
  - Per-category findings table (Header / URL / Body)
  - Verdict and disclaimer footer
"""

import os
from datetime import datetime

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, KeepTogether,
)
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT


# ---------------------------------------------------------------------------
# Brand palette
# ---------------------------------------------------------------------------

BRAND_DARK       = colors.HexColor("#0D1117")
BRAND_BLUE       = colors.HexColor("#1E6FA8")
BRAND_LIGHT_BLUE = colors.HexColor("#5BC8F5")
GRAY_BG          = colors.HexColor("#F6F8FA")
GRAY_BORDER      = colors.HexColor("#D0D7DE")
GRAY_TEXT        = colors.HexColor("#57606A")

COLOR_CRITICAL = colors.HexColor("#FF3B3B")
COLOR_HIGH     = colors.HexColor("#FF6B35")
COLOR_MEDIUM   = colors.HexColor("#FFB347")
COLOR_LOW      = colors.HexColor("#4CAF50")
COLOR_OK       = colors.HexColor("#4CAF50")

SEVERITY_COLORS = {
    "HIGH":   COLOR_HIGH,
    "MEDIUM": COLOR_MEDIUM,
    "LOW":    COLOR_LOW,
}

RISK_COLORS = {
    "CRITICAL": COLOR_CRITICAL,
    "HIGH":     COLOR_HIGH,
    "MEDIUM":   COLOR_MEDIUM,
    "LOW":      COLOR_LOW,
}

CONFIDENCE_COLORS = {
    "HIGH":   COLOR_HIGH,
    "MEDIUM": COLOR_MEDIUM,
    "LOW":    COLOR_LOW,
}

PAGE_W, PAGE_H = A4
MARGIN = 18 * mm


# ---------------------------------------------------------------------------
# Style sheet
# ---------------------------------------------------------------------------

def _build_styles():
    base = getSampleStyleSheet()

    styles = {
        "title": ParagraphStyle(
            "title",
            fontName="Helvetica-Bold",
            fontSize=22,
            textColor=BRAND_LIGHT_BLUE,
            spaceAfter=2,
        ),
        "subtitle": ParagraphStyle(
            "subtitle",
            fontName="Helvetica",
            fontSize=11,
            textColor=GRAY_TEXT,
            spaceAfter=6,
        ),
        "section_heading": ParagraphStyle(
            "section_heading",
            fontName="Helvetica-Bold",
            fontSize=11,
            textColor=BRAND_BLUE,
            spaceBefore=10,
            spaceAfter=4,
            borderPad=2,
        ),
        "normal": ParagraphStyle(
            "normal",
            fontName="Helvetica",
            fontSize=9,
            textColor=colors.HexColor("#24292F"),
            leading=13,
            spaceAfter=2,
        ),
        "small_gray": ParagraphStyle(
            "small_gray",
            fontName="Helvetica",
            fontSize=8,
            textColor=GRAY_TEXT,
            leading=11,
        ),
        "verdict": ParagraphStyle(
            "verdict",
            fontName="Helvetica-BoldOblique",
            fontSize=10,
            textColor=colors.HexColor("#24292F"),
            leading=15,
        ),
        "footer": ParagraphStyle(
            "footer",
            fontName="Helvetica",
            fontSize=7,
            textColor=GRAY_TEXT,
            alignment=TA_CENTER,
        ),
        "mono": ParagraphStyle(
            "mono",
            fontName="Courier",
            fontSize=8,
            textColor=colors.HexColor("#24292F"),
            leading=11,
        ),
        "mitre": ParagraphStyle(
            "mitre",
            fontName="Helvetica-Oblique",
            fontSize=8,
            textColor=GRAY_TEXT,
            leading=11,
        ),
        "center": ParagraphStyle(
            "center",
            fontName="Helvetica",
            fontSize=9,
            alignment=TA_CENTER,
            textColor=colors.HexColor("#24292F"),
        ),
    }
    return styles


# ---------------------------------------------------------------------------
# Helper flowables
# ---------------------------------------------------------------------------

def _divider(color=GRAY_BORDER, thickness=0.5):
    return HRFlowable(width="100%", thickness=thickness, color=color, spaceAfter=6, spaceBefore=6)


def _spacer(h_mm=3):
    return Spacer(1, h_mm * mm)


def _risk_color(level: str):
    return RISK_COLORS.get(level.upper(), colors.gray)


def _score_bar_table(score: int, level: str, styles: dict):
    """Return a Table that renders a filled progress bar representing the score."""
    bar_width = PAGE_W - 2 * MARGIN
    filled = bar_width * (score / 100)
    empty  = bar_width - filled
    risk_c = _risk_color(level)

    # Build as a two-cell wide table inside a colored wrapper
    bar_data = [["", ""]]
    bar_style = TableStyle([
        ("BACKGROUND",  (0, 0), (0, 0), risk_c),
        ("BACKGROUND",  (1, 0), (1, 0), GRAY_BORDER),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [None]),
        ("LEFTPADDING",  (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (-1, -1), 0),
        ("TOPPADDING",   (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 0),
    ])
    return Table(bar_data, colWidths=[filled, empty], rowHeights=[8],
                 style=bar_style)


# ---------------------------------------------------------------------------
# Section builders
# ---------------------------------------------------------------------------

def _build_header_block(story, score, level, verdict, classifications,
                        email_subject, email_from, filename, styles):
    """Top section: branding, scan info, score card."""

    # Branding header background table
    header_data = [[
        Paragraph("🛡  PhishGuard", styles["title"]),
        Paragraph("Email Threat Analysis Report", styles["subtitle"]),
    ]]
    header_tbl = Table(header_data, colWidths=[PAGE_W * 0.45 - MARGIN, PAGE_W * 0.55 - MARGIN])
    header_tbl.setStyle(TableStyle([
        ("BACKGROUND",   (0, 0), (-1, -1), BRAND_DARK),
        ("LEFTPADDING",  (0, 0), (-1, -1), 10),
        ("RIGHTPADDING", (0, 0), (-1, -1), 10),
        ("TOPPADDING",   (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 10),
        ("VALIGN",       (0, 0), (-1, -1), "MIDDLE"),
    ]))
    story.append(header_tbl)
    story.append(_spacer(4))

    # Scan metadata row
    now = datetime.now().strftime("%Y-%m-%d  %H:%M:%S")
    meta_rows = [
        ["Analyzed",  now],
        ["Source",    filename or "Pasted content"],
        ["Subject",   (email_subject or "(none)")[:80]],
        ["From",      (email_from or "(unknown)")[:80]],
    ]
    meta_data  = [[Paragraph(k, styles["small_gray"]), Paragraph(v, styles["normal"])]
                  for k, v in meta_rows]
    meta_tbl   = Table(meta_data, colWidths=[28 * mm, PAGE_W - 2 * MARGIN - 28 * mm])
    meta_tbl.setStyle(TableStyle([
        ("LEFTPADDING",  (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING",   (0, 0), (-1, -1), 2),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 2),
        ("BACKGROUND",   (0, 0), (-1, -1), GRAY_BG),
        ("GRID",         (0, 0), (-1, -1), 0.3, GRAY_BORDER),
    ]))
    story.append(meta_tbl)
    story.append(_spacer(5))

    # Score card
    risk_c     = _risk_color(level)
    score_data = [[
        Paragraph(f'<font size="38" color="{risk_c.hexval()}">'
                  f'<b>{score}</b></font>'
                  f'<font size="16" color="#888888"> / 100</font>', styles["center"]),
        Paragraph(f'<font size="18"><b>{level}</b></font>', ParagraphStyle(
            "risklevel", fontName="Helvetica-Bold", fontSize=18,
            textColor=risk_c, spaceAfter=4)),
        Paragraph(verdict, styles["verdict"]),
    ]]
    score_tbl = Table(score_data,
                      colWidths=[32 * mm, 40 * mm, PAGE_W - 2 * MARGIN - 72 * mm])
    score_tbl.setStyle(TableStyle([
        ("BACKGROUND",   (0, 0), (-1, -1), GRAY_BG),
        ("BOX",          (0, 0), (-1, -1), 1.0, risk_c),
        ("LEFTPADDING",  (0, 0), (-1, -1), 10),
        ("RIGHTPADDING", (0, 0), (-1, -1), 10),
        ("TOPPADDING",   (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 10),
        ("VALIGN",       (0, 0), (-1, -1), "MIDDLE"),
        ("LINEAFTER",    (0, 0), (1, 0),   0.5, GRAY_BORDER),
    ]))
    story.append(score_tbl)
    story.append(_spacer(2))

    # Score progress bar
    story.append(_score_bar_table(score, level, styles))
    story.append(_spacer(6))


def _build_classification_block(story, classifications, styles):
    """Threat classification cards with MITRE ATT&CK references."""
    story.append(Paragraph("THREAT CLASSIFICATION", styles["section_heading"]))
    story.append(_divider(BRAND_BLUE, thickness=1))

    if not classifications:
        story.append(Paragraph("No threat classification — email appears benign.", styles["normal"]))
        story.append(_spacer(3))
        return

    for clf in classifications:
        conf_color = CONFIDENCE_COLORS.get(clf["confidence"], colors.gray)

        clf_data = [[
            # Label + confidence badge column
            Table([
                [Paragraph(f'<b>{clf["label"]}</b>', ParagraphStyle(
                    "clf_label", fontName="Helvetica-Bold", fontSize=10,
                    textColor=colors.HexColor("#24292F")))],
                [Paragraph(f'Confidence: <b>{clf["confidence"]}</b>', ParagraphStyle(
                    "clf_conf", fontName="Helvetica-Bold", fontSize=8,
                    textColor=conf_color))],
            ], colWidths=[58 * mm]),
            # Rationale + MITRE column
            Table([
                [Paragraph(clf["rationale"], styles["normal"])],
                [Paragraph(clf["mitre"], styles["mitre"])],
            ], colWidths=[PAGE_W - 2 * MARGIN - 58 * mm - 4]),
        ]]

        clf_tbl = Table(clf_data,
                        colWidths=[58 * mm, PAGE_W - 2 * MARGIN - 58 * mm])
        clf_tbl.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, -1), GRAY_BG),
            ("BOX",           (0, 0), (-1, -1), 0.5, GRAY_BORDER),
            ("LINEAFTER",     (0, 0), (0, 0),   0.5, GRAY_BORDER),
            ("LEFTBORDER",    (0, 0), (0, -1),  2.0, conf_color),
            ("LEFTPADDING",   (0, 0), (-1, -1), 8),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 8),
            ("TOPPADDING",    (0, 0), (-1, -1), 7),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
            ("VALIGN",        (0, 0), (-1, -1), "TOP"),
        ]))
        story.append(KeepTogether([clf_tbl, _spacer(2)]))

    story.append(_spacer(4))


def _build_findings_block(story, findings, styles):
    """Per-category findings tables."""
    story.append(Paragraph("DETAILED FINDINGS", styles["section_heading"]))
    story.append(_divider(BRAND_BLUE, thickness=1))

    # Summary counts row
    high   = sum(1 for f in findings if f["severity"] == "HIGH")
    medium = sum(1 for f in findings if f["severity"] == "MEDIUM")
    low    = sum(1 for f in findings if f["severity"] == "LOW")

    sum_data = [[
        Paragraph(f'<b>{len(findings)}</b>  Total', styles["normal"]),
        Paragraph(f'<font color="{COLOR_HIGH.hexval()}"><b>{high}</b></font>  HIGH',   styles["normal"]),
        Paragraph(f'<font color="{COLOR_MEDIUM.hexval()}"><b>{medium}</b></font>  MEDIUM', styles["normal"]),
        Paragraph(f'<font color="{COLOR_LOW.hexval()}"><b>{low}</b></font>  LOW',      styles["normal"]),
    ]]
    sum_tbl = Table(sum_data, colWidths=[(PAGE_W - 2 * MARGIN) / 4] * 4)
    sum_tbl.setStyle(TableStyle([
        ("BACKGROUND",   (0, 0), (-1, -1), GRAY_BG),
        ("BOX",          (0, 0), (-1, -1), 0.5, GRAY_BORDER),
        ("INNERGRID",    (0, 0), (-1, -1), 0.3, GRAY_BORDER),
        ("LEFTPADDING",  (0, 0), (-1, -1), 10),
        ("TOPPADDING",   (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 6),
    ]))
    story.append(sum_tbl)
    story.append(_spacer(5))

    # One table per category
    categories = [
        ("Header", "HEADER ANALYSIS",  colors.HexColor("#A78BFA")),
        ("URL",    "URL ANALYSIS",     colors.HexColor("#38BDF8")),
        ("Body",   "BODY ANALYSIS",    colors.HexColor("#FB923C")),
    ]

    for cat_key, cat_title, cat_color in categories:
        cat_findings = [f for f in findings if f["category"] == cat_key]

        # Section sub-header
        hdr_data = [[Paragraph(cat_title, ParagraphStyle(
            "cat_hdr", fontName="Helvetica-Bold", fontSize=10,
            textColor=colors.white))]]
        hdr_tbl = Table(hdr_data, colWidths=[PAGE_W - 2 * MARGIN])
        hdr_tbl.setStyle(TableStyle([
            ("BACKGROUND",   (0, 0), (-1, -1), cat_color),
            ("LEFTPADDING",  (0, 0), (-1, -1), 8),
            ("TOPPADDING",   (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING",(0, 0), (-1, -1), 5),
        ]))
        story.append(hdr_tbl)

        if not cat_findings:
            ok_data = [[Paragraph("✓  No issues detected in this category.", ParagraphStyle(
                "ok", fontName="Helvetica", fontSize=9, textColor=COLOR_OK))]]
            ok_tbl = Table(ok_data, colWidths=[PAGE_W - 2 * MARGIN])
            ok_tbl.setStyle(TableStyle([
                ("BACKGROUND",   (0, 0), (-1, -1), GRAY_BG),
                ("BOX",          (0, 0), (-1, -1), 0.3, GRAY_BORDER),
                ("LEFTPADDING",  (0, 0), (-1, -1), 10),
                ("TOPPADDING",   (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING",(0, 0), (-1, -1), 6),
            ]))
            story.append(ok_tbl)
        else:
            # Column header row
            col_hdr = [[
                Paragraph("<b>SEV</b>",    styles["small_gray"]),
                Paragraph("<b>DETAIL</b>", styles["small_gray"]),
            ]]
            rows = list(col_hdr)
            for f in cat_findings:
                sev_c = SEVERITY_COLORS.get(f["severity"], colors.gray)
                rows.append([
                    Paragraph(f'<font color="{sev_c.hexval()}"><b>{f["severity"]}</b></font>',
                               styles["normal"]),
                    Paragraph(f["detail"], styles["normal"]),
                ])

            col_widths = [18 * mm, PAGE_W - 2 * MARGIN - 18 * mm]
            findings_tbl = Table(rows, colWidths=col_widths, repeatRows=1)
            findings_tbl.setStyle(TableStyle([
                ("BACKGROUND",   (0, 0), (-1, 0),  GRAY_BG),
                ("BACKGROUND",   (0, 1), (-1, -1), colors.white),
                ("ROWBACKGROUNDS",(0, 1),(-1,-1), [colors.white, GRAY_BG]),
                ("BOX",          (0, 0), (-1, -1), 0.3, GRAY_BORDER),
                ("INNERGRID",    (0, 0), (-1, -1), 0.3, GRAY_BORDER),
                ("LEFTPADDING",  (0, 0), (-1, -1), 8),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING",   (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING",(0, 0), (-1, -1), 4),
                ("VALIGN",       (0, 0), (-1, -1), "TOP"),
            ]))
            story.append(findings_tbl)

        story.append(_spacer(4))


def _build_footer_block(story, styles):
    """Disclaimer and branding footer."""
    story.append(_divider())
    story.append(Paragraph(
        "This report was generated by PhishGuard for <b>educational and security awareness purposes only</b>. "
        "Static analysis may not detect all phishing attempts. Always verify suspicious emails through "
        "official channels. Do not use this tool as a sole security control.",
        styles["footer"],
    ))
    story.append(_spacer(1))
    story.append(Paragraph(
        f"PhishGuard v1.0  ·  Generated {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  ·  Offline Analysis",
        styles["footer"],
    ))


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def export_pdf(
    output_path: str,
    findings: list[dict],
    score: int,
    level: str,
    verdict: str,
    classifications: list[dict],
    email_subject: str = "",
    email_from: str = "",
    filename: str = "",
) -> str:
    """
    Generate a PDF report and save it to output_path.
    Returns the absolute path of the saved file.
    """
    styles = _build_styles()

    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        leftMargin=MARGIN,
        rightMargin=MARGIN,
        topMargin=MARGIN,
        bottomMargin=MARGIN,
        title="PhishGuard Analysis Report",
        author="PhishGuard",
        subject=f"Phishing Analysis — {level} Risk",
    )

    story = []

    _build_header_block(
        story, score, level, verdict, classifications,
        email_subject, email_from, filename, styles,
    )
    _build_classification_block(story, classifications, styles)
    _build_findings_block(story, findings, styles)
    _build_footer_block(story, styles)

    doc.build(story)
    return os.path.abspath(output_path)
