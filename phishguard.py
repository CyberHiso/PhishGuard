#!/usr/bin/env python3
"""
phishguard.py
PhishGuard — Phishing Email Detector
Main entry point. Accepts email input via CLI file argument or interactive paste,
then runs all analyzers and prints a color-coded terminal report.

Usage:
    python phishguard.py                                   # paste mode (interactive)
    python phishguard.py path/to/email.eml                 # file mode
    python phishguard.py path/to/email.eml --export        # auto-named PDF export
    python phishguard.py path/to/email.eml --export report.pdf  # named PDF export
"""

import sys
import os
import email
import argparse
import textwrap
from datetime import datetime
from email import policy

from colorama import init, Fore, Style

from analyzers.header_analyzer import analyze_headers
from analyzers.url_analyzer import analyze_urls
from analyzers.body_analyzer import analyze_body, get_body_text
from utils.scorer import calculate_score, get_risk_level, get_verdict
from utils.classifier import classify_threat
from utils.pdf_exporter import export_pdf

# Initialize colorama — required for Windows ANSI color support
init(autoreset=True)

# Terminal width for the report banner
BANNER_WIDTH = 58


# ---------------------------------------------------------------------------
# Color helpers
# ---------------------------------------------------------------------------

def _severity_color(severity: str) -> str:
    return {
        "HIGH":   Fore.RED,
        "MEDIUM": Fore.YELLOW,
        "LOW":    Fore.CYAN,
    }.get(severity.upper(), Fore.WHITE)


def _risk_level_color(level: str) -> str:
    return {
        "CRITICAL": Fore.RED + Style.BRIGHT,
        "HIGH":     Fore.RED,
        "MEDIUM":   Fore.YELLOW,
        "LOW":      Fore.GREEN,
    }.get(level.upper(), Fore.WHITE)


def _score_color(score: int) -> str:
    if score >= 75:
        return Fore.RED + Style.BRIGHT
    elif score >= 50:
        return Fore.RED
    elif score >= 25:
        return Fore.YELLOW
    return Fore.GREEN


def _confidence_color(confidence: str) -> str:
    return {
        "HIGH":   Fore.RED,
        "MEDIUM": Fore.YELLOW,
        "LOW":    Fore.CYAN,
    }.get(confidence.upper(), Fore.WHITE)


# ---------------------------------------------------------------------------
# Input handling
# ---------------------------------------------------------------------------

def load_email_from_file(filepath: str) -> email.message.Message:
    """Parse an .eml or .txt file into an email.Message object."""
    try:
        with open(filepath, "rb") as f:
            raw = f.read()
        return email.message_from_bytes(raw, policy=policy.compat32)
    except FileNotFoundError:
        print(Fore.RED + f"[ERROR] File not found: {filepath}")
        sys.exit(1)
    except Exception as exc:
        print(Fore.RED + f"[ERROR] Could not read file: {exc}")
        sys.exit(1)


def load_email_from_stdin() -> email.message.Message:
    """Prompt the user to paste raw email text interactively."""
    print(Fore.CYAN + Style.BRIGHT + "\n Paste the raw email content below.")
    print(Fore.CYAN + " When finished, type " + Fore.WHITE + Style.BRIGHT + "END" +
          Fore.CYAN + Style.NORMAL + " on a new line and press Enter.\n")

    lines = []
    try:
        while True:
            line = input()
            if line.strip().upper() == "END":
                break
            lines.append(line)
    except EOFError:
        pass

    raw_text = "\n".join(lines)
    if not raw_text.strip():
        print(Fore.RED + "[ERROR] No email content provided.")
        sys.exit(1)

    return email.message_from_string(raw_text, policy=policy.compat32)


# ---------------------------------------------------------------------------
# Report rendering
# ---------------------------------------------------------------------------

def _print_banner():
    print()
    print(Fore.CYAN + Style.BRIGHT + "=" * BANNER_WIDTH)
    print(Fore.CYAN + Style.BRIGHT + "         PHISHGUARD - EMAIL ANALYZER          ")
    print(Fore.CYAN + Style.BRIGHT + "=" * BANNER_WIDTH)


def _print_score_block(score: int, level: str):
    score_clr = _score_color(score)
    level_clr = _risk_level_color(level)
    print()
    print(Fore.WHITE + Style.BRIGHT + f"  Risk Score : " + score_clr + f"{score}/100")
    print(Fore.WHITE + Style.BRIGHT + f"  Risk Level : " + level_clr + level)
    print()


def _print_summary_stats(findings: list[dict]):
    high   = sum(1 for f in findings if f["severity"] == "HIGH")
    medium = sum(1 for f in findings if f["severity"] == "MEDIUM")
    low    = sum(1 for f in findings if f["severity"] == "LOW")

    print(Fore.WHITE + Style.BRIGHT + "  Finding Summary")
    print(Fore.WHITE + "  " + "-" * (BANNER_WIDTH - 4))
    print(Fore.RED    + f"   HIGH   : {high}")
    print(Fore.YELLOW + f"   MEDIUM : {medium}")
    print(Fore.CYAN   + f"   LOW    : {low}")
    print(Fore.WHITE  + f"   TOTAL  : {len(findings)}")
    print()


def _print_classifications(classifications: list[dict]):
    """Print threat classification block."""
    print(Fore.WHITE + Style.BRIGHT + "  THREAT CLASSIFICATION")
    print(Fore.WHITE + "  " + "-" * (BANNER_WIDTH - 4))

    if not classifications:
        print(Fore.GREEN + "   [OK] No dominant threat pattern identified.")
    else:
        for clf in classifications:
            conf_clr = _confidence_color(clf["confidence"])
            print(
                conf_clr + f"   [>>] {clf['label']}"
                + Fore.WHITE + f"  [{clf['confidence']} confidence]"
            )
            # Wrap the rationale
            for line in textwrap.wrap(clf["rationale"], width=BANNER_WIDTH - 10):
                print(Fore.WHITE + Style.DIM + "        " + line)
            print(Fore.WHITE + Style.DIM + f"        MITRE: {clf['mitre']}")
    print()


def _print_section(title: str, findings: list[dict], category_filter: str):
    section_findings = [f for f in findings if f["category"] == category_filter]

    print(Fore.WHITE + Style.BRIGHT + f"  {title}")
    print(Fore.WHITE + "  " + "-" * (BANNER_WIDTH - 4))

    if not section_findings:
        print(Fore.GREEN + "   [OK] No issues detected in this category.")
    else:
        for finding in section_findings:
            color = _severity_color(finding["severity"])
            severity_tag = f"[{finding['severity']:6}]"
            detail = finding["detail"]
            wrapped = textwrap.wrap(detail, width=BANNER_WIDTH - 18)
            print(color + f"   [!] {severity_tag} " + wrapped[0])
            for continuation in wrapped[1:]:
                print(color + " " * 18 + continuation)
    print()


def _print_verdict(score: int):
    verdict = get_verdict(score)
    level_clr = _risk_level_color(get_risk_level(score))
    print(Fore.WHITE + Style.BRIGHT + "  VERDICT:")
    for line in textwrap.wrap(verdict, width=BANNER_WIDTH - 4):
        print(level_clr + f"   {line}")
    print()
    print(Fore.CYAN + Style.BRIGHT + "=" * BANNER_WIDTH)
    print()


def print_report(findings: list[dict], score: int, level: str, classifications: list[dict]):
    """Assemble and print the full color-coded terminal report."""
    _print_banner()
    _print_score_block(score, level)
    _print_summary_stats(findings)
    _print_classifications(classifications)
    _print_section("HEADER ANALYSIS",  findings, "Header")
    _print_section("URL ANALYSIS",     findings, "URL")
    _print_section("BODY ANALYSIS",    findings, "Body")
    _print_verdict(score)


# ---------------------------------------------------------------------------
# PDF export helpers
# ---------------------------------------------------------------------------

def _build_export_path(email_file: str | None, export_arg: str | None) -> str:
    """
    Determine the output PDF path.
    - If --export was given a filename, use that.
    - Otherwise, auto-generate a timestamped filename next to the input file
      (or in the current directory for paste mode).
    """
    if export_arg and export_arg.lower().endswith(".pdf"):
        return export_arg

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    base_name = f"phishguard_report_{timestamp}.pdf"

    if email_file:
        return os.path.join(os.path.dirname(os.path.abspath(email_file)), base_name)
    return base_name


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        prog="phishguard",
        description="PhishGuard — Offline phishing email detector.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Examples:
              python phishguard.py                                      # interactive paste
              python phishguard.py samples/phishing1.eml                # analyze a file
              python phishguard.py samples/phishing1.eml --export       # save PDF (auto-named)
              python phishguard.py samples/phishing1.eml --export my_report.pdf
        """),
    )
    parser.add_argument(
        "email_file",
        nargs="?",
        help="Path to a .eml or .txt email file (omit for interactive paste mode)",
    )
    parser.add_argument(
        "--export",
        nargs="?",
        const="AUTO",           # --export with no value → auto-name
        metavar="OUTPUT.pdf",
        help="Export analysis as a PDF report. Optionally specify output path.",
    )
    parser.add_argument(
        "--show-body",
        action="store_true",
        help="Print the raw extracted email body before the report (debug)",
    )
    args = parser.parse_args()

    # --- Load email ---
    if args.email_file:
        print(Fore.CYAN + f"\n[*] Loading email from file: {args.email_file}")
        msg = load_email_from_file(args.email_file)
    else:
        msg = load_email_from_stdin()

    if args.show_body:
        body_text = get_body_text(msg)
        print(Fore.WHITE + Style.DIM + "\n--- RAW EMAIL BODY ---")
        print(Fore.WHITE + Style.DIM + body_text[:2000])
        print(Fore.WHITE + Style.DIM + "--- END OF BODY ---\n")

    # --- Run analyzers ---
    print(Fore.CYAN + "[*] Running analysis...\n")

    header_findings  = analyze_headers(msg)
    body_text        = get_body_text(msg)
    url_findings     = analyze_urls(body_text)
    body_findings    = analyze_body(msg)
    all_findings     = header_findings + url_findings + body_findings

    # --- Score & classify ---
    score           = calculate_score(all_findings)
    level           = get_risk_level(score)
    verdict         = get_verdict(score)
    classifications = classify_threat(all_findings, body_text, msg)

    # --- Terminal report ---
    print_report(all_findings, score, level, classifications)

    # --- PDF export (if requested) ---
    if args.export is not None:
        pdf_path = _build_export_path(args.email_file, args.export if args.export != "AUTO" else None)
        print(Fore.CYAN + f"[*] Exporting PDF report -> {pdf_path}")
        try:
            saved = export_pdf(
                output_path=pdf_path,
                findings=all_findings,
                score=score,
                level=level,
                verdict=verdict,
                classifications=classifications,
                email_subject=msg.get("Subject", ""),
                email_from=msg.get("From", ""),
                filename=os.path.basename(args.email_file) if args.email_file else "Pasted content",
            )
            print(Fore.GREEN + Style.BRIGHT + f"[OK] PDF saved: {saved}\n")
        except Exception as exc:
            print(Fore.RED + f"[ERROR] PDF export failed: {exc}\n")


if __name__ == "__main__":
    main()
