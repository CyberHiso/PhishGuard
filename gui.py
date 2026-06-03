#!/usr/bin/env python3
"""
gui.py
PhishGuard — Graphical User Interface
A modern CustomTkinter GUI that wraps all analysis logic with
color-coded results, threat classification, and PDF export.

Launch with:
    python gui.py
"""

import email
import os
import threading
import tkinter as tk
from tkinter import filedialog, messagebox
from datetime import datetime
from email import policy

import customtkinter as ctk

from analyzers.header_analyzer import analyze_headers
from analyzers.url_analyzer import analyze_urls
from analyzers.body_analyzer import analyze_body, get_body_text
from utils.scorer import calculate_score, get_risk_level, get_verdict
from utils.classifier import classify_threat
from utils.pdf_exporter import export_pdf

# --- Appearance defaults ---
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

# Risk level colors (hex)
RISK_COLORS = {
    "CRITICAL": "#FF3B3B",
    "HIGH":     "#FF6B35",
    "MEDIUM":   "#FFB347",
    "LOW":      "#4CAF50",
}

SEVERITY_COLORS = {
    "HIGH":   "#FF3B3B",
    "MEDIUM": "#FFB347",
    "LOW":    "#5BC8F5",
}

CONFIDENCE_COLORS = {
    "HIGH":   "#FF6B35",
    "MEDIUM": "#FFB347",
    "LOW":    "#5BC8F5",
}

CATEGORY_COLORS = {
    "Header": "#A78BFA",
    "URL":    "#38BDF8",
    "Body":   "#FB923C",
}

# Threat type accent colors
THREAT_COLORS = {
    "Credential Harvesting":           "#FF3B3B",
    "Business Email Compromise (BEC)": "#FF6B35",
    "Delivery / Logistics Scam":       "#FFB347",
    "Account Takeover Attempt":        "#FF3B3B",
    "Malware Delivery":                "#FF3B3B",
    "Financial Fraud":                 "#FFB347",
    "Generic Spam / Phishing":         "#5BC8F5",
}


class PhishGuardApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("PhishGuard — Phishing Email Analyzer")
        self.geometry("1150x760")
        self.minsize(950, 640)

        # Store last analysis results so Export PDF can use them
        self._last_results: dict | None = None
        self._current_file: str | None = None

        self._build_layout()

    # ------------------------------------------------------------------
    # Layout construction
    # ------------------------------------------------------------------

    def _build_layout(self):
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)
        self._build_sidebar()
        self._build_main()
        self._build_statusbar()

    def _build_sidebar(self):
        sidebar = ctk.CTkFrame(self, width=230, corner_radius=0)
        sidebar.grid(row=0, column=0, rowspan=2, sticky="nsew")
        sidebar.grid_rowconfigure(9, weight=1)

        # Logo
        ctk.CTkLabel(
            sidebar,
            text="🛡 PhishGuard",
            font=ctk.CTkFont(size=22, weight="bold"),
            text_color="#5BC8F5",
        ).grid(row=0, column=0, padx=20, pady=(28, 4))

        ctk.CTkLabel(
            sidebar,
            text="Email Threat Analyzer",
            font=ctk.CTkFont(size=11),
            text_color="gray60",
        ).grid(row=1, column=0, padx=20, pady=(0, 20))

        ctk.CTkFrame(sidebar, height=1, fg_color="gray30").grid(
            row=2, column=0, sticky="ew", padx=16, pady=(0, 16)
        )

        # Input mode label
        ctk.CTkLabel(
            sidebar, text="INPUT MODE",
            font=ctk.CTkFont(size=10, weight="bold"),
            text_color="gray50",
        ).grid(row=3, column=0, padx=20, pady=(0, 8), sticky="w")

        # Load file
        self.btn_load = ctk.CTkButton(
            sidebar, text="  Load .eml / .txt File",
            command=self._load_file, height=38, corner_radius=8,
            fg_color="#1E6FA8", hover_color="#155A8A",
            font=ctk.CTkFont(size=13),
        )
        self.btn_load.grid(row=4, column=0, padx=16, pady=(0, 8), sticky="ew")

        ctk.CTkLabel(
            sidebar, text="  — or paste below —",
            font=ctk.CTkFont(size=11), text_color="gray50",
        ).grid(row=5, column=0, pady=(0, 12))

        # Analyze
        self.btn_analyze = ctk.CTkButton(
            sidebar, text="  Analyze Email",
            command=self._run_analysis, height=44, corner_radius=8,
            fg_color="#1A7A4A", hover_color="#145E39",
            font=ctk.CTkFont(size=14, weight="bold"),
        )
        self.btn_analyze.grid(row=6, column=0, padx=16, pady=(0, 8), sticky="ew")

        # Export PDF (disabled until analysis runs)
        self.btn_export = ctk.CTkButton(
            sidebar, text="  Export PDF Report",
            command=self._export_pdf, height=38, corner_radius=8,
            fg_color="#6B3FA8", hover_color="#562E8A",
            font=ctk.CTkFont(size=13),
            state="disabled",
        )
        self.btn_export.grid(row=7, column=0, padx=16, pady=(0, 8), sticky="ew")

        # Clear
        self.btn_clear = ctk.CTkButton(
            sidebar, text="  Clear",
            command=self._clear_all, height=34, corner_radius=8,
            fg_color="gray25", hover_color="gray35",
            font=ctk.CTkFont(size=12),
        )
        self.btn_clear.grid(row=8, column=0, padx=16, pady=(0, 20), sticky="ew")

        # Spacer (row 9 expands)

        # Appearance toggle
        ctk.CTkLabel(
            sidebar, text="APPEARANCE",
            font=ctk.CTkFont(size=10, weight="bold"),
            text_color="gray50",
        ).grid(row=10, column=0, padx=20, pady=(0, 6), sticky="w")

        self.appearance_menu = ctk.CTkOptionMenu(
            sidebar, values=["Dark", "Light", "System"],
            command=ctk.set_appearance_mode,
            height=30, corner_radius=6,
        )
        self.appearance_menu.set("Dark")
        self.appearance_menu.grid(row=11, column=0, padx=16, pady=(0, 20), sticky="ew")

        ctk.CTkLabel(
            sidebar, text="v1.0 · Educational Use Only",
            font=ctk.CTkFont(size=9), text_color="gray40",
        ).grid(row=12, column=0, padx=16, pady=(0, 16))

    def _build_main(self):
        main = ctk.CTkFrame(self, corner_radius=0, fg_color="transparent")
        main.grid(row=0, column=1, sticky="nsew")
        main.grid_rowconfigure(1, weight=1)
        main.grid_rowconfigure(3, weight=2)
        main.grid_columnconfigure(0, weight=1)

        # Input header
        input_hdr = ctk.CTkFrame(main, fg_color="transparent")
        input_hdr.grid(row=0, column=0, sticky="ew", padx=20, pady=(16, 4))
        input_hdr.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(
            input_hdr, text="EMAIL INPUT",
            font=ctk.CTkFont(size=11, weight="bold"), text_color="gray50",
        ).grid(row=0, column=0, sticky="w")

        self.input_filename_label = ctk.CTkLabel(
            input_hdr, text="",
            font=ctk.CTkFont(size=11), text_color="#5BC8F5",
        )
        self.input_filename_label.grid(row=0, column=1, sticky="w", padx=(12, 0))

        # Email input text box
        self.email_input = ctk.CTkTextbox(
            main, corner_radius=8,
            font=ctk.CTkFont(family="Courier New", size=12),
            wrap="none",
        )
        self.email_input.grid(row=1, column=0, sticky="nsew", padx=20, pady=(0, 8))
        self._set_placeholder()

        # Results header
        results_hdr = ctk.CTkFrame(main, fg_color="transparent")
        results_hdr.grid(row=2, column=0, sticky="ew", padx=20, pady=(8, 4))
        results_hdr.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(
            results_hdr, text="ANALYSIS RESULTS",
            font=ctk.CTkFont(size=11, weight="bold"), text_color="gray50",
        ).grid(row=0, column=0, sticky="w")

        self.score_badge = ctk.CTkLabel(
            results_hdr, text="",
            font=ctk.CTkFont(size=12, weight="bold"),
        )
        self.score_badge.grid(row=0, column=1, sticky="e")

        # Scrollable results area
        self.results_frame = ctk.CTkScrollableFrame(main, corner_radius=8)
        self.results_frame.grid(row=3, column=0, sticky="nsew", padx=20, pady=(0, 8))
        self.results_frame.grid_columnconfigure(0, weight=1)

        self._show_results_placeholder()

    def _build_statusbar(self):
        self.status_var = tk.StringVar(
            value="Ready — load a file or paste email content, then click Analyze."
        )
        ctk.CTkLabel(
            self, textvariable=self.status_var,
            font=ctk.CTkFont(size=11), text_color="gray50",
            anchor="w", height=26,
        ).grid(row=1, column=0, columnspan=2, sticky="ew", padx=16, pady=(0, 6))

    # ------------------------------------------------------------------
    # Placeholder helpers
    # ------------------------------------------------------------------

    PLACEHOLDER_TEXT = (
        "Paste raw email content here (headers + body)...\n\n"
        "Tip: In Gmail, open the email → ⋮ menu → 'Show original' → copy all text."
    )

    def _set_placeholder(self):
        self.email_input.insert("1.0", self.PLACEHOLDER_TEXT)
        self.email_input.configure(text_color="gray50")
        self.email_input.bind("<FocusIn>",  self._clear_placeholder)
        self.email_input.bind("<FocusOut>", self._restore_placeholder)

    def _clear_placeholder(self, _=None):
        if self.email_input.get("1.0", "end-1c") == self.PLACEHOLDER_TEXT:
            self.email_input.delete("1.0", "end")
            self.email_input.configure(text_color=("gray10", "gray90"))

    def _restore_placeholder(self, _=None):
        if not self.email_input.get("1.0", "end-1c").strip():
            self.email_input.insert("1.0", self.PLACEHOLDER_TEXT)
            self.email_input.configure(text_color="gray50")

    def _show_results_placeholder(self):
        ctk.CTkLabel(
            self.results_frame,
            text="Results will appear here after analysis.",
            font=ctk.CTkFont(size=13), text_color="gray50",
        ).grid(row=0, column=0, pady=40)

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------

    def _load_file(self):
        path = filedialog.askopenfilename(
            title="Open Email File",
            filetypes=[("Email files", "*.eml *.txt"), ("All files", "*.*")],
        )
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
        except Exception as exc:
            messagebox.showerror("File Error", f"Could not read file:\n{exc}")
            return

        self.email_input.configure(text_color=("gray10", "gray90"))
        self.email_input.delete("1.0", "end")
        self.email_input.insert("1.0", content)

        self._current_file = path
        self.input_filename_label.configure(text=f"· {os.path.basename(path)}")
        self.status_var.set(f"Loaded: {path}")

    def _run_analysis(self):
        raw_text = self.email_input.get("1.0", "end-1c").strip()
        if not raw_text or raw_text == self.PLACEHOLDER_TEXT.strip():
            messagebox.showwarning("No Input", "Please paste email content or load a file first.")
            return

        self.btn_analyze.configure(state="disabled", text="  Analyzing...")
        self.btn_load.configure(state="disabled")
        self.btn_export.configure(state="disabled")
        self.status_var.set("Analyzing email...")

        threading.Thread(
            target=self._analyze_worker, args=(raw_text,), daemon=True
        ).start()

    def _analyze_worker(self, raw_text: str):
        try:
            msg             = email.message_from_string(raw_text, policy=policy.compat32)
            header_findings = analyze_headers(msg)
            body_text       = get_body_text(msg)
            url_findings    = analyze_urls(body_text)
            body_findings   = analyze_body(msg)
            all_findings    = header_findings + url_findings + body_findings
            score           = calculate_score(all_findings)
            level           = get_risk_level(score)
            verdict         = get_verdict(score)
            classifications = classify_threat(all_findings, body_text, msg)
        except Exception as exc:
            self.after(0, lambda: self._on_error(str(exc)))
            return

        # Cache results for PDF export
        self._last_results = {
            "findings": all_findings, "score": score, "level": level,
            "verdict": verdict, "classifications": classifications,
            "subject": msg.get("Subject", ""),
            "from":    msg.get("From", ""),
        }
        self.after(0, lambda: self._render_results(
            all_findings, score, level, verdict, classifications
        ))

    def _on_error(self, msg: str):
        self.btn_analyze.configure(state="normal", text="  Analyze Email")
        self.btn_load.configure(state="normal")
        self.status_var.set("Error during analysis.")
        messagebox.showerror("Analysis Error", f"Something went wrong:\n{msg}")

    def _clear_all(self):
        self.email_input.delete("1.0", "end")
        self._restore_placeholder()
        self.input_filename_label.configure(text="")
        self.score_badge.configure(text="")
        self._current_file = None
        self._last_results = None
        self._clear_results_frame()
        self._show_results_placeholder()
        self.btn_export.configure(state="disabled")
        self.status_var.set("Cleared — ready for new input.")

    def _export_pdf(self):
        if not self._last_results:
            return

        # Ask where to save
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        default_name = f"phishguard_report_{timestamp}.pdf"
        save_path = filedialog.asksaveasfilename(
            title="Save PDF Report",
            defaultextension=".pdf",
            initialfile=default_name,
            filetypes=[("PDF files", "*.pdf")],
        )
        if not save_path:
            return

        self.btn_export.configure(state="disabled", text="  Exporting...")
        self.status_var.set("Generating PDF report...")

        def _worker():
            try:
                r = self._last_results
                saved = export_pdf(
                    output_path=save_path,
                    findings=r["findings"],
                    score=r["score"],
                    level=r["level"],
                    verdict=r["verdict"],
                    classifications=r["classifications"],
                    email_subject=r["subject"],
                    email_from=r["from"],
                    filename=os.path.basename(self._current_file) if self._current_file else "Pasted content",
                )
                self.after(0, lambda: self._on_export_done(saved))
            except Exception as exc:
                self.after(0, lambda: self._on_export_error(str(exc)))

        threading.Thread(target=_worker, daemon=True).start()

    def _on_export_done(self, path: str):
        self.btn_export.configure(state="normal", text="  Export PDF Report")
        self.status_var.set(f"PDF saved: {path}")
        messagebox.showinfo("Export Complete", f"PDF report saved to:\n{path}")

    def _on_export_error(self, msg: str):
        self.btn_export.configure(state="normal", text="  Export PDF Report")
        self.status_var.set("PDF export failed.")
        messagebox.showerror("Export Error", f"Could not save PDF:\n{msg}")

    # ------------------------------------------------------------------
    # Results rendering
    # ------------------------------------------------------------------

    def _clear_results_frame(self):
        for w in self.results_frame.winfo_children():
            w.destroy()

    def _render_results(self, findings, score, level, verdict, classifications):
        self._clear_results_frame()
        risk_color = RISK_COLORS.get(level, "#FFFFFF")

        # --- Score card ---
        score_card = ctk.CTkFrame(
            self.results_frame, corner_radius=10, fg_color=("gray85", "gray20")
        )
        score_card.grid(row=0, column=0, sticky="ew", padx=4, pady=(4, 8))
        score_card.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(
            score_card, text=f"{score}",
            font=ctk.CTkFont(size=52, weight="bold"),
            text_color=risk_color,
        ).grid(row=0, column=0, rowspan=2, padx=(20, 12), pady=16)

        ctk.CTkLabel(
            score_card, text="/ 100",
            font=ctk.CTkFont(size=18), text_color="gray50",
        ).grid(row=0, column=1, sticky="sw", pady=(20, 0))

        ctk.CTkLabel(
            score_card,
            text=f"Risk Level: {level}",
            font=ctk.CTkFont(size=20, weight="bold"),
            text_color=risk_color,
        ).grid(row=1, column=1, sticky="nw", pady=(0, 16))

        # Finding count pills
        counts = ctk.CTkFrame(score_card, fg_color="transparent")
        counts.grid(row=0, column=2, rowspan=2, padx=(0, 20), pady=16, sticky="e")
        high   = sum(1 for f in findings if f["severity"] == "HIGH")
        medium = sum(1 for f in findings if f["severity"] == "MEDIUM")
        low    = sum(1 for f in findings if f["severity"] == "LOW")
        for i, (lbl, cnt, clr) in enumerate([
            ("HIGH",   high,   SEVERITY_COLORS["HIGH"]),
            ("MEDIUM", medium, SEVERITY_COLORS["MEDIUM"]),
            ("LOW",    low,    SEVERITY_COLORS["LOW"]),
        ]):
            ctk.CTkLabel(
                counts, text=f"{cnt}  {lbl}",
                font=ctk.CTkFont(size=13, weight="bold"),
                text_color=clr, anchor="e",
            ).grid(row=i, column=0, sticky="e")

        self.score_badge.configure(text=f"{score}/100  {level}", text_color=risk_color)

        # Progress bar
        bar_frame = ctk.CTkFrame(self.results_frame, fg_color="transparent")
        bar_frame.grid(row=1, column=0, sticky="ew", padx=4, pady=(0, 12))
        bar_frame.grid_columnconfigure(0, weight=1)
        bar = ctk.CTkProgressBar(bar_frame, height=12, corner_radius=6)
        bar.grid(row=0, column=0, sticky="ew", padx=4)
        bar.set(score / 100)
        bar.configure(progress_color=risk_color)

        row_idx = 2

        # --- Threat Classification block ---
        row_idx = self._render_classification_section(classifications, row_idx)

        # --- Findings by category ---
        for cat_key, cat_title in [
            ("Header", "HEADER ANALYSIS"),
            ("URL",    "URL ANALYSIS"),
            ("Body",   "BODY ANALYSIS"),
        ]:
            cat_findings = [f for f in findings if f["category"] == cat_key]
            cat_color    = CATEGORY_COLORS[cat_key]

            # Section header row
            sec_hdr = ctk.CTkFrame(self.results_frame, fg_color="transparent")
            sec_hdr.grid(row=row_idx, column=0, sticky="ew", padx=4, pady=(10, 2))
            row_idx += 1

            ctk.CTkLabel(
                sec_hdr, text=f"  {cat_title}",
                font=ctk.CTkFont(size=13, weight="bold"),
                text_color=cat_color, anchor="w",
            ).pack(side="left")
            ctk.CTkLabel(
                sec_hdr,
                text=f"{len(cat_findings)} finding{'s' if len(cat_findings) != 1 else ''}",
                font=ctk.CTkFont(size=11), text_color="gray50",
            ).pack(side="left", padx=8)

            # Colored accent line
            ctk.CTkFrame(
                self.results_frame, height=2, fg_color=cat_color, corner_radius=1,
            ).grid(row=row_idx, column=0, sticky="ew", padx=4, pady=(0, 6))
            row_idx += 1

            if not cat_findings:
                ok = ctk.CTkFrame(
                    self.results_frame, corner_radius=6, fg_color=("gray88", "gray18")
                )
                ok.grid(row=row_idx, column=0, sticky="ew", padx=4, pady=(0, 4))
                ctk.CTkLabel(
                    ok, text="  ✓  No issues detected",
                    font=ctk.CTkFont(size=12), text_color="#4CAF50", anchor="w",
                ).pack(fill="x", padx=8, pady=8)
                row_idx += 1
            else:
                for finding in cat_findings:
                    self._render_finding_row(finding, row_idx)
                    row_idx += 1

        # --- Verdict ---
        verdict_card = ctk.CTkFrame(
            self.results_frame, corner_radius=10,
            fg_color=("gray85", "gray20"),
            border_width=2, border_color=risk_color,
        )
        verdict_card.grid(row=row_idx, column=0, sticky="ew", padx=4, pady=(16, 8))
        ctk.CTkLabel(
            verdict_card, text="VERDICT",
            font=ctk.CTkFont(size=11, weight="bold"),
            text_color="gray50", anchor="w",
        ).pack(fill="x", padx=16, pady=(12, 2))
        ctk.CTkLabel(
            verdict_card, text=verdict,
            font=ctk.CTkFont(size=13), text_color=risk_color,
            wraplength=700, justify="left", anchor="w",
        ).pack(fill="x", padx=16, pady=(0, 14))

        # Re-enable buttons
        self.btn_analyze.configure(state="normal", text="  Analyze Email")
        self.btn_load.configure(state="normal")
        self.btn_export.configure(state="normal")
        total = len(findings)
        self.status_var.set(
            f"Analysis complete — {total} finding{'s' if total != 1 else ''} | "
            f"Risk: {level} ({score}/100) | "
            f"Threat: {classifications[0]['label'] if classifications else 'N/A'}"
        )

    def _render_classification_section(self, classifications: list, row_idx: int) -> int:
        """Render the threat classification block. Returns the next available row index."""
        # Section header
        sec_hdr = ctk.CTkFrame(self.results_frame, fg_color="transparent")
        sec_hdr.grid(row=row_idx, column=0, sticky="ew", padx=4, pady=(10, 2))
        row_idx += 1

        ctk.CTkLabel(
            sec_hdr, text="  THREAT CLASSIFICATION",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color="#E879F9", anchor="w",
        ).pack(side="left")

        # Accent line
        ctk.CTkFrame(
            self.results_frame, height=2, fg_color="#E879F9", corner_radius=1,
        ).grid(row=row_idx, column=0, sticky="ew", padx=4, pady=(0, 6))
        row_idx += 1

        if not classifications:
            ok = ctk.CTkFrame(
                self.results_frame, corner_radius=6, fg_color=("gray88", "gray18")
            )
            ok.grid(row=row_idx, column=0, sticky="ew", padx=4, pady=(0, 4))
            ctk.CTkLabel(
                ok, text="  ✓  No dominant threat pattern identified",
                font=ctk.CTkFont(size=12), text_color="#4CAF50", anchor="w",
            ).pack(fill="x", padx=8, pady=8)
            row_idx += 1
            return row_idx

        for clf in classifications:
            threat_color = THREAT_COLORS.get(clf["label"], "#E879F9")
            conf_color   = CONFIDENCE_COLORS.get(clf["confidence"], "#FFFFFF")

            card = ctk.CTkFrame(
                self.results_frame, corner_radius=8,
                fg_color=("gray88", "gray17"),
                border_width=1, border_color=threat_color,
            )
            card.grid(row=row_idx, column=0, sticky="ew", padx=4, pady=3)
            card.grid_columnconfigure(1, weight=1)
            row_idx += 1

            # Left: colored threat-type pill
            left = ctk.CTkFrame(card, fg_color="transparent", width=140)
            left.grid(row=0, column=0, rowspan=2, padx=(10, 8), pady=10, sticky="nw")

            ctk.CTkLabel(
                left, text=clf["label"],
                font=ctk.CTkFont(size=11, weight="bold"),
                text_color=threat_color,
                wraplength=130, justify="left", anchor="w",
            ).pack(anchor="w")

            ctk.CTkLabel(
                left,
                text=f"Confidence: {clf['confidence']}",
                font=ctk.CTkFont(size=10, weight="bold"),
                text_color=conf_color, anchor="w",
            ).pack(anchor="w", pady=(4, 0))

            # Right: rationale + MITRE
            right = ctk.CTkFrame(card, fg_color="transparent")
            right.grid(row=0, column=1, padx=(0, 12), pady=(10, 0), sticky="ew")

            ctk.CTkLabel(
                right, text=clf["rationale"],
                font=ctk.CTkFont(size=11),
                text_color=("gray15", "gray85"),
                wraplength=620, justify="left", anchor="w",
            ).pack(anchor="w")

            ctk.CTkLabel(
                card, text=f"MITRE ATT&CK: {clf['mitre']}",
                font=ctk.CTkFont(size=10),
                text_color="gray50", anchor="w",
            ).grid(row=1, column=1, padx=(0, 12), pady=(0, 8), sticky="w")

        return row_idx

    def _render_finding_row(self, finding: dict, row_idx: int):
        severity = finding["severity"]
        color    = SEVERITY_COLORS.get(severity, "#FFFFFF")

        row = ctk.CTkFrame(
            self.results_frame, corner_radius=6, fg_color=("gray88", "gray17")
        )
        row.grid(row=row_idx, column=0, sticky="ew", padx=4, pady=2)
        row.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(
            row, text=f" {severity} ",
            font=ctk.CTkFont(size=10, weight="bold"),
            text_color="black", fg_color=color,
            corner_radius=4, width=60,
        ).grid(row=0, column=0, padx=(10, 8), pady=8, sticky="w")

        ctk.CTkLabel(
            row, text=finding["detail"],
            font=ctk.CTkFont(size=12),
            text_color=("gray15", "gray85"),
            anchor="w", justify="left", wraplength=700,
        ).grid(row=0, column=1, padx=(0, 12), pady=8, sticky="w")


# ------------------------------------------------------------------
# Entry point
# ------------------------------------------------------------------

if __name__ == "__main__":
    app = PhishGuardApp()
    app.mainloop()
