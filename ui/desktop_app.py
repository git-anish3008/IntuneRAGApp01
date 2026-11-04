import os
import threading
from pathlib import Path
from typing import List, Dict, Optional
import customtkinter as ctk
from tkinter import messagebox

from core.orchestrator import LangGraphOrchestrator

ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

# Theme Colors
BG_MAIN = "#0F172A"
BG_SIDEBAR = "#1E293B"
BG_CARD = "#1E293B"
TEXT_PRIMARY = "#F8FAFC"
TEXT_SECONDARY = "#94A3B8"
BORDER_SUBTLE = "#334155"
ACCENT_BLUE = "#2563EB"
STATUS_GREEN = "#10B981"
STATUS_BG_GREEN = "#064E3B"
TAG_BG = "#334155"


class IntuneRAGDesktopApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Intune RAG Agent")
        self.geometry("1280=820" if False else "1280x820")
        self.minsize(1000, 700)
        self.configure(fg_color=BG_MAIN)

        self.log_paths: List[str] = []
        self.runbook_paths: List[str] = []
        self.orchestrator: Optional[LangGraphOrchestrator] = None

        self._build_layout()

    def _build_layout(self):
        # Grid layout: Sidebar (240px) | Main Content (Expand)
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # ----------------------------------------------------------------------
        # 1. SIDEBAR NAVIGATION
        # ----------------------------------------------------------------------
        self.sidebar = ctk.CTkFrame(self, fg_color=BG_SIDEBAR, corner_radius=0, width=240)
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        self.sidebar.grid_rowconfigure(6, weight=1)

        logo_label = ctk.CTkLabel(
            self.sidebar, text="🛡️  Intune RAG Agent",
            font=ctk.CTkFont(family="Segoe UI", size=16, weight="bold"),
            text_color=TEXT_PRIMARY
        )
        logo_label.grid(row=0, column=0, padx=20, pady=(24, 20), sticky="w")

        nav_buttons = [
            ("🏠  Home", self._show_home_view),
            ("📄  Logs & Documents", self._show_logs_view),
            ("📊  Analyzer", self._show_analyzer_view),
            ("⚙️  Settings", self._show_settings_view)
        ]

        self.nav_btn_refs = {}
        for idx, (label_text, cmd) in enumerate(nav_buttons, 1):
            btn = ctk.CTkButton(
                self.sidebar, text=label_text, anchor="w",
                fg_color="transparent", hover_color=BORDER_SUBTLE,
                text_color=TEXT_SECONDARY, height=38, corner_radius=6,
                font=ctk.CTkFont(family="Segoe UI", size=13),
                command=cmd
            )
            btn.grid(row=idx, column=0, padx=12, pady=4, sticky="ew")
            self.nav_btn_refs[label_text] = btn

        # Status footer at bottom of sidebar
        status_frame = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        status_frame.grid(row=7, column=0, padx=16, pady=20, sticky="ew")

        self.lbl_ready_dot = ctk.CTkLabel(
            status_frame, text="● Offline",
            font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
            text_color="#EF4444"
        )
        self.lbl_ready_dot.pack(anchor="w")

        # ----------------------------------------------------------------------
        # 2. MAIN CONTENT AREA CONTAINER
        # ----------------------------------------------------------------------
        self.content_container = ctk.CTkFrame(self, fg_color=BG_MAIN, corner_radius=0)
        self.content_container.grid(row=0, column=1, sticky="nsew")
        self.content_container.grid_columnconfigure(0, weight=1)
        self.content_container.grid_rowconfigure(0, weight=1)

        # Build all views
        self.views = {}
        self._build_home_view()
        self._build_logs_view()
        self._build_analyzer_view()
        self._build_settings_view()

        self._show_home_view()

    def _set_active_nav(self, active_label: str):
        for label, btn in self.nav_btn_refs.items():
            if label == active_label:
                btn.configure(fg_color=ACCENT_BLUE, text_color=TEXT_PRIMARY)
            else:
                btn.configure(fg_color="transparent", text_color=TEXT_SECONDARY)

    def _switch_view(self, view_name: str):
        for name, frame in self.views.items():
            if name == view_name:
                frame.grid(row=0, column=0, sticky="nsew")
            else:
                frame.grid_forget()

    # ==========================================================================
    # VIEW 1: HOME (Dashboard & Chat)
    # ==========================================================================
    def _build_home_view(self):
        self.home_view = ctk.CTkScrollableFrame(self.content_container, fg_color=BG_MAIN, corner_radius=0)
        self.views["home"] = self.home_view
        self.home_view.grid_columnconfigure(0, weight=1)

        # Header
        header = ctk.CTkFrame(self.home_view, fg_color="transparent")
        header.pack(fill="x", padx=24, pady=(24, 16))
        ctk.CTkLabel(
            header, text="Intune Local RAG Agent",
            font=ctk.CTkFont(family="Segoe UI", size=22, weight="bold"), text_color=TEXT_PRIMARY
        ).pack(anchor="w")
        ctk.CTkLabel(
            header, text="Analyze Win32 App failures entirely on CPU using GGUF Layer Streaming.",
            font=ctk.CTkFont(family="Segoe UI", size=13), text_color=TEXT_SECONDARY
        ).pack(anchor="w", pady=(2, 0))

        # Ingestion Cards Frame
        ingest_frame = ctk.CTkFrame(self.home_view, fg_color="transparent")
        ingest_frame.pack(fill="x", padx=24, pady=8)
        ingest_frame.grid_columnconfigure((0, 1), weight=1)

        # Box 1: Upload Logs
        box_log = ctk.CTkFrame(ingest_frame, fg_color=BG_CARD, corner_radius=10, border_width=1, border_color=BORDER_SUBTLE)
        box_log.grid(row=0, column=0, sticky="nsew", padx=(0, 8), pady=4)
        ctk.CTkLabel(box_log, text="Upload Intune Logs (.log / .evtx)", font=ctk.CTkFont(family="Segoe UI", size=14, weight="bold"), text_color=TEXT_PRIMARY).pack(anchor="w", padx=16, pady=(16, 8))
        self.btn_upl_log = ctk.CTkButton(
            box_log, text="📁 Select Log Files", height=36, corner_radius=6, fg_color=TAG_BG, hover_color=BORDER_SUBTLE, text_color=TEXT_PRIMARY,
            command=lambda: self._browse_files("log")
        )
        self.btn_upl_log.pack(padx=16, pady=(0, 16), fill="x")

        # Box 2: Upload Runbooks
        box_rb = ctk.CTkFrame(ingest_frame, fg_color=BG_CARD, corner_radius=10, border_width=1, border_color=BORDER_SUBTLE)
        box_rb.grid(row=0, column=1, sticky="nsew", padx=(8, 0), pady=4)
        ctk.CTkLabel(box_rb, text="Upload Runbook Manuals (.txt)", font=ctk.CTkFont(family="Segoe UI", size=14, weight="bold"), text_color=TEXT_PRIMARY).pack(anchor="w", padx=16, pady=(16, 8))
        self.btn_upl_rb = ctk.CTkButton(
            box_rb, text="📁 Select Runbook Files", height=36, corner_radius=6, fg_color=TAG_BG, hover_color=BORDER_SUBTLE, text_color=TEXT_PRIMARY,
            command=lambda: self._browse_files("runbook")
        )
        self.btn_upl_rb.pack(padx=16, pady=(0, 16), fill="x")

        # Initialize Button
        init_wrapper = ctk.CTkFrame(self.home_view, fg_color="transparent")
        init_wrapper.pack(fill="x", padx=24, pady=12)
        self.btn_initialize = ctk.CTkButton(
            init_wrapper, text="Initialize Agent", height=42, corner_radius=8,
            fg_color=ACCENT_BLUE, hover_color="#1D4ED8", text_color=TEXT_PRIMARY,
            font=ctk.CTkFont(family="Segoe UI", size=14, weight="bold"),
            command=self._start_initialization_thread
        )
        self.btn_initialize.pack(fill="x")

        # Chat Assistant Section
        chat_section = ctk.CTkFrame(self.home_view, fg_color=BG_CARD, corner_radius=10, border_width=1, border_color=BORDER_SUBTLE)
        chat_section.pack(fill="both", expand=True, padx=24, pady=(12, 24))
        
        chat_header = ctk.CTkFrame(chat_section, fg_color="transparent")
        chat_header.pack(fill="x", padx=16, pady=12)
        ctk.CTkLabel(chat_header, text="AI Chat Assistant", font=ctk.CTkFont(family="Segoe UI", size=15, weight="bold"), text_color=TEXT_PRIMARY).pack(side="left")

        # Chat Feed
        self.chat_feed = ctk.CTkScrollableFrame(chat_section, fg_color=BG_MAIN, corner_radius=8, height=350)
        self.chat_feed.pack(fill="both", expand=True, padx=16, pady=(0, 12))

        self._add_ai_response_card("How can I help you troubleshoot Win32 App failures today?", "Status: Idle", "Tags: Ready")

        # Prompt Input Bar
        input_bar = ctk.CTkFrame(chat_section, fg_color="transparent")
        input_bar.pack(fill="x", padx=16, pady=(0, 16))
        input_bar.grid_columnconfigure(0, weight=1)

        self.entry_prompt = ctk.CTkEntry(
            input_bar, placeholder_text="Ask about Win32 failures, app IDs, or error codes...",
            height=40, fg_color=BG_MAIN, border_color=BORDER_SUBTLE, text_color=TEXT_PRIMARY,
            font=ctk.CTkFont(family="Segoe UI", size=13)
        )
        self.entry_prompt.grid(row=0, column=0, sticky="ew", padx=(0, 8))
        self.entry_prompt.bind("<Return>", lambda e: self._on_send_clicked())

        self.btn_send = ctk.CTkButton(
            input_bar, text="Send 🚀", width=90, height=40, corner_radius=8,
            fg_color=ACCENT_BLUE, hover_color="#1D4ED8", text_color=TEXT_PRIMARY,
            font=ctk.CTkFont(family="Segoe UI", size=13, weight="bold"),
            command=self._on_send_clicked
        )
        self.btn_send.grid(row=0, column=1, sticky="e")

        # Quick Suggestion Chips
        chips_frame = ctk.CTkFrame(chat_section, fg_color="transparent")
        chips_frame.pack(fill="x", padx=16, pady=(0, 16))
        
        ctk.CTkButton(
            chips_frame, text="See if any application got failed?", height=26, corner_radius=6,
            fg_color=TAG_BG, hover_color=BORDER_SUBTLE, text_color=TEXT_SECONDARY,
            font=ctk.CTkFont(family="Segoe UI", size=11),
            command=lambda: self._submit_quick_query("See if any application got failed?")
        ).pack(side="left", padx=(0, 8))

        ctk.CTkButton(
            chips_frame, text="Fetch all application IDs mentioned in the logs", height=26, corner_radius=6,
            fg_color=TAG_BG, hover_color=BORDER_SUBTLE, text_color=TEXT_SECONDARY,
            font=ctk.CTkFont(family="Segoe UI", size=11),
            command=lambda: self._submit_quick_query("Fetch all application IDs mentioned in the logs")
        ).pack(side="left", padx=(0, 8))

    def _show_home_view(self):
        self._set_active_nav("🏠  Home")
        self._switch_view("home")

    # ==========================================================================
    # VIEW 2: LOGS & DOCUMENTS (File Management & Removal Panel)
    # ==========================================================================
    def _build_logs_view(self):
        self.logs_view = ctk.CTkScrollableFrame(self.content_container, fg_color=BG_MAIN, corner_radius=0)
        self.views["logs"] = self.logs_view
        self.logs_view.grid_columnconfigure(0, weight=1)

        header = ctk.CTkFrame(self.logs_view, fg_color="transparent")
        header.pack(fill="x", padx=24, pady=(24, 16))
        ctk.CTkLabel(header, text="Injected Logs & Documents", font=ctk.CTkFont(family="Segoe UI", size=22, weight="bold"), text_color=TEXT_PRIMARY).pack(anchor="w")
        ctk.CTkLabel(header, text="Manage currently loaded log files (.log / .evtx) and knowledge manuals (.txt).", font=ctk.CTkFont(family="Segoe UI", size=13), text_color=TEXT_SECONDARY).pack(anchor="w", pady=(2, 0))

        self.logs_list_frame = ctk.CTkFrame(self.logs_view, fg_color=BG_CARD, corner_radius=10, border_width=1, border_color=BORDER_SUBTLE)
        self.logs_list_frame.pack(fill="both", expand=True, padx=24, pady=12)

    def _refresh_logs_panel(self):
        for widget in self.logs_list_frame.winfo_children():
            widget.destroy()

        all_files = [("Log / EVTX File", path) for path in self.log_paths] + [("Runbook Manual", path) for path in self.runbook_paths]

        if not all_files:
            ctk.CTkLabel(
                self.logs_list_frame, text="No logs or documents injected yet. Go to Home to upload files.",
                font=ctk.CTkFont(family="Segoe UI", size=13), text_color=TEXT_SECONDARY
            ).pack(padx=20, pady=30)
            return

        ctk.CTkLabel(
            self.logs_list_frame, text=f"Total Injected Files: {len(all_files)}",
            font=ctk.CTkFont(family="Segoe UI", size=14, weight="bold"), text_color=TEXT_PRIMARY
        ).pack(anchor="w", padx=20, pady=(16, 12))

        for ftype, fpath in all_files:
            row = ctk.CTkFrame(self.logs_list_frame, fg_color=BG_MAIN, corner_radius=6, border_width=1, border_color=BORDER_SUBTLE)
            row.pack(fill="x", padx=20, pady=6)

            info_text = f"[{ftype}] {Path(fpath).name}\nPath: {fpath}"
            ctk.CTkLabel(row, text=info_text, font=ctk.CTkFont(family="Segoe UI", size=12), text_color=TEXT_PRIMARY, justify="left").pack(side="left", padx=16, pady=10)

            ctk.CTkButton(
                row, text="❌ Remove", width=80, height=30, corner_radius=6,
                fg_color="#EF4444", hover_color="#DC2626", text_color=TEXT_PRIMARY,
                font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"),
                command=lambda p=fpath: self._remove_file(p)
            ).pack(side="right", padx=16, pady=10)

    def _remove_file(self, path: str):
        if path in self.log_paths:
            self.log_paths.remove(path)
        if path in self.runbook_paths:
            self.runbook_paths.remove(path)
        self._refresh_logs_panel()
        messagebox.showinfo("File Removed", f"Successfully removed {Path(path).name} from active session.")

    def _show_logs_view(self):
        self._refresh_logs_panel()
        self._set_active_nav("📄  Logs & Documents")
        self._switch_view("logs")

    # ==========================================================================
    # VIEW 3: ANALYZER (Stage Failure Graph / Telemetry Statistics)
    # ==========================================================================
    def _build_analyzer_view(self):
        self.analyzer_view = ctk.CTkScrollableFrame(self.content_container, fg_color=BG_MAIN, corner_radius=0)
        self.views["analyzer"] = self.analyzer_view
        self.analyzer_view.grid_columnconfigure(0, weight=1)

        header = ctk.CTkFrame(self.analyzer_view, fg_color="transparent")
        header.pack(fill="x", padx=24, pady=(24, 16))
        ctk.CTkLabel(header, text="Intune Win32 Lifecycle Analyzer", font=ctk.CTkFont(family="Segoe UI", size=22, weight="bold"), text_color=TEXT_PRIMARY).pack(anchor="w")
        ctk.CTkLabel(header, text="Statistical breakdown of detected applications and failure distribution across lifecycle stages.", font=ctk.CTkFont(family="Segoe UI", size=13), text_color=TEXT_SECONDARY).pack(anchor="w", pady=(2, 0))

        self.analyzer_stats_frame = ctk.CTkFrame(self.analyzer_view, fg_color=BG_CARD, corner_radius=10, border_width=1, border_color=BORDER_SUBTLE)
        self.analyzer_stats_frame.pack(fill="both", expand=True, padx=24, pady=12)

    def _refresh_analyzer_panel(self):
        for widget in self.analyzer_stats_frame.winfo_children():
            widget.destroy()

        if not self.orchestrator:
            ctk.CTkLabel(
                self.analyzer_stats_frame, text="Agent not initialized. Please upload logs and click 'Initialize Agent' on Home first.",
                font=ctk.CTkFont(family="Segoe UI", size=13), text_color=TEXT_SECONDARY
            ).pack(padx=20, pady=40)
            return

        apps = self.orchestrator.retrieval.get_all_unique_app_ids()
        total_apps = len(apps)
        failed_apps = sum(1 for a in apps if a["status"] == "Failed")
        success_apps = total_apps - failed_apps

        # Count failures per phase
        phase_counts = {
            "1. Applicability": 0,
            "2. Detection": 0,
            "3. Download": 0,
            "4. Decryption": 0,
            "5. Execution": 0,
            "6. Reporting": 0
        }
        for a in apps:
            p = a.get("last_phase", "Unknown")
            if p in phase_counts:
                phase_counts[p] += 1

        # Summary Metrics Row
        metrics_row = ctk.CTkFrame(self.analyzer_stats_frame, fg_color="transparent")
        metrics_row.pack(fill="x", padx=20, pady=16)
        metrics_row.grid_columnconfigure((0, 1, 2), weight=1)

        self._create_metric_card(metrics_row, 0, "Total Detected Apps", str(total_apps), ACCENT_BLUE)
        self._create_metric_card(metrics_row, 1, "Successful / Processed", str(success_apps), STATUS_GREEN)
        self._create_metric_card(metrics_row, 2, "Failed / Error Flagged", str(failed_apps), "#EF4444")

        # Stage Failure Distribution Header
        ctk.CTkLabel(
            self.analyzer_stats_frame, text="Lifecycle Stage Distribution",
            font=ctk.CTkFont(family="Segoe UI", size=15, weight="bold"), text_color=TEXT_PRIMARY
        ).pack(anchor="w", padx=20, pady=(16, 8))

        # Progress bar visualizer for each stage
        max_count = max(list(phase_counts.values()) + [1])
        for stage, count in phase_counts.items():
            stage_row = ctk.CTkFrame(self.analyzer_stats_frame, fg_color=BG_MAIN, corner_radius=6, border_width=1, border_color=BORDER_SUBTLE)
            stage_row.pack(fill="x", padx=20, pady=4)
            stage_row.grid_columnconfigure(1, weight=1)

            ctk.CTkLabel(stage_row, text=stage, font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"), text_color=TEXT_PRIMARY, width=150, anchor="w").grid(row=0, column=0, padx=14, pady=10)

            # Visual bar
            bar_frame = ctk.CTkFrame(stage_row, fg_color=TAG_BG, height=14, corner_radius=4)
            bar_frame.grid(row=0, column=1, sticky="ew", padx=10)
            
            fill_pct = count / max_count
            if fill_pct > 0:
                fill_bar = ctk.CTkFrame(bar_frame, fg_color="#3B82F6" if count > 0 else TAG_BG, height=14, corner_radius=4)
                fill_bar.place(relx=0, rely=0, relwidth=fill_pct, relheight=1.0)

            ctk.CTkLabel(stage_row, text=f"{count} app(s)", font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"), text_color=TEXT_SECONDARY, width=70).grid(row=0, column=2, padx=14, pady=10)

    def _create_metric_card(self, parent, col: int, title: str, value: str, accent_color: str):
        card = ctk.CTkFrame(parent, fg_color=BG_MAIN, corner_radius=8, border_width=1, border_color=BORDER_SUBTLE)
        card.grid(row=0, column=col, sticky="nsew", padx=6)
        ctk.CTkLabel(card, text=title, font=ctk.CTkFont(family="Segoe UI", size=12), text_color=TEXT_SECONDARY).pack(anchor="w", padx=14, pady=(12, 2))
        ctk.CTkLabel(card, text=value, font=ctk.CTkFont(family="Segoe UI", size=22, weight="bold"), text_color=accent_color).pack(anchor="w", padx=14, pady=(0, 12))

    def _show_analyzer_view(self):
        self._refresh_analyzer_panel()
        self._set_active_nav("📊  Analyzer")
        self._switch_view("analyzer")

    # ==========================================================================
    # VIEW 4: SETTINGS (Placeholder)
    # ==========================================================================
    def _build_settings_view(self):
        self.settings_view = ctk.CTkScrollableFrame(self.content_container, fg_color=BG_MAIN, corner_radius=0)
        self.views["settings"] = self.settings_view
        
        header = ctk.CTkFrame(self.settings_view, fg_color="transparent")
        header.pack(fill="x", padx=24, pady=(24, 16))
        ctk.CTkLabel(header, text="Settings & Configuration", font=ctk.CTkFont(family="Segoe UI", size=22, weight="bold"), text_color=TEXT_PRIMARY).pack(anchor="w")
        ctk.CTkLabel(header, text="Local GGUF model path, thread allocations, and cache parameters.", font=ctk.CTkFont(family="Segoe UI", size=13), text_color=TEXT_SECONDARY).pack(anchor="w", pady=(2, 0))

        card = ctk.CTkFrame(self.settings_view, fg_color=BG_CARD, corner_radius=10, border_width=1, border_color=BORDER_SUBTLE)
        card.pack(fill="x", padx=24, pady=12)
        ctk.CTkLabel(card, text="Model Engine: Qwen 2.5 Coder 1.5B/3B (GGUF CPU Layer Streaming)", font=ctk.CTkFont(family="Segoe UI", size=13, weight="bold"), text_color=TEXT_PRIMARY).pack(anchor="w", padx=20, pady=20)

    def _show_settings_view(self):
        self._set_active_nav("⚙️  Settings")
        self._switch_view("settings")

    # ==========================================================================
    # CORE LOGIC & FILE BROWSING
    # ==========================================================================
    def _browse_files(self, ftype: str):
        from tkinter import filedialog
        filetypes = [("Intune Logs & EVTX", "*.log *.evtx")] if ftype == "log" else [("Runbook Manuals", "*.txt")]
        paths = filedialog.askopenfilenames(title=f"Select {ftype.capitalize()} Files", filetypes=filetypes)
        if not paths:
            return

        if ftype == "log":
            for p in paths:
                if p not in self.log_paths:
                    self.log_paths.append(p)
            messagebox.setAttribute = getattr(messagebox, 'setAttribute', None)
            messagebox.showinfo("Logs Added", f"Added {len(paths)} log file(s). Total loaded: {len(self.log_paths)}")
        else:
            for p in paths:
                if p not in self.runbook_paths:
                    self.runbook_paths.append(p)
            messagebox.showinfo("Runbooks Added", f"Added {len(paths)} runbook file(s). Total loaded: {len(self.runbook_paths)}")

    def _start_initialization_thread(self):
        if not self.log_paths and not self.runbook_paths:
            messagebox.showwarning("Missing Files", "Please upload at least one Intune log (.log / .evtx) or Runbook (.txt) first.")
            return

        self.btn_initialize.configure(state="disabled", text="Initializing BM25 & Loading Model...")
        self.lbl_ready_dot.configure(text="● Loading...", text_color="#F59E0B")

        def _worker():
            try:
                if self.orchestrator is not None:
                    self.orchestrator.close()
                engine = LangGraphOrchestrator(self.log_paths, self.runbook_paths)
                self.after(0, lambda: self._on_init_success(engine))
            except Exception as err:
                self.after(0, lambda e=str(err): self._on_init_error(e))

        threading.Thread(target=_worker, daemon=True).start()

    def _on_init_success(self, engine: LangGraphOrchestrator):
        self.orchestrator = engine
        self.btn_initialize.configure(state="normal", text="Initialize Agent")
        self.lbl_ready_dot.configure(text="● Ready", text_color=STATUS_GREEN)
        num_apps = len(self.orchestrator.retrieval.get_all_unique_app_ids())
        self._add_ai_response_card(
            body_text=(
                f"Agent initialized successfully in ~1 second.\n"
                f"• Indexed {len(self.orchestrator.retrieval.internal_nodes)} log entries via BM25 ({num_apps} unique App IDs detected).\n"
                f"• Hybrid Deterministic + Streaming LLM pipeline active."
            ),
            status_tag="Status: Ready",
            phase_tag=f"Apps Detected: {num_apps}"
        )

    def _on_init_error(self, error_msg: str):
        self.btn_initialize.configure(state="normal", text="Initialize Agent")
        self.lbl_ready_dot.configure(text="● Error", text_color="#EF4444")
        messagebox.showerror("Initialization Error", error_msg)

    def _submit_quick_query(self, query_text: str):
        self._show_home_view()
        self.entry_prompt.delete(0, "end")
        self.entry_prompt.insert(0, query_text)
        self._on_send_clicked()

    def _add_user_bubble(self, text: str):
        row_frame = ctk.CTkFrame(self.chat_feed, fg_color="transparent")
        row_frame.pack(fill="x", padx=10, pady=8)

        card = ctk.CTkFrame(row_frame, fg_color=ACCENT_BLUE, corner_radius=10)
        card.pack(side="right", padx=4)

        lbl = ctk.CTkLabel(
            card, text=text, font=ctk.CTkFont(family="Segoe UI", size=13),
            text_color=TEXT_PRIMARY, justify="left", wraplength=700
        )
        lbl.pack(padx=14, pady=10)
        self._scroll_to_bottom()

    def _add_ai_response_card(self, body_text: str, status_tag: str, phase_tag: str, evidence_text: str = "") -> ctk.CTkLabel:
        row_frame = ctk.CTkFrame(self.chat_feed, fg_color="transparent")
        row_frame.pack(fill="x", padx=10, pady=8)

        avatar = ctk.CTkLabel(row_frame, text="🛡️", font=ctk.CTkFont(size=18))
        avatar.pack(side="left", padx=(0, 10), anchor="n", pady=4)

        card = ctk.CTkFrame(
            row_frame, fg_color=BG_CARD, corner_radius=10,
            border_width=1, border_color=BORDER_SUBTLE
        )
        card.pack(side="left", fill="x", expand=True, padx=4)

        top_bar = ctk.CTkFrame(card, fg_color="transparent")
        top_bar.pack(fill="x", padx=14, pady=(10, 6))

        ctk.CTkLabel(
            top_bar, text="AI Response",
            font=ctk.CTkFont(family="Segoe UI", size=13, weight="bold"),
            text_color=TEXT_PRIMARY
        ).pack(side="left")

        body_label = ctk.CTkLabel(
            card, text=body_text,
            font=ctk.CTkFont(family="Segoe UI", size=13),
            text_color="#E2E8F0", justify="left", anchor="w", wraplength=760
        )

        btn_copy = ctk.CTkButton(
            top_bar, text="📋 Copy", width=60, height=22, corner_radius=6,
            fg_color=TAG_BG, hover_color=BORDER_SUBTLE, text_color=TEXT_SECONDARY,
            font=ctk.CTkFont(family="Segoe UI", size=11),
            command=lambda: self._copy_to_clipboard(body_label.cget("text"))
        )
        btn_copy.pack(side="right", padx=(6, 0))

        status_pill = ctk.CTkLabel(
            top_bar, text="  ● Status  ", fg_color=STATUS_BG_GREEN, corner_radius=10,
            text_color=STATUS_GREEN, font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold")
        )
        status_pill.pack(side="right", padx=6)

        body_label.pack(fill="x", padx=14, pady=(2, 10))

        footer_bar = ctk.CTkFrame(card, fg_color="transparent")
        footer_bar.pack(fill="x", padx=14, pady=(0, 10))

        ctk.CTkLabel(
            footer_bar, text=f"  {status_tag}  ", fg_color=TAG_BG, corner_radius=6,
            text_color=TEXT_SECONDARY, font=ctk.CTkFont(family="Segoe UI", size=11)
        ).pack(side="left", padx=(0, 8))

        ctk.CTkLabel(
            footer_bar, text=f"  {phase_tag}  ", fg_color=TAG_BG, corner_radius=6,
            text_color=TEXT_SECONDARY, font=ctk.CTkFont(family="Segoe UI", size=11)
        ).pack(side="left", padx=(0, 8))

        if evidence_text:
            evidence_box = ctk.CTkTextbox(
                card, height=110, fg_color=BG_MAIN, text_color=TEXT_SECONDARY,
                font=ctk.CTkFont(family="Consolas", size=11), border_width=1, border_color=BORDER_SUBTLE
            )
            evidence_box.insert("1.0", evidence_text)
            evidence_box.configure(state="disabled")

            def _toggle_evidence():
                if evidence_box.winfo_ismapped():
                    evidence_box.pack_forget()
                else:
                    evidence_box.pack(fill="x", padx=14, pady=(0, 10))

            ctk.CTkButton(
                footer_bar, text="🔍 View Log Evidence", width=130, height=22, corner_radius=6,
                fg_color=TAG_BG, hover_color=BORDER_SUBTLE, text_color=TEXT_SECONDARY,
                font=ctk.CTkFont(family="Segoe UI", size=11), command=_toggle_evidence
            ).pack(side="right")

        self._scroll_to_bottom()
        return body_label

    def _copy_to_clipboard(self, text: str):
        self.clipboard_clear()
        self.clipboard_append(text)

    def _scroll_to_bottom(self):
        self.update_idletasks()
        self.chat_feed._parent_canvas.yview_moveto(1.0)

    def _on_send_clicked(self):
        query = self.entry_prompt.get().strip()
        if not query:
            return
        if self.orchestrator is None:
            messagebox.showwarning("Agent Not Initialized", "Please upload your logs and click 'Initialize Agent' on Home first.")
            return

        self.entry_prompt.delete(0, "end")
        self._add_user_bubble(query)

        prepared = self.orchestrator.prepare_turn(query)

        if prepared["mode"] == "instant":
            self._add_ai_response_card(
                body_text=prepared["response"],
                status_tag=prepared["status_tag"],
                phase_tag=prepared["phase_tag"],
                evidence_text=prepared["evidence"]
            )
            return

        initial_text = prepared["instant_header"] + "⏳ Synthesizing root cause & remediation steps..."
        target_label = self._add_ai_response_card(
            body_text=initial_text,
            status_tag=prepared["status_tag"],
            phase_tag=prepared["phase_tag"],
            evidence_text=prepared["evidence"]
        )

        self.btn_send.configure(state="disabled")
        self.lbl_ready_dot.configure(text="● Streaming...", text_color="#3B82F6")

        def _stream_worker():
            accumulated = prepared["instant_header"]
            try:
                for token in self.orchestrator.stream_llm_explanation(prepared):
                    accumulated += token
                    self.after(0, lambda txt=accumulated: target_label.configure(text=txt))
                self.after(0, self._on_stream_finished)
            except Exception as err:
                err_txt = accumulated + f"\n[Error: {err}]"
                self.after(0, lambda txt=err_txt: target_label.configure(text=txt))
                self.after(0, self._on_stream_finished)

        threading.Thread(target=_stream_worker, daemon=True).start()

    def _on_stream_finished(self):
        self.btn_send.configure(state="normal")
        self.lbl_ready_dot.configure(text="● Ready", text_color=STATUS_GREEN)
        self._scroll_to_bottom()


if __name__ == "__main__":
    app = IntuneRAGDesktopApp()
    app.mainloop()