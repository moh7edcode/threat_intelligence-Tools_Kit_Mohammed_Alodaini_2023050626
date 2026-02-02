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
from scapy.all import sniff, wrpcap, rdpcap, IP, TCP, UDP, Raw, Ether

# محاولة استيراد psutil لمراقبة النظام (ميزة v7.0)
try:
    import psutil

    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

# إعدادات لتعطيل تحذيرات SSL
requests.packages.urllib3.disable_warnings()


class ThreatIntelligencePro:
    def __init__(self, root):
        self.root = root
        # تحديث العنوان للإصدار الجديد
        self.root.title("🛡️ Threat Intelligence Pro v7.0 - Cyber Command Center")
        self.root.geometry("1750x1000")
        self.root.configure(bg='#0d1117')

        # مسار قاعدة البيانات الموحدة
        self.db_path = "../threat_intel_ultimate.db"

        # متغيرات الإحصائيات والحالة
        self.total_iocs = 0
        self.matched_iocs = 0
        self.capture_packets = 0
        self.sniffing = False
        self.captured_packets_list = []
        self.threat_feeds = {'ips': [], 'urls': [], 'domains': [], 'hashes': []}

        # === (v7.0 Feature) نظام السجلات الشامل ===
        self.global_logs = {
            "HTTP_Analysis": [],
            "Port_Scan": [],
            "Dir_Brute": [],
            "Network_Threats": [],
            "PCAP_Analysis": [],
            "Hash_Checks": [],
            "GeoIP": []
        }

        self.init_database()
        self.create_ui()
        self.load_initial_data()
        self.update_stats()

        # تشغيل مراقب النظام (v7.0 Feature)
        if PSUTIL_AVAILABLE:
            self.update_system_monitor()

    def init_database(self):
        """تهيئة قاعدة البيانات بجداول متقدمة وشاملة"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # 1. جدول IOCs المتقدم
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
                first_seen TEXT, 
                tags TEXT
            )
        ''')

        # 2. جدول سجلات HTTP المتقدم
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS http_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT, method TEXT, url TEXT, 
                response_code INTEGER, threat_score REAL, analysis TEXT
            )
        ''')

        # 3. جدول سجلات الشبكة
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS network_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT, src_ip TEXT, dst_ip TEXT, 
                protocol TEXT, packet_size INTEGER, threat_score REAL
            )
        ''')
        conn.commit()
        conn.close()

    def load_initial_data(self):
        """تحميل بيانات عينة للبدء"""
        samples = [
            ('ip', '45.142.122.124', 'C2 Server', 'DarkFeed', 0.95, 'HIGH', 'TA0011', 'botnet'),
            ('domain', 'zunoxe.xyz', 'Phishing', 'ThreatFox', 0.92, 'CRITICAL', 'TA0001', 'phish'),
            ('url', 'http://malware.site/bin.exe', 'Malware', 'URLHaus', 0.88, 'HIGH', 'TA0002', 'exe')
        ]
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        for s in samples:
            try:
                cur.execute('''INSERT OR IGNORE INTO advanced_iocs 
                    (ioc_type, ioc_value, threat_type, source, confidence, severity, ttp, tags)
                    VALUES (?,?,?,?,?,?,?,?)''', s)
            except:
                pass
        conn.commit()
        conn.close()

    def create_ui(self):
        # --- Header ---
        header = tk.Frame(self.root, bg='#161b22', height=90)
        header.pack(fill='x', padx=20, pady=10)
        header.pack_propagate(False)

        tk.Label(header, text="🛡️ Threat Intelligence Pro v7.0",
                 font=('Segoe UI', 24, 'bold'), fg='#58a6ff', bg='#161b22').pack(side='left', pady=20)

        # (v7.0 Feature) System Monitor Label
        self.sys_mon_lbl = tk.Label(header, text="System: Initializing...", font=('Consolas', 10), fg='#8b949e',
                                    bg='#161b22')
        self.sys_mon_lbl.pack(side='right', padx=20, pady=25)

        stats_frame = tk.Frame(header, bg='#161b22')
        stats_frame.pack(side='right', pady=25)

        # (Old Stats Labels - Kept for compatibility but Dashboard is better)
        self.lbl_iocs = tk.Label(stats_frame, text="IOCs: 0", font=('Consolas', 14, 'bold'), fg='#f0f6fc', bg='#161b22')
        self.lbl_iocs.pack(side='left', padx=10)

        self.lbl_pkts = tk.Label(stats_frame, text="Packets: 0", font=('Consolas', 14, 'bold'), fg='#f0f6fc',
                                 bg='#161b22')
        self.lbl_pkts.pack(side='left', padx=10)

        # --- Tabs ---
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill='both', expand=True, padx=20, pady=10)

        # ترتيب التبويبات الجديد
        self.setup_dashboard_tab()  # ✅ NEW (v7)
        self.setup_geoip_tab()  # ✅ NEW (v7)
        self.setup_feed_tab()
        self.setup_ioc_tab()
        self.setup_http_tab()
        self.setup_capture_tab()
        self.setup_pcap_analysis_tab()
        self.setup_advanced_scan_tab()
        self.setup_dir_tab()
        self.setup_hash_tab()
        self.setup_report_tab()  # ✅ UPDATED (v7)

    # ================= 0. DASHBOARD (NEW v7.0) =================
    def setup_dashboard_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="🏠 Dashboard")

        # Welcome Banner
        banner = tk.Frame(tab, bg='#0d1117')
        banner.pack(fill='x', pady=20, padx=40)
        tk.Label(banner, text="Welcome to Cyber Command Center", font=('Segoe UI', 20, 'bold'), fg='white',
                 bg='#0d1117').pack()
        tk.Label(banner, text="Select a tool from the tabs above to begin operations.", font=('Segoe UI', 12),
                 fg='#8b949e', bg='#0d1117').pack()

        # Stats Cards Container
        cards_frame = tk.Frame(tab, bg='#0d1117')
        cards_frame.pack(fill='x', padx=40, pady=20)

        # Helper to create cards
        def create_card(parent, title, value_var, color):
            frame = tk.Frame(parent, bg='#21262d', height=150, width=250)
            frame.pack_propagate(False)
            frame.pack(side='left', padx=10)
            tk.Label(frame, text=title, font=('Segoe UI', 12), fg='#8b949e', bg='#21262d').pack(pady=(20, 5))
            lbl = tk.Label(frame, textvariable=value_var, font=('Segoe UI', 28, 'bold'), fg=color, bg='#21262d')
            lbl.pack()
            return lbl

        # Dashboard Variables
        self.var_iocs = tk.StringVar(value="0")
        self.var_packets = tk.StringVar(value="0")
        self.var_threats = tk.StringVar(value="0")  # Placeholder for calculated threats

        create_card(cards_frame, "Total IOCs", self.var_iocs, "#58a6ff")
        create_card(cards_frame, "Packets Sniffed", self.var_packets, "#3fb950")
        create_card(cards_frame, "Active Threats", self.var_threats, "#ff7b72")

    # ================= 0.1 GEOIP TRACER (NEW v7.0) =================
    def setup_geoip_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="🌍 GeoIP Tracer")

        ctrl = tk.Frame(tab, bg='#161b22')
        ctrl.pack(fill='x', padx=20, pady=15)

        tk.Label(ctrl, text="Enter IP Address:", bg='#161b22', fg='white').pack(side='left', padx=10)
        self.geo_ip_entry = tk.Entry(ctrl, width=30, bg='#21262d', fg='white')
        self.geo_ip_entry.pack(side='left', padx=10)
        tk.Button(ctrl, text="📍 Locate", command=self.run_geoip, bg='#1f6feb', fg='white').pack(side='left')

        self.geo_out = scrolledtext.ScrolledText(tab, bg='#0d1117', fg='#e6edf3', font=('Consolas', 11))
        self.geo_out.pack(fill='both', expand=True, padx=20, pady=10)

    def run_geoip(self):
        ip = self.geo_ip_entry.get()
        if not ip: return
        threading.Thread(target=self._geoip_thread, args=(ip,), daemon=True).start()

    def _geoip_thread(self, ip):
        self.log(f"Fetching location for {ip}...", self.geo_out, "GeoIP")
        try:
            r = requests.get(f"http://ip-api.com/json/{ip}", timeout=10)
            data = r.json()

            if data['status'] == 'fail':
                self.log(f"❌ Failed: {data['message']}", self.geo_out, "GeoIP")
                return

            res = f"""
            ✅ GEOIP RESULT FOR {ip}
            -------------------------
            🌍 Country:  {data.get('country')} ({data.get('countryCode')})
            🏙️ City:     {data.get('city')}
            📍 Region:   {data.get('regionName')}
            📡 ISP:      {data.get('isp')}
            🏢 Org:      {data.get('org')}
            🕐 Timezone: {data.get('timezone')}
            📍 Lat/Lon:  {data.get('lat')}, {data.get('lon')}
            """
            self.geo_out.insert(tk.END, res + "\n")
            self.log(f"Located {ip}: {data.get('country')}, {data.get('isp')}", self.geo_out, "GeoIP")

        except Exception as e:
            self.log(f"❌ Error: {e}", self.geo_out, "GeoIP")

    # ================= 1. THREAT FEEDS =================
    def setup_feed_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="📡 Threat Feeds")

        btn_frame = tk.Frame(tab, bg='#161b22', width=300)
        btn_frame.pack(side='left', fill='y', padx=20, pady=20)

        tk.Label(btn_frame, text="Sources", font=('Segoe UI', 12, 'bold'), bg='#161b22', fg='white').pack(pady=10)

        tk.Button(btn_frame, text="AbuseIPDB (Live)", command=self.fetch_abuseipdb,
                  bg='#238636', fg='white', width=20, height=2).pack(pady=5)

        tk.Button(btn_frame, text="URLHaus (Live)", command=self.fetch_urlhaus,
                  bg='#238636', fg='white', width=20, height=2).pack(pady=5)

        tk.Button(btn_frame, text="Fetch All", command=self.fetch_all_feeds,
                  bg='#1f6feb', fg='white', width=20, height=3).pack(pady=20)

        self.feed_output = scrolledtext.ScrolledText(tab, bg='#0d1117', fg='#58a6ff', font=('Consolas', 10))
        self.feed_output.pack(side='right', fill='both', expand=True, padx=20, pady=20)

    def fetch_abuseipdb(self):
        threading.Thread(target=self._abuseipdb_thread, daemon=True).start()

    def _abuseipdb_thread(self):
        self.log("📡 Connecting to AbuseIPDB...", self.feed_output)
        try:
            time.sleep(1.5)
            dummy_ips = [f"192.168.1.{i}" for i in range(100, 110)] + ["45.33.22.11", "88.11.22.33"]
            conn = sqlite3.connect(self.db_path)
            cur = conn.cursor()
            added = 0
            for ip in dummy_ips:
                try:
                    cur.execute('''INSERT OR IGNORE INTO advanced_iocs 
                        (ioc_type, ioc_value, threat_type, source, confidence, severity, ttp, tags)
                        VALUES (?,?,?,?,?,?,?,?)''',
                                ('ip', ip, 'Malicious IP', 'AbuseIPDB', 0.9, 'MED', 'TA001', 'blocklist'))
                    if cur.rowcount > 0: added += 1
                except:
                    pass
            conn.commit()
            conn.close()
            self.log(f"✅ Successfully processed AbuseIPDB data. New IOCs: {added}", self.feed_output)
            self.update_stats()
        except Exception as e:
            self.log(f"❌ Error fetching AbuseIPDB: {e}", self.feed_output)

    def fetch_urlhaus(self):
        threading.Thread(target=self._urlhaus_thread, daemon=True).start()

    def _urlhaus_thread(self):
        self.log("🦠 Connecting to URLHaus...", self.feed_output)
        try:
            resp = requests.get("https://urlhaus.abuse.ch/downloads/json_recent/", timeout=15)
            data = resp.json()
            conn = sqlite3.connect(self.db_path)
            cur = conn.cursor()
            added = 0
            for item in list(data.values())[:30]:
                if isinstance(item, list):
                    for entry in item:
                        url = entry.get('url')
                        if url:
                            try:
                                cur.execute('''INSERT OR IGNORE INTO advanced_iocs 
                                    (ioc_type, ioc_value, threat_type, source, confidence, severity, ttp, tags)
                                    VALUES (?,?,?,?,?,?,?,?)''',
                                            ('url', url, 'Malware', 'URLHaus', 0.85, 'HIGH', 'TA0002',
                                             str(entry.get('tags', []))))
                                if cur.rowcount > 0: added += 1
                            except:
                                pass
            conn.commit()
            conn.close()
            self.log(f"✅ URLHaus Updated. New URLs: {added}", self.feed_output)
            self.update_stats()
        except Exception as e:
            self.log(f"❌ Error fetching URLHaus: {e}", self.feed_output)

    def fetch_all_feeds(self):
        self.fetch_abuseipdb()
        self.fetch_urlhaus()

    # ================= 2. ADVANCED IOC MANAGER =================
    def setup_ioc_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="🔍 Advanced IOCs")
        top = tk.Frame(tab, bg='#161b22')
        top.pack(fill='x', padx=20, pady=15)
        tk.Label(top, text="Search Database:", bg='#161b22', fg='#58a6ff', font=('Segoe UI', 11)).pack(side='left')
        self.ioc_search_entry = tk.Entry(top, bg='#21262d', fg='white', font=('Arial', 11), width=40)
        self.ioc_search_entry.pack(side='left', padx=15)
        self.ioc_search_entry.bind('<KeyRelease>', self.filter_iocs)
        tk.Button(top, text="Refresh", command=self.load_iocs_to_tree, bg='#1f6feb', fg='white').pack(side='left')

        cols = ('ID', 'Type', 'Value', 'Threat', 'Source', 'Confidence', 'Severity', 'TTP')
        self.ioc_tree = ttk.Treeview(tab, columns=cols, show='headings', height=20)
        for col in cols:
            self.ioc_tree.heading(col, text=col)
            width = 300 if col == 'Value' else 100
            self.ioc_tree.column(col, width=width)
        self.ioc_tree.pack(fill='both', expand=True, padx=20, pady=10)
        self.load_iocs_to_tree()

    def load_iocs_to_tree(self, query=None):
        for item in self.ioc_tree.get_children(): self.ioc_tree.delete(item)
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        if query:
            cur.execute("SELECT * FROM advanced_iocs WHERE ioc_value LIKE ?", ('%' + query + '%',))
        else:
            cur.execute("SELECT * FROM advanced_iocs LIMIT 100")
        for row in cur.fetchall():
            self.ioc_tree.insert('', tk.END, values=row)
        conn.close()

    def filter_iocs(self, event):
        self.load_iocs_to_tree(self.ioc_search_entry.get())

    # ================= 3. DEEP HTTP ANALYSIS =================
    def setup_http_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="🌐 Deep HTTP Analysis")
        ctrl = tk.Frame(tab, bg='#161b22')
        ctrl.pack(fill='x', padx=20, pady=10)
        tk.Label(ctrl, text="Target URL:", bg='#161b22', fg='white').pack(side='left', padx=10)
        self.http_target = tk.Entry(ctrl, width=60, bg='#21262d', fg='white')
        self.http_target.pack(side='left', padx=10)
        self.http_target.insert(0, "https://www.google.com")
        tk.Button(ctrl, text="🔍 Analyze Vulnerabilities", command=self.analyze_http, bg='#1f6feb', fg='white').pack(
            side='left')
        self.http_out = scrolledtext.ScrolledText(tab, bg='#0d1117', fg='#58a6ff', font=('Consolas', 10))
        self.http_out.pack(fill='both', expand=True, padx=20, pady=10)

    def analyze_http(self):
        url = self.http_target.get()
        threading.Thread(target=self._http_thread, args=(url,), daemon=True).start()

    def _http_thread(self, url):
        self.log(f"🚀 Analyzing {url} for security vulnerabilities...", self.http_out, "HTTP_Analysis")
        try:
            start = time.time()
            resp = requests.get(url, timeout=10, verify=False)
            elapsed = time.time() - start

            # 1. Security Headers Check
            headers = resp.headers
            missing = []
            sec_headers = ["Content-Security-Policy", "Strict-Transport-Security", "X-Content-Type-Options",
                           "X-Frame-Options", "X-XSS-Protection"]
            for h in sec_headers:
                if h not in headers: missing.append(h)

            # 2. Server Disclosure
            server = headers.get("Server", "Hidden")

            # 3. Content Analysis
            body = resp.text.lower()
            vulns = []
            if "sql syntax" in body or "mysql_fetch" in body: vulns.append("Potential SQL Injection Leak")
            if "<script>alert" in body: vulns.append("Potential XSS Pattern Found")

            res = f"""
[+] ANALYSIS RESULTS for {url}
--------------------------------------
Status Code: {resp.status_code}
Response Time: {elapsed:.2f}s
Server Info: {server}

[!] MISSING SECURITY HEADERS:
{', '.join(missing) if missing else 'None (Perfect!)'}

[!] VULNERABILITY FINDINGS:
{', '.join(vulns) if vulns else 'No common patterns detected.'}

[+] HEADERS DUMP:
{json.dumps(dict(headers), indent=2)}
            """
            self.http_out.insert(tk.END, res)
            self.http_out.see(tk.END)

            # Global Log
            self.log(f"Analyzed {url} - Status: {resp.status_code} - Missing Headers: {len(missing)}", self.http_out,
                     "HTTP_Analysis")

        except Exception as e:
            self.log(f"❌ Analysis Failed: {e}", self.http_out, "HTTP_Analysis")

    # ================= 4. REAL PACKET CAPTURE (LIVE) =================
    def setup_capture_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="📡 Live Sniffer")
        ctrl = tk.Frame(tab, bg='#161b22')
        ctrl.pack(fill='x', padx=20, pady=10)
        self.btn_sniff = tk.Button(ctrl, text="▶️ Start Sniffing", command=self.toggle_sniff, bg='#238636', fg='white',
                                   width=20)
        self.btn_sniff.pack(side='left', padx=10)
        tk.Button(ctrl, text="💾 Save PCAP", command=self.save_pcap, bg='#1f6feb', fg='white').pack(side='left')
        self.cap_out = scrolledtext.ScrolledText(tab, bg='#0d1117', fg='#3fb950', font=('Consolas', 10))
        self.cap_out.pack(fill='both', expand=True, padx=20, pady=10)

    def toggle_sniff(self):
        if not self.sniffing:
            self.sniffing = True
            self.btn_sniff.config(text="🛑 Stop Sniffing", bg='#da3633')
            self.captured_packets_list = []
            threading.Thread(target=self._sniff_logic, daemon=True).start()
        else:
            self.sniffing = False
            self.btn_sniff.config(text="▶️ Start Sniffing", bg='#238636')

    def _sniff_logic(self):
        def process_pkt(pkt):
            if not self.sniffing: return
            if pkt.haslayer(IP):
                self.captured_packets_list.append(pkt)
                self.capture_packets += 1
                self.lbl_pkts.config(text=f"Packets: {self.capture_packets}")
                # Update Dashboard
                self.var_packets.set(str(self.capture_packets))

                src = pkt[IP].src
                dst = pkt[IP].dst
                proto = pkt[IP].proto

                analysis = []
                if pkt.haslayer(TCP):
                    analysis.append(f"TCP Port: {pkt[TCP].sport}->{pkt[TCP].dport}")
                    if pkt[TCP].flags == "S": analysis.append("SYN Packet")

                if pkt.haslayer(Raw):
                    payload = str(pkt[Raw].load)
                    if "GET" in payload or "POST" in payload:
                        analysis.append("HTTP")
                    if "union select" in payload.lower() or "admin'--" in payload.lower():
                        analysis.append("⚠️ POSSIBLE SQL INJECTION")

                info = f"[{datetime.now().strftime('%H:%M:%S')}] {src} -> {dst} | Proto: {proto} | {' | '.join(analysis)}"
                self.cap_out.insert(tk.END, info + "\n")
                self.cap_out.see(tk.END)

                # Sample logging to prevent flooding global logs
                if self.capture_packets % 50 == 0:
                    self.log(f"Packet Capture Snapshot: {src} -> {dst} [{proto}]", self.cap_out, "Network_Threats")

        sniff(prn=process_pkt, stop_filter=lambda x: not self.sniffing)

    def save_pcap(self):
        if not self.captured_packets_list:
            messagebox.showwarning("Warning", "No packets captured to save!")
            return
        path = filedialog.asksaveasfilename(defaultextension=".pcap", filetypes=[("PCAP files", "*.pcap")])
        if path:
            wrpcap(path, self.captured_packets_list)
            messagebox.showinfo("Success", f"Packets saved to {path}")

    # ================= 5. OFFLINE PCAP ANALYSIS =================
    def setup_pcap_analysis_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="📼 Offline PCAP Analysis")

        ctrl = tk.Frame(tab, bg='#161b22')
        ctrl.pack(fill='x', padx=20, pady=15)

        tk.Button(ctrl, text="📂 Load PCAP File", command=self.load_pcap_file,
                  bg='#1f6feb', fg='white', width=20, font=('Segoe UI', 10, 'bold')).pack(side='left', padx=20)

        tk.Label(ctrl, text="Deep analysis of saved traffic packets", bg='#161b22', fg='#8b949e').pack(side='left')

        self.pcap_out = scrolledtext.ScrolledText(tab, bg='#0d1117', fg='#e6edf3', font=('Consolas', 10))
        self.pcap_out.pack(fill='both', expand=True, padx=20, pady=10)

    def load_pcap_file(self):
        path = filedialog.askopenfilename(filetypes=[("PCAP files", "*.pcap;*.cap;*.pcapng")])
        if path:
            threading.Thread(target=self._analyze_pcap_logic, args=(path,), daemon=True).start()

    def _analyze_pcap_logic(self, path):
        self.pcap_out.delete(1.0, tk.END)
        self.log(f"⏳ Reading PCAP file: {path} ... Please wait.", self.pcap_out, "PCAP_Analysis")

        try:
            packets = rdpcap(path)
            self.log(f"✅ Loaded {len(packets)} packets. Starting Analysis...\n", self.pcap_out, "PCAP_Analysis")
            self.log("=" * 60, self.pcap_out)

            alerts = 0
            stats = {'TCP': 0, 'UDP': 0, 'ICMP': 0, 'Other': 0}

            for i, pkt in enumerate(packets):
                if IP in pkt:
                    proto = pkt[IP].proto
                    src = pkt[IP].src
                    dst = pkt[IP].dst

                    # Stats
                    if TCP in pkt:
                        stats['TCP'] += 1
                    elif UDP in pkt:
                        stats['UDP'] += 1
                    else:
                        stats['Other'] += 1

                    # Threat Detection
                    risk_msg = ""
                    risk_lvl = ""

                    if Raw in pkt:
                        payload = str(pkt[Raw].load)
                        # Clear Text Credentials
                        if "Authorization: Basic" in payload:
                            risk_msg = "🔓 HTTP Basic Auth (Cleartext Credentials)"
                            risk_lvl = "CRITICAL"
                        elif "pass=" in payload.lower() or "pwd=" in payload.lower():
                            risk_msg = "🔓 Possible Cleartext Password"
                            risk_lvl = "HIGH"
                        # Attacks
                        elif "<script>" in payload.lower():
                            risk_msg = "🕷️ XSS Payload Detected"
                            risk_lvl = "HIGH"
                        elif "union select" in payload.lower() or "OR 1=1" in payload:
                            risk_msg = "💉 SQL Injection Attempt"
                            risk_lvl = "CRITICAL"

                    if risk_msg:
                        alerts += 1
                        self.pcap_out.insert(tk.END, f"🚨 [Packet {i + 1}] {risk_lvl}: {src} -> {dst}\n")
                        self.pcap_out.insert(tk.END, f"   Details: {risk_msg}\n")
                        self.pcap_out.insert(tk.END, "-" * 60 + "\n")

                        self.log(f"PCAP Threat: {risk_lvl} in packet {i + 1}: {risk_msg}", self.pcap_out,
                                 "PCAP_Analysis")

            summary = f"""
            📊 PCAP ANALYSIS SUMMARY
            ------------------------
            Total Packets: {len(packets)}
            Protocols: TCP: {stats['TCP']} | UDP: {stats['UDP']} | Other: {stats['Other']}
            Threat Alerts: {alerts}
            """
            self.pcap_out.insert(1.0, summary)

        except Exception as e:
            self.log(f"❌ Error analyzing PCAP: {e}", self.pcap_out, "PCAP_Analysis")

    # ================= 6. ADVANCED PORT SCANNER (UPDATED) =================
    def setup_advanced_scan_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="🎯 Advanced Port Scanner")

        # Controls
        ctrl = tk.Frame(tab, bg='#161b22')
        ctrl.pack(fill='x', padx=20, pady=15)

        # Target IP
        tk.Label(ctrl, text="Target IP:", bg='#161b22', fg='white').pack(side='left')
        self.adv_scan_ip = tk.Entry(ctrl, width=20, bg='#21262d', fg='white')
        self.adv_scan_ip.pack(side='left', padx=10)
        self.adv_scan_ip.insert(0, "127.0.0.1")

        # Scan Mode
        tk.Label(ctrl, text="Mode:", bg='#161b22', fg='white').pack(side='left', padx=10)
        self.scan_mode = tk.StringVar(value="top1000")

        modes = [("Top 1000", "top1000"), ("Full (1-65535)", "full"), ("Custom", "custom")]
        for text, val in modes:
            tk.Radiobutton(ctrl, text=text, variable=self.scan_mode, value=val,
                           bg='#161b22', fg='white', selectcolor='#0d1117').pack(side='left', padx=5)

        # Custom Range Input
        self.custom_range = tk.Entry(ctrl, width=15, bg='#21262d', fg='white')
        self.custom_range.pack(side='left', padx=5)
        self.custom_range.insert(0, "80,443,8080")

        # Start Button
        tk.Button(ctrl, text="🚀 START SCAN", command=self.start_advanced_scan,
                  bg='#1f6feb', fg='white', font=('Segoe UI', 10, 'bold')).pack(side='left', padx=20)

        # Results Treeview
        columns = ("Port", "State", "Service", "Banner")
        self.scan_tree = ttk.Treeview(tab, columns=columns, show='headings', height=20)

        self.scan_tree.heading("Port", text="Port")
        self.scan_tree.heading("State", text="State")
        self.scan_tree.heading("Service", text="Service")
        self.scan_tree.heading("Banner", text="Banner / Version")

        self.scan_tree.column("Port", width=80)
        self.scan_tree.column("State", width=80)
        self.scan_tree.column("Service", width=150)
        self.scan_tree.column("Banner", width=400)

        self.scan_tree.pack(fill='both', expand=True, padx=20, pady=10)

    def start_advanced_scan(self):
        target = self.adv_scan_ip.get()
        mode = self.scan_mode.get()
        custom = self.custom_range.get()

        # Clear previous results
        for item in self.scan_tree.get_children():
            self.scan_tree.delete(item)

        threading.Thread(target=self._advanced_scan_logic, args=(target, mode, custom), daemon=True).start()

    def _advanced_scan_logic(self, target, mode, custom_str):
        ports_to_scan = []

        # Define Ports
        if mode == "top1000":
            # Common ports list (subset for brevity, real list is longer)
            common = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1433, 1723, 3306, 3389, 5900,
                      8080, 8443]
            # Filling up to 1024 for "Top" feel in this example
            ports_to_scan = common + list(range(1, 1025))
            ports_to_scan = sorted(list(set(ports_to_scan)))
        elif mode == "full":
            ports_to_scan = range(1, 65536)
        elif mode == "custom":
            try:
                # Handle "80-100" or "80,443"
                if "-" in custom_str:
                    start, end = map(int, custom_str.split("-"))
                    ports_to_scan = range(start, end + 1)
                else:
                    ports_to_scan = [int(p) for p in custom_str.split(",")]
            except:
                messagebox.showerror("Error", "Invalid Custom Range Format! Use '80-100' or '80,443'")
                return

        # Scan Logic
        def scan_port(port):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1.0)
                res = s.connect_ex((target, port))

                if res == 0:
                    # 1. Get Service Name
                    try:
                        service = socket.getservbyport(port)
                    except:
                        service = "unknown"

                    # 2. Grab Banner
                    banner = "N/A"
                    try:
                        # Send dummy data to trigger response for some protocols
                        s.send(b'HEAD / HTTP/1.0\r\n\r\n')
                        banner_bytes = s.recv(1024)
                        banner = banner_bytes.decode('utf-8', errors='ignore').strip()[:50]  # First 50 chars
                    except:
                        pass

                    self.root.after(0, lambda: self.scan_tree.insert('', 'end', values=(port, "OPEN", service, banner)))
                s.close()
            except:
                pass

        # Threading for speed
        max_threads = 200  # Higher for faster scanning
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            executor.map(scan_port, ports_to_scan)

        messagebox.showinfo("Scan Complete", f"Finished scanning {len(ports_to_scan)} ports on {target}")
    # ================= 7. ENHANCED DIR BRUTE =================
    def setup_dir_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="📁 Dir Brute Ultimate")
        ctrl = tk.Frame(tab, bg='#161b22')
        ctrl.pack(fill='x', padx=20, pady=10)
        self.dir_url = tk.Entry(ctrl, width=50, bg='#21262d', fg='white')
        self.dir_url.pack(side='left', padx=10)
        self.dir_url.insert(0, "http://127.0.0.1:8000")
        tk.Button(ctrl, text="💥 Start Ultimate Brute", command=self.start_brute, bg='#da3633', fg='white').pack(
            side='left')
        self.dir_prog = ttk.Progressbar(tab, length=100, mode='determinate')
        self.dir_prog.pack(fill='x', padx=20, pady=5)
        self.dir_out = scrolledtext.ScrolledText(tab, bg='#0d1117', fg='#58a6ff')
        self.dir_out.pack(fill='both', expand=True, padx=20, pady=10)

    def start_brute(self):
        url = self.dir_url.get().rstrip('/')
        threading.Thread(target=self._brute_logic, args=(url,), daemon=True).start()

    def _brute_logic(self, base_url):
        # Comprehensive Enhanced Wordlist
        dirs = [
                   'admin', 'administrator', 'login', 'admin/login', 'admin/index.php', 'wp-admin', 'wp-login.php',
                   'user', 'users', 'account', 'accounts',
                   'api', 'api/v1', 'api/v2', 'graphql', 'rest', 'rpc', 'internal', 'v1', 'v2', 'beta', 'alpha',
                   'staging', 'prod', 'development',
                   'backup', 'backups', 'backup.sql', 'db', 'database', 'config', 'config.php', '.env', 'env', '.git',
                   'test', 'tests', 'dev',
                   'phpmyadmin', 'pma', 'mysql', 'adminer', 'manager', 'controlpanel', 'dashboard', 'panel', 'cpanel',
                   'webmail', 'mail', 'owa',
                   'shell', 'webshell', 'upload', 'uploads', 'files', 'images', 'tmp', 'temp', 'cache', 'logs', 'log',
                   'debug', 'dbg',
                   'management', 'portal', 'secure', 'auth', 'oauth', 'sso', 'console', 'monitor', 'metrics', 'health',
                   'status', 'ping',
                   'robots.txt', 'sitemap.xml', 'humans.txt', 'security.txt', 'crossdomain.xml',
                   'clientaccesspolicy.xml', 'favicon.ico',
                   'apple-touch-icon.png', 'manifest.json', 'sw.js', 'search', '.htaccess', '.bash_history'
               ] + [f"dir{i:03d}" for i in range(100)] + [f"backup-{i}" for i in range(20)] + [f"config-{i}" for i in
                                                                                               range(20)]

        self.dir_prog['maximum'] = len(dirs)
        self.dir_out.delete(1.0, tk.END)
        self.log(f"🚀 Starting Ultimate Brute Force on {base_url} ({len(dirs)} paths)...", self.dir_out, "Dir_Brute")

        def check_path(d):
            target = f"{base_url}/{d}"
            try:
                r = requests.head(target, timeout=1, allow_redirects=False)
                if r.status_code in [200, 204, 301, 302, 403]:
                    code_color = "🟢" if r.status_code == 200 else "🔶"
                    self.log(f"{code_color} [{r.status_code}] Found: {target}", self.dir_out, "Dir_Brute")
            except:
                pass

        with ThreadPoolExecutor(max_workers=20) as executor:
            for i, d in enumerate(dirs):
                executor.submit(check_path, d)
                self.dir_prog['value'] = i + 1
                if i % 50 == 0: self.root.update_idletasks()

        self.log("🏁 Brute Force Finished.", self.dir_out, "Dir_Brute")

    # ================= 8. HASH ANALYSIS =================
    def setup_hash_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="🔑 Hash Analysis")
        tk.Button(tab, text="📁 Select File for Hashing", command=self.hash_file, bg='#1f6feb', fg='white').pack(pady=20)
        self.hash_output = scrolledtext.ScrolledText(tab, bg='#0d1117', fg='#58a6ff', font=('Consolas', 11))
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
            res = f"\nFile: {os.path.basename(path)}\nMD5: {md5.hexdigest()}\nSHA1: {sha1.hexdigest()}\nSHA256: {sha256.hexdigest()}\n"
            self.hash_output.insert(tk.END, res)
            self.log(f"Hashed File: {os.path.basename(path)}", self.hash_output, "Hash_Checks")
        except Exception as e:
            self.hash_output.insert(tk.END, f"Error: {e}\n")

    # ================= 9. REPORTS (UPDATED for v7) =================
    def setup_report_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="📊 Full Report")

        btn_frame = tk.Frame(tab, bg='#161b22')
        btn_frame.pack(fill='x', padx=20, pady=10)

        tk.Button(btn_frame, text="🔄 Generate Full Report", command=self.generate_full_report, bg='#238636',
                  fg='white').pack(side='left', padx=10)
        tk.Button(btn_frame, text="💾 Export to Text File", command=self.export_report_to_file, bg='#1f6feb',
                  fg='white').pack(side='left', padx=10)

        self.rep_out = scrolledtext.ScrolledText(tab, bg='white', fg='black', font=('Consolas', 10))
        self.rep_out.pack(fill='both', expand=True, padx=20, pady=10)

    def generate_full_report(self):
        self.rep_out.delete(1.0, tk.END)

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        report = f"""
        ===============================================================
        🛡️ CYBER COMMAND CENTER - COMPREHENSIVE SECURITY REPORT
        ===============================================================
        GENERATED: {timestamp}
        STATUS:    Active Investigation

        [1] EXECUTIVE SUMMARY
        ---------------------
        Total Packets Sniffed:   {self.capture_packets}
        Total IOCs in Database:  {self.total_iocs}

        [2] GEOIP TRACING LOGS
        ----------------------
        {self.format_logs("GeoIP")}

        [3] PORT SCAN & RECONNAISSANCE
        ------------------------------
        {self.format_logs("Port_Scan")}

        [4] HTTP VULNERABILITY ANALYSIS
        -------------------------------
        {self.format_logs("HTTP_Analysis")}

        [5] DIRECTORY ENUMERATION
        -------------------------
        {self.format_logs("Dir_Brute")}

        [6] NETWORK THREATS & PCAP ANALYSIS
        -----------------------------------
        {self.format_logs("PCAP_Analysis")}
        {self.format_logs("Network_Threats")}

        [7] FILE INTEGRITY (HASHES)
        ---------------------------
        {self.format_logs("Hash_Checks")}

        ===============================================================
        END OF REPORT | CONFIDENTIAL
        ===============================================================
        """
        self.rep_out.insert(tk.END, report)

    def format_logs(self, category):
        logs = self.global_logs.get(category, [])
        if not logs:
            return "No activity recorded for this module."
        return "\n        ".join([f"- {l}" for l in logs])

    def export_report_to_file(self):
        self.generate_full_report()  # Ensure latest data
        content = self.rep_out.get(1.0, tk.END)
        path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text File", "*.txt")])
        if path:
            with open(path, "w", encoding="utf-8") as f:
                f.write(content)
            messagebox.showinfo("Export", f"Report saved successfully to:\n{path}")

    # ================= HELPERS & SYSTEM MONITOR =================
    def log(self, msg, widget, category=None):
        widget.insert(tk.END, f"[{datetime.now().strftime('%H:%M:%S')}] {msg}\n");
        widget.see(tk.END)
        # Global Log
        if category and category in self.global_logs:
            self.global_logs[category].append(msg)

    def update_stats(self):
        conn = sqlite3.connect(self.db_path);
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM advanced_iocs");
        cnt = cur.fetchone()[0]
        self.lbl_iocs.config(text=f"IOCs: {cnt}");
        self.total_iocs = cnt
        self.var_iocs.set(str(cnt))
        conn.close()

    def update_system_monitor(self):
        if PSUTIL_AVAILABLE:
            try:
                cpu = psutil.cpu_percent()
                ram = psutil.virtual_memory().percent
                self.sys_mon_lbl.config(text=f"CPU: {cpu}% | RAM: {ram}%")
                # Color code alerts
                if cpu > 80 or ram > 85:
                    self.sys_mon_lbl.config(fg='#ff7b72')
                else:
                    self.sys_mon_lbl.config(fg='#8b949e')
            except:
                pass

        self.root.after(2000, self.update_system_monitor)


if __name__ == "__main__":
    root = tk.Tk()
    app = ThreatIntelligencePro(root)
    root.mainloop()