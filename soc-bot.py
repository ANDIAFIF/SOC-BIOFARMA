#!/usr/bin/env python3
"""
SOC IP Reputation Checker - BIOFARMA
=====================================
Unified script for CLI and Telegram Bot

Usage:
    python3 soc_bot.py              # Run CLI mode
    python3 soc_bot.py --telegram   # Run Telegram Bot mode
    python3 soc_bot.py --bot        # Run Telegram Bot mode (alias)

Features:
    - Check IP reputation via VirusTotal & AbuseIPDB
    - Auto-blacklist malicious IPs
    - Auto-push to GitHub
    - Support SIEM data format (QRadar/Splunk)
    - Role-based access (Admin/Staff)
    - Dump IP by date range
"""

from email import message
import os
import sys
import re
import json
import logging
import argparse
import tempfile
import base64
from datetime import datetime, timedelta

# Fix encoding untuk Linux terminal
if sys.stdout.encoding != 'utf-8':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except AttributeError:
        pass  # Python < 3.7

# ==================================================
# AUTO INSTALL DEPENDENCIES
# ==================================================
def install_package(package):
    import subprocess
    subprocess.check_call([sys.executable, "-m", "pip", "install", package, "-q"])

try:
    from dotenv import load_dotenv
except ImportError:
    print("Installing python-dotenv...")
    install_package("python-dotenv")
    from dotenv import load_dotenv

try:
    import requests
except ImportError:
    print("Installing requests...")
    install_package("requests")
    import requests

try:
    import aiohttp
except ImportError:
    print("Installing aiohttp...")
    install_package("aiohttp")
    import aiohttp

import asyncio

# Load environment variables
load_dotenv()

# ==================================================
# CONFIGURATION
# ==================================================
VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")

# Paths
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
BLACKLIST_FILE = os.path.join(SCRIPT_DIR, "List-IP-Blacklist.txt")
BLACKLIST_DB_FILE = os.path.join(SCRIPT_DIR, "blacklist_db.json")  # New: untuk tracking timestamp
ACTIVITY_DB_FILE = os.path.join(SCRIPT_DIR, "activity_db.json")   # Audit trail blacklist actions

# Domain Blacklist Paths
DOMAIN_BLACKLIST_FILE = os.path.join(SCRIPT_DIR, "List-Domain-Blacklist.txt")
DOMAIN_BLACKLIST_DB_FILE = os.path.join(SCRIPT_DIR, "domain_blacklist_db.json")

# GitHub Configuration
GITHUB_REMOTE = os.getenv("GITHUB_REMOTE", "origin")
GITHUB_BRANCH = os.getenv("GITHUB_BRANCH", "main")

# API Endpoints
VT_URL = "https://www.virustotal.com/api/v3/ip_addresses/{}"
ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"

# Telegram Security
SUPER_ADMIN_ID = 6872081104          # Super admin — can manage admins
ADMIN_IDS = {SUPER_ADMIN_ID}        # Seed; extended at runtime by admin_db.json
ALLOWED_GROUP_IDS = {-1002863933728}  # Allowed group chats

# Staff / Admin database files
STAFF_FILE = os.path.join(SCRIPT_DIR, "staff.json")
ADMIN_DB_FILE = os.path.join(SCRIPT_DIR, "admin_db.json")


# ==================================================
# STAFF MANAGEMENT
# ==================================================
def load_staff() -> dict:
    """Load staff database"""
    if not os.path.exists(STAFF_FILE):
        return {"staff": {}, "pending": {}}
    try:
        with open(STAFF_FILE, "r") as f:
            data = json.load(f)
            # Ensure structure
            if "staff" not in data:
                data["staff"] = {}
            if "pending" not in data:
                data["pending"] = {}
            return data
    except:
        return {"staff": {}, "pending": {}}


def save_staff(data: dict):
    """Save staff database"""
    with open(STAFF_FILE, "w") as f:
        json.dump(data, f, indent=2)


def add_staff(user_id: int, username: str, added_by: int) -> bool:
    """Add new staff member"""
    data = load_staff()
    user_id_str = str(user_id)
    if user_id_str in data["staff"]:
        return False
    data["staff"][user_id_str] = {
        "username": username,
        "added_by": added_by,
        "added_at": datetime.now().isoformat()
    }
    save_staff(data)
    logger.info(f"STAFF_ADDED | ID={user_id} | BY={added_by}")
    return True


def remove_staff(user_id: int) -> bool:
    """Remove staff member"""
    data = load_staff()
    user_id_str = str(user_id)
    if user_id_str not in data["staff"]:
        return False
    del data["staff"][user_id_str]
    save_staff(data)
    logger.info(f"STAFF_REMOVED | ID={user_id}")
    return True


def get_all_staff() -> dict:
    """Get all staff members"""
    data = load_staff()
    return data.get("staff", {})


def is_staff(user_id: int) -> bool:
    """Check if user is staff"""
    data = load_staff()
    return str(user_id) in data.get("staff", {})


def is_super_admin(user_id: int) -> bool:
    """Check if user is the super admin"""
    return user_id == SUPER_ADMIN_ID


def load_admin_db() -> dict:
    """Load admin database"""
    if not os.path.exists(ADMIN_DB_FILE):
        return {"admins": {}}
    try:
        with open(ADMIN_DB_FILE, "r") as f:
            data = json.load(f)
            if "admins" not in data:
                data["admins"] = {}
            return data
    except Exception:
        return {"admins": {}}


def save_admin_db(data: dict):
    """Save admin database"""
    with open(ADMIN_DB_FILE, "w") as f:
        json.dump(data, f, indent=2)


def get_all_admins() -> dict:
    """Get all extra admins from DB"""
    return load_admin_db().get("admins", {})


def add_admin(user_id: int, username: str, added_by: int) -> bool:
    """Add new admin (super admin only)"""
    if user_id == SUPER_ADMIN_ID:
        return False  # Already super admin
    data = load_admin_db()
    uid_str = str(user_id)
    if uid_str in data["admins"]:
        return False
    data["admins"][uid_str] = {
        "username": username,
        "added_by": added_by,
        "added_at": datetime.now().isoformat()
    }
    save_admin_db(data)
    # Refresh ADMIN_IDS at runtime
    ADMIN_IDS.add(user_id)
    return True


def remove_admin(user_id: int) -> bool:
    """Remove an admin (super admin only)"""
    if user_id == SUPER_ADMIN_ID:
        return False  # Cannot remove super admin
    data = load_admin_db()
    uid_str = str(user_id)
    if uid_str not in data["admins"]:
        return False
    del data["admins"][uid_str]
    save_admin_db(data)
    ADMIN_IDS.discard(user_id)
    return True


def is_admin(user_id: int) -> bool:
    """Check if user is admin (includes super admin and DB admins)"""
    if user_id in ADMIN_IDS:
        return True
    # Also check DB in case ADMIN_IDS wasn't refreshed
    return str(user_id) in load_admin_db().get("admins", {})


def get_user_role(user_id: int) -> str:
    """Get user role: admin, staff, or none"""
    if is_admin(user_id):
        return "admin"
    if is_staff(user_id):
        return "staff"
    return "none"

# ==================================================
# LOGGING
# ==================================================
LOG_DIR = os.path.join(SCRIPT_DIR, "logs")
os.makedirs(LOG_DIR, exist_ok=True)
_start_ts = datetime.now().strftime("%Y%m%d_%H%M%S")
LOG_FILE = os.path.join(LOG_DIR, f"soc_bot_{_start_ts}.log")

# Custom formatter untuk console (dengan warna dan emoji)
class ColoredFormatter(logging.Formatter):
    """Custom formatter dengan warna untuk console output"""
    
    COLORS = {
        'DEBUG': '\033[36m',    # Cyan
        'INFO': '\033[32m',     # Green
        'WARNING': '\033[33m',  # Yellow
        'ERROR': '\033[31m',    # Red
        'CRITICAL': '\033[35m'  # Magenta
    }
    RESET = '\033[0m'
    
    def format(self, record):
        # Skip HTTP request logs dari library eksternal
        if 'HTTP Request:' in record.getMessage():
            return ''  # Return empty string instead of None
            
        levelname = record.levelname
        color = self.COLORS.get(levelname, self.RESET)
        
        # Format timestamp
        timestamp = datetime.fromtimestamp(record.created).strftime('%Y-%m-%d %H:%M:%S')
        
        # Custom format berdasarkan jenis log
        msg = record.getMessage()
        
        # Jika ini log dari telegram bot
        if 'TELEGRAM_BOT' in msg or 'BOT_' in msg:
            return f"{color}[{timestamp}] {msg}{self.RESET}"
        
        # Log biasa
        return f"{color}[{timestamp}] [{levelname}] {msg}{self.RESET}"

# File formatter (tanpa warna)
file_formatter = logging.Formatter(
    '%(asctime)s | %(levelname)s | %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

# Console formatter (dengan warna)
console_formatter = ColoredFormatter()

# Custom filter untuk skip HTTP logs
class SkipHTTPFilter(logging.Filter):
    def filter(self, record):
        return 'HTTP Request:' not in record.getMessage()

# Setup handlers
file_handler = logging.FileHandler(LOG_FILE)
file_handler.setFormatter(file_formatter)
file_handler.setLevel(logging.INFO)

console_handler = logging.StreamHandler()
console_handler.setFormatter(console_formatter)
console_handler.setLevel(logging.INFO)
console_handler.addFilter(SkipHTTPFilter())  # Add filter to skip HTTP logs

# Configure root logger
logging.basicConfig(
    level=logging.INFO,
    handlers=[file_handler, console_handler]
)

# Dapatkan logger untuk script ini
logger = logging.getLogger(__name__)

# SUPPRESS logging dari library eksternal yang berisik
logging.getLogger('httpx').setLevel(logging.WARNING)
logging.getLogger('httpcore').setLevel(logging.WARNING)
logging.getLogger('telegram').setLevel(logging.WARNING)
logging.getLogger('telegram.ext').setLevel(logging.WARNING)
logging.getLogger('urllib3').setLevel(logging.WARNING)
logging.getLogger('aiohttp').setLevel(logging.WARNING)

# ==================================================
# CLI COLORS
# ==================================================
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    RESET = '\033[0m'

# ==================================================
# CORE FUNCTIONS
# ==================================================
def validate_ip(ip: str) -> bool:
    """Validate IP address format"""
    pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if re.match(pattern, ip):
        parts = ip.split('.')
        return all(0 <= int(part) <= 255 for part in parts)
    return False


def is_private_ip(ip: str) -> bool:
    """Check if IP is private/internal"""
    parts = list(map(int, ip.split('.')))
    if parts[0] == 10:
        return True
    if parts[0] == 172 and 16 <= parts[1] <= 31:
        return True
    if parts[0] == 192 and parts[1] == 168:
        return True
    if parts[0] == 127:
        return True
    return False


def ip_to_int(ip: str) -> int:
    """Convert IP address string to integer"""
    parts = list(map(int, ip.split('.')))
    return (parts[0] << 24) + (parts[1] << 16) + (parts[2] << 8) + parts[3]


def int_to_ip(num: int) -> str:
    """Convert integer to IP address string"""
    return f"{(num >> 24) & 0xFF}.{(num >> 16) & 0xFF}.{(num >> 8) & 0xFF}.{num & 0xFF}"


def expand_cidr(cidr: str) -> list:
    """Expand CIDR notation (e.g. 192.168.1.0/24) to list of individual IPs.
    Excludes network and broadcast address for subnets > /31."""
    try:
        ip_part, prefix_len = cidr.split('/')
        prefix_len = int(prefix_len)
        if not validate_ip(ip_part) or not (0 <= prefix_len <= 32):
            return []
        
        ip_int = ip_to_int(ip_part)
        # Calculate network address
        mask = (0xFFFFFFFF << (32 - prefix_len)) & 0xFFFFFFFF
        network = ip_int & mask
        broadcast = network | (~mask & 0xFFFFFFFF)
        
        # For /32 return single IP
        if prefix_len == 32:
            return [int_to_ip(network)]
        # For /31 return both IPs (point-to-point link)
        if prefix_len == 31:
            return [int_to_ip(network), int_to_ip(broadcast)]
        
        # For other subnets, exclude network and broadcast
        ips = []
        for i in range(network + 1, broadcast):
            ips.append(int_to_ip(i))
        return ips
    except (ValueError, IndexError):
        return []


def expand_ip_range(ip_range: str) -> list:
    """Expand IP range (e.g. 10.0.0.1-10.0.0.5 or 10.0.0.1-5) to list of IPs.
    Supports both full range (start_ip-end_ip) and short range (ip-last_octet)."""
    try:
        parts = ip_range.split('-')
        if len(parts) != 2:
            return []
        
        start_str = parts[0].strip()
        end_str = parts[1].strip()
        
        if not validate_ip(start_str):
            return []
        
        # Check if end is a full IP or just the last octet
        if validate_ip(end_str):
            # Full IP range: 10.0.0.1-10.0.0.5
            start_int = ip_to_int(start_str)
            end_int = ip_to_int(end_str)
        else:
            # Short range: 10.0.0.1-5 (only last octet)
            try:
                last_octet = int(end_str)
                if not (0 <= last_octet <= 255):
                    return []
                base = '.'.join(start_str.split('.')[:3])
                end_ip = f"{base}.{last_octet}"
                start_int = ip_to_int(start_str)
                end_int = ip_to_int(end_ip)
            except ValueError:
                return []
        
        if start_int > end_int:
            return []
        
        # Safety limit: max 65536 IPs (/16 subnet)
        if (end_int - start_int + 1) > 65536:
            return []
        
        return [int_to_ip(i) for i in range(start_int, end_int + 1)]
    except Exception:
        return []


def parse_ip_input(text: str) -> dict:
    """Parse IP input and return type and expanded IPs.
    
    Supports:
    - Single IP: 1.2.3.4
    - CIDR: 1.2.3.0/24
    - Range: 1.2.3.1-1.2.3.10 or 1.2.3.1-10
    
    Returns dict with keys: type, ips, original, error
    """
    text = text.strip()
    
    # Check CIDR notation
    if '/' in text:
        ips = expand_cidr(text)
        if not ips:
            return {"type": "error", "ips": [], "original": text, "error": "Format CIDR tidak valid (contoh: 192.168.1.0/24)"}
        # Safety check: warn if too many
        if len(ips) > 65536:
            return {"type": "error", "ips": [], "original": text, "error": "Terlalu banyak IP (max /16)"}
        return {"type": "cidr", "ips": ips, "original": text, "error": None}
    
    # Check IP range
    if '-' in text:
        ips = expand_ip_range(text)
        if not ips:
            return {"type": "error", "ips": [], "original": text, "error": "Format range tidak valid (contoh: 10.0.0.1-10.0.0.5 atau 10.0.0.1-5)"}
        return {"type": "range", "ips": ips, "original": text, "error": None}
    
    # Single IP
    if validate_ip(text):
        return {"type": "single", "ips": [text], "original": text, "error": None}
    
    return {"type": "error", "ips": [], "original": text, "error": "Format IP tidak valid"}


def extract_ips_from_text(text: str, ip_type: str = "all") -> list:
    """Extract IPs from SIEM data

    ip_type:
        - "source": First IP per line
        - "dest": Second IP per line
        - "all": All IPs
    """
    ip_pattern = r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b'

    skip_patterns = [
        'Event Name', 'Log Source', 'Event Count', 'Time Sort',
        'Low Level Category', 'Source IP', 'Source Port',
        'Destination IP', 'Destination Port', 'Username', 'Magnitude',
        'FortiGate @', 'Firewall @', 'QRadar @', 'Splunk @',
    ]

    found_ips = []
    lines = text.strip().split('\n')

    for line in lines:
        line = line.strip()
        if not line or line.isdigit():
            continue

        if any(p.lower() in line.lower() for p in skip_patterns):
            continue

        ips_in_line = re.findall(ip_pattern, line)
        valid_ips = [ip for ip in ips_in_line if validate_ip(ip)]

        if not valid_ips:
            continue

        if ip_type == "source":
            ip = valid_ips[0]
            if not is_private_ip(ip) and ip not in found_ips:
                found_ips.append(ip)
        elif ip_type == "dest":
            ip = valid_ips[1] if len(valid_ips) >= 2 else valid_ips[0]
            if not is_private_ip(ip) and ip not in found_ips:
                found_ips.append(ip)
        else:
            for ip in valid_ips:
                if not is_private_ip(ip) and ip not in found_ips:
                    found_ips.append(ip)

    return found_ips


# ==================================================
# API FUNCTIONS
# ==================================================
def check_virustotal(ip: str) -> dict:
    """Check IP on VirusTotal"""
    if not VT_API_KEY:
        return {"error": "API key not configured"}

    try:
        response = requests.get(
            VT_URL.format(ip),
            headers={"x-apikey": VT_API_KEY},
            timeout=30
        )
        if response.status_code == 200:
            data = response.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            attrs = data.get("data", {}).get("attributes", {})
            return {
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "country": attrs.get("country", "Unknown"),
                "as_owner": attrs.get("as_owner", "Unknown"),
                "is_bad": stats.get("malicious", 0) > 0 or stats.get("suspicious", 0) > 0
            }
        elif response.status_code == 429:
            return {"error": "Rate limit exceeded"}
        return {"error": f"Error {response.status_code}"}
    except Exception as e:
        return {"error": str(e)}


def check_abuseipdb(ip: str) -> dict:
    """Check IP on AbuseIPDB"""
    if not ABUSEIPDB_API_KEY:
        return {"error": "API key not configured"}

    try:
        response = requests.get(
            ABUSEIPDB_URL,
            headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": True},
            timeout=30
        )
        if response.status_code == 200:
            data = response.json().get("data", {})
            return {
                "abuse_score": data.get("abuseConfidenceScore", 0),
                "total_reports": data.get("totalReports", 0),
                "country": data.get("countryCode", "Unknown"),
                "isp": data.get("isp", "Unknown"),
                "is_tor": data.get("isTor", False),
                "is_bad": data.get("abuseConfidenceScore", 0) > 0 or data.get("totalReports", 0) > 0
            }
        elif response.status_code == 429:
            return {"error": "Rate limit exceeded"}
        return {"error": f"Error {response.status_code}"}
    except Exception as e:
        return {"error": str(e)}


def check_ip_reputation(ip: str) -> tuple:
    """Check IP reputation and return (vt_result, abuse_result, is_malicious)"""
    vt = check_virustotal(ip)
    abuse = check_abuseipdb(ip)

    is_malicious = False
    if "error" not in vt and vt.get("is_bad"):
        is_malicious = True
    if "error" not in abuse and abuse.get("is_bad"):
        is_malicious = True

    return vt, abuse, is_malicious


# ==================================================
# ASYNC API FUNCTIONS (for parallel checking)
# ==================================================
async def check_virustotal_async(session: aiohttp.ClientSession, ip: str) -> dict:
    """Check IP on VirusTotal (async)"""
    if not VT_API_KEY:
        return {"error": "API key not configured"}

    try:
        async with session.get(
            VT_URL.format(ip),
            headers={"x-apikey": VT_API_KEY},
            timeout=aiohttp.ClientTimeout(total=15)
        ) as response:
            if response.status == 200:
                data = await response.json()
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                attrs = data.get("data", {}).get("attributes", {})
                return {
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless": stats.get("harmless", 0),
                    "country": attrs.get("country", "Unknown"),
                    "as_owner": attrs.get("as_owner", "Unknown"),
                    "is_bad": stats.get("malicious", 0) > 0 or stats.get("suspicious", 0) > 0
                }
            elif response.status == 429:
                return {"error": "Rate limit exceeded"}
            return {"error": f"Error {response.status}"}
    except asyncio.TimeoutError:
        return {"error": "Timeout"}
    except Exception as e:
        return {"error": str(e)}


async def check_abuseipdb_async(session: aiohttp.ClientSession, ip: str) -> dict:
    """Check IP on AbuseIPDB (async)"""
    if not ABUSEIPDB_API_KEY:
        return {"error": "API key not configured"}

    try:
        async with session.get(
            ABUSEIPDB_URL,
            headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": True},
            timeout=aiohttp.ClientTimeout(total=15)
        ) as response:
            if response.status == 200:
                data = (await response.json()).get("data", {})
                return {
                    "abuse_score": data.get("abuseConfidenceScore", 0),
                    "total_reports": data.get("totalReports", 0),
                    "country": data.get("countryCode", "Unknown"),
                    "isp": data.get("isp", "Unknown"),
                    "is_tor": data.get("isTor", False),
                    "is_bad": data.get("abuseConfidenceScore", 0) > 0 or data.get("totalReports", 0) > 0
                }
            elif response.status == 429:
                return {"error": "Rate limit exceeded"}
            return {"error": f"Error {response.status}"}
    except asyncio.TimeoutError:
        return {"error": "Timeout"}
    except Exception as e:
        return {"error": str(e)}


async def check_ip_reputation_async(session: aiohttp.ClientSession, ip: str) -> tuple:
    """Check IP reputation async and return (ip, vt_result, abuse_result, is_malicious)"""
    vt, abuse = await asyncio.gather(
        check_virustotal_async(session, ip),
        check_abuseipdb_async(session, ip)
    )

    is_malicious = False
    if "error" not in vt and vt.get("is_bad"):
        is_malicious = True
    if "error" not in abuse and abuse.get("is_bad"):
        is_malicious = True

    return ip, vt, abuse, is_malicious


async def check_multiple_ips_async(ips: list, batch_size: int = 5) -> list:
    """Check multiple IPs in parallel batches"""
    results = []
    connector = aiohttp.TCPConnector(limit=10)

    async with aiohttp.ClientSession(connector=connector) as session:
        for i in range(0, len(ips), batch_size):
            batch = ips[i:i + batch_size]
            batch_results = await asyncio.gather(
                *[check_ip_reputation_async(session, ip) for ip in batch]
            )
            results.extend(batch_results)

    return results


# ==================================================
# BLACKLIST DATABASE FUNCTIONS (with timestamp tracking)
# ==================================================
def load_blacklist_db() -> dict:
    """Load blacklist database with timestamps"""
    if not os.path.exists(BLACKLIST_DB_FILE):
        return {}
    try:
        with open(BLACKLIST_DB_FILE, "r") as f:
            return json.load(f)
    except:
        return {}


def save_blacklist_db(data: dict):
    """Save blacklist database"""
    with open(BLACKLIST_DB_FILE, "w") as f:
        json.dump(data, f, indent=2)


def sync_blacklist_db():
    """Sync blacklist.txt with blacklist_db.json (for existing IPs without timestamp)"""
    db = load_blacklist_db()
    txt_ips = load_blacklist()
    
    changed = False
    for ip in txt_ips:
        if ip not in db:
            # Add existing IP with unknown date
            db[ip] = {
                "added_at": "unknown",
                "reason": "legacy"
            }
            changed = True
    
    if changed:
        save_blacklist_db(db)
    
    return db


def add_to_blacklist_db(ip: str, reason: str = "auto", added_by: int = None, added_by_username: str = None) -> bool:
    """Add IP to blacklist database with timestamp and who added it"""
    db = load_blacklist_db()
    if ip in db:
        return False

    entry = {
        "added_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "reason": reason
    }
    if added_by is not None:
        entry["added_by"] = added_by
        entry["added_by_username"] = added_by_username or "unknown"
    save_blacklist_db({**db, ip: entry})
    return True


def remove_from_blacklist_db(ip: str) -> bool:
    """Remove IP from blacklist database"""
    db = load_blacklist_db()
    if ip not in db:
        return False
    del db[ip]
    save_blacklist_db(db)
    return True


def get_ips_by_date_range(start_date: datetime, end_date: datetime) -> list:
    """Get IPs blacklisted within date range"""
    db = load_blacklist_db()
    result = []
    
    for ip, info in db.items():
        added_at = info.get("added_at", "unknown")
        if added_at == "unknown":
            continue
        
        try:
            ip_date = datetime.strptime(added_at.split()[0], "%Y-%m-%d")
            if start_date <= ip_date <= end_date:
                result.append({
                    "ip": ip,
                    "added_at": added_at,
                    "reason": info.get("reason", "unknown")
                })
        except:
            continue
    
    # Sort by date
    result.sort(key=lambda x: x["added_at"])
    return result


def get_ips_by_single_date(date: datetime) -> list:
    """Get IPs blacklisted on specific date"""
    return get_ips_by_date_range(date, date)


def get_blacklist_stats() -> dict:
    """Get blacklist statistics"""
    db = load_blacklist_db()
    total = len(db)
    
    today = datetime.now().date()
    today_count = 0
    this_week_count = 0
    this_month_count = 0
    
    week_start = today - timedelta(days=today.weekday())
    month_start = today.replace(day=1)
    
    for ip, info in db.items():
        added_at = info.get("added_at", "unknown")
        if added_at == "unknown":
            continue
        
        try:
            ip_date = datetime.strptime(added_at.split()[0], "%Y-%m-%d").date()
            if ip_date == today:
                today_count += 1
            if ip_date >= week_start:
                this_week_count += 1
            if ip_date >= month_start:
                this_month_count += 1
        except:
            continue
    
    return {
        "total": total,
        "today": today_count,
        "this_week": this_week_count,
        "this_month": this_month_count
    }


# ==================================================
# ACTIVITY DB FUNCTIONS
# ==================================================
def load_activity_db() -> dict:
    """Load activity database"""
    if not os.path.exists(ACTIVITY_DB_FILE):
        return {"activities": []}
    try:
        with open(ACTIVITY_DB_FILE, "r") as f:
            data = json.load(f)
            if "activities" not in data:
                data["activities"] = []
            return data
    except Exception:
        return {"activities": []}


def save_activity_db(data: dict):
    """Save activity database"""
    with open(ACTIVITY_DB_FILE, "w") as f:
        json.dump(data, f, indent=2)


def log_activity(action: str, ip: str, user_id: int, username: str, reason: str):
    """Append an activity entry to the audit trail"""
    data = load_activity_db()
    data["activities"].append({
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "action": action,
        "ip": ip,
        "user_id": user_id,
        "username": username or "unknown",
        "reason": reason
    })
    save_activity_db(data)


# ==================================================
# BLACKLIST FUNCTIONS
# ==================================================
def load_blacklist() -> set:
    """Load blacklist IPs"""
    if not os.path.exists(BLACKLIST_FILE):
        return set()
    with open(BLACKLIST_FILE, "r") as f:
        ips = set()
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                ip = line.split()[0]
                if validate_ip(ip):
                    ips.add(ip)
        return ips


def add_to_blacklist(ip: str, reason: str = "auto", added_by: int = None, added_by_username: str = None) -> bool:
    """Add IP to blacklist"""
    existing = load_blacklist()
    if ip in existing:
        return False
    with open(BLACKLIST_FILE, "a") as f:
        f.write(f"{ip}\n")

    # Also add to database with timestamp and user info
    add_to_blacklist_db(ip, reason, added_by=added_by, added_by_username=added_by_username)

    # Log to activity audit trail
    log_activity("blacklist", ip, added_by or 0, added_by_username or "unknown", reason)

    logger.info(f"BLACKLISTED | IP={ip} | REASON={reason} | BY={added_by_username}({added_by})")
    return True


def remove_from_blacklist(ip: str, removed_by: int = None, removed_by_username: str = None, reason: str = "Manual - Unblacklist") -> bool:
    """Remove IP from blacklist"""
    existing = load_blacklist()
    if ip not in existing:
        return False

    # Rewrite file without the IP
    with open(BLACKLIST_FILE, "r") as f:
        lines = f.readlines()

    with open(BLACKLIST_FILE, "w") as f:
        for line in lines:
            line_ip = line.strip().split()[0] if line.strip() and not line.strip().startswith("#") else ""
            if line_ip != ip:
                f.write(line)

    # Also remove from database
    remove_from_blacklist_db(ip)

    # Log to activity audit trail
    log_activity("unblacklist", ip, removed_by or 0, removed_by_username or "unknown", reason)

    logger.info(f"UNBLACKLISTED | IP={ip} | BY={removed_by_username}({removed_by})")
    return True


def force_blacklist(ip: str, reason: str = "Manual/Anomaly", added_by: int = None, added_by_username: str = None) -> bool:
    """Force add IP to blacklist without reputation check"""
    existing = load_blacklist()
    if ip in existing:
        return False
    with open(BLACKLIST_FILE, "a") as f:
        f.write(f"{ip}\n")

    # Also add to database with timestamp and user info
    add_to_blacklist_db(ip, reason, added_by=added_by, added_by_username=added_by_username)

    # Log to activity audit trail
    log_activity("force_blacklist", ip, added_by or 0, added_by_username or "unknown", reason)

    logger.info(f"FORCE_BLACKLISTED | IP={ip} | REASON={reason} | BY={added_by_username}({added_by})")
    return True


def search_blacklist(query: str) -> list:
    """Search IP in blacklist"""
    return [ip for ip in load_blacklist() if query in ip]


# ==================================================
# DOMAIN BLACKLIST FUNCTIONS
# ==================================================
def validate_domain(domain: str) -> bool:
    """Validate domain format"""
    # Basic domain validation pattern
    pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    return bool(re.match(pattern, domain.lower().strip()))


def extract_domains_from_text(text: str) -> list:
    """Extract domains from text"""
    # Pattern to match domains
    domain_pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'

    found_domains = []
    matches = re.findall(domain_pattern, text)

    for domain in matches:
        domain = domain.lower().strip()
        # Skip common non-malicious domains
        skip_domains = ['google.com', 'microsoft.com', 'github.com', 'githubusercontent.com']
        if domain not in skip_domains and domain not in found_domains:
            found_domains.append(domain)

    return found_domains


# Domain Blacklist Database Functions
def load_domain_blacklist_db() -> dict:
    """Load domain blacklist database with timestamps"""
    if not os.path.exists(DOMAIN_BLACKLIST_DB_FILE):
        return {}
    try:
        with open(DOMAIN_BLACKLIST_DB_FILE, "r") as f:
            return json.load(f)
    except:
        return {}


def save_domain_blacklist_db(data: dict):
    """Save domain blacklist database"""
    with open(DOMAIN_BLACKLIST_DB_FILE, "w") as f:
        json.dump(data, f, indent=2)


def sync_domain_blacklist_db():
    """Sync domain blacklist txt with domain_blacklist_db.json"""
    db = load_domain_blacklist_db()
    txt_domains = load_domain_blacklist()

    changed = False
    for domain in txt_domains:
        if domain not in db:
            db[domain] = {
                "added_at": "unknown",
                "reason": "legacy"
            }
            changed = True

    if changed:
        save_domain_blacklist_db(db)

    return db


def add_to_domain_blacklist_db(domain: str, reason: str = "auto") -> bool:
    """Add domain to blacklist database with timestamp"""
    db = load_domain_blacklist_db()
    if domain in db:
        return False

    db[domain] = {
        "added_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "reason": reason
    }
    save_domain_blacklist_db(db)
    return True


def remove_from_domain_blacklist_db(domain: str) -> bool:
    """Remove domain from blacklist database"""
    db = load_domain_blacklist_db()
    if domain not in db:
        return False
    del db[domain]
    save_domain_blacklist_db(db)
    return True


def get_domains_by_date_range(start_date: datetime, end_date: datetime) -> list:
    """Get domains blacklisted within date range"""
    db = load_domain_blacklist_db()
    result = []

    for domain, info in db.items():
        added_at = info.get("added_at", "unknown")
        if added_at == "unknown":
            continue

        try:
            domain_date = datetime.strptime(added_at.split()[0], "%Y-%m-%d")
            if start_date <= domain_date <= end_date:
                result.append({
                    "domain": domain,
                    "added_at": added_at,
                    "reason": info.get("reason", "unknown")
                })
        except:
            continue

    result.sort(key=lambda x: x["added_at"])
    return result


def get_domain_blacklist_stats() -> dict:
    """Get domain blacklist statistics"""
    db = load_domain_blacklist_db()
    total = len(db)

    today = datetime.now().date()
    today_count = 0
    this_week_count = 0
    this_month_count = 0

    week_start = today - timedelta(days=today.weekday())
    month_start = today.replace(day=1)

    for domain, info in db.items():
        added_at = info.get("added_at", "unknown")
        if added_at == "unknown":
            continue

        try:
            domain_date = datetime.strptime(added_at.split()[0], "%Y-%m-%d").date()
            if domain_date == today:
                today_count += 1
            if domain_date >= week_start:
                this_week_count += 1
            if domain_date >= month_start:
                this_month_count += 1
        except:
            continue

    return {
        "total": total,
        "today": today_count,
        "this_week": this_week_count,
        "this_month": this_month_count
    }


# Domain Blacklist File Functions
def load_domain_blacklist() -> set:
    """Load blacklist domains"""
    if not os.path.exists(DOMAIN_BLACKLIST_FILE):
        return set()
    with open(DOMAIN_BLACKLIST_FILE, "r") as f:
        domains = set()
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                domain = line.split()[0].lower()
                if validate_domain(domain):
                    domains.add(domain)
        return domains


def add_to_domain_blacklist(domain: str, reason: str = "auto") -> bool:
    """Add domain to blacklist"""
    domain = domain.lower().strip()
    existing = load_domain_blacklist()
    if domain in existing:
        return False
    with open(DOMAIN_BLACKLIST_FILE, "a") as f:
        f.write(f"{domain}\n")

    # Also add to database with timestamp
    add_to_domain_blacklist_db(domain, reason)

    logger.info(f"DOMAIN_BLACKLISTED | DOMAIN={domain} | REASON={reason}")
    return True


def remove_from_domain_blacklist(domain: str) -> bool:
    """Remove domain from blacklist"""
    domain = domain.lower().strip()
    existing = load_domain_blacklist()
    if domain not in existing:
        return False

    # Rewrite file without the domain
    with open(DOMAIN_BLACKLIST_FILE, "r") as f:
        lines = f.readlines()

    with open(DOMAIN_BLACKLIST_FILE, "w") as f:
        for line in lines:
            line_domain = line.strip().split()[0].lower() if line.strip() and not line.strip().startswith("#") else ""
            if line_domain != domain:
                f.write(line)

    # Also remove from database
    remove_from_domain_blacklist_db(domain)

    logger.info(f"DOMAIN_UNBLACKLISTED | DOMAIN={domain}")
    return True


def force_domain_blacklist(domain: str, reason: str = "Manual/Anomaly") -> bool:
    """Force add domain to blacklist without validation"""
    domain = domain.lower().strip()
    existing = load_domain_blacklist()
    if domain in existing:
        return False
    with open(DOMAIN_BLACKLIST_FILE, "a") as f:
        f.write(f"{domain}\n")

    # Also add to database with timestamp
    add_to_domain_blacklist_db(domain, reason)

    logger.info(f"DOMAIN_FORCE_BLACKLISTED | DOMAIN={domain} | REASON={reason}")
    return True


def search_domain_blacklist(query: str) -> list:
    """Search domain in blacklist"""
    return [d for d in load_domain_blacklist() if query.lower() in d]


# ==================================================
# GIT FUNCTIONS
# ==================================================
def git_push(silent: bool = False) -> str:
    """Push List-IP-Blacklist.txt and List-Domain-Blacklist.txt to GitHub"""
    import subprocess
    try:
        os.chdir(SCRIPT_DIR)

        # Pull first to avoid conflicts
        subprocess.run(
            ["git", "pull", "--rebase", GITHUB_REMOTE, GITHUB_BRANCH],
            capture_output=True, text=True
        )

        # Add both blacklist files
        subprocess.run(["git", "add", "List-IP-Blacklist.txt"], capture_output=True)
        subprocess.run(["git", "add", "List-Domain-Blacklist.txt"], capture_output=True)

        # Check if there are changes
        result = subprocess.run(
            ["git", "status", "--porcelain", "List-IP-Blacklist.txt", "List-Domain-Blacklist.txt"],
            capture_output=True, text=True
        )
        if not result.stdout.strip():
            return "" if silent else "No changes to commit"

        # Commit
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        subprocess.run(
            ["git", "commit", "-m", f"Update Blacklist - {timestamp}"],
            capture_output=True
        )

        # Push
        result = subprocess.run(
            ["git", "push", GITHUB_REMOTE, GITHUB_BRANCH],
            capture_output=True, text=True
        )

        if result.returncode == 0:
            logger.info("GIT_PUSH | SUCCESS")
            return "Successfully pushed to GitHub"

        # If push failed, log error
        logger.error(f"GIT_PUSH | FAILED | {result.stderr}")
        return f"Failed: {result.stderr}"

    except Exception as e:
        logger.error(f"GIT_PUSH | ERROR | {str(e)}")
        return f"Error: {str(e)}"


def git_push_domain(silent: bool = False) -> str:
    """Push ONLY List-Domain-Blacklist.txt to GitHub"""
    import subprocess
    try:
        os.chdir(SCRIPT_DIR)

        # Pull first to avoid conflicts
        subprocess.run(
            ["git", "pull", "--rebase", GITHUB_REMOTE, GITHUB_BRANCH],
            capture_output=True, text=True
        )

        # Add only domain blacklist file
        subprocess.run(["git", "add", "List-Domain-Blacklist.txt"], capture_output=True)

        # Check if there are changes
        result = subprocess.run(
            ["git", "status", "--porcelain", "List-Domain-Blacklist.txt"],
            capture_output=True, text=True
        )
        if not result.stdout.strip():
            return "" if silent else "No changes to commit"

        # Commit
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        subprocess.run(
            ["git", "commit", "-m", f"Update List-Domain-Blacklist.txt - {timestamp}"],
            capture_output=True
        )

        # Push
        result = subprocess.run(
            ["git", "push", GITHUB_REMOTE, GITHUB_BRANCH],
            capture_output=True, text=True
        )

        if result.returncode == 0:
            logger.info("GIT_PUSH_DOMAIN | SUCCESS")
            return "Successfully pushed domain blacklist to GitHub"

        # If push failed, log error
        logger.error(f"GIT_PUSH_DOMAIN | FAILED | {result.stderr}")
        return f"Failed: {result.stderr}"

    except Exception as e:
        logger.error(f"GIT_PUSH_DOMAIN | ERROR | {str(e)}")
        return f"Error: {str(e)}"


def git_pull() -> str:
    """Pull from GitHub"""
    import subprocess
    try:
        os.chdir(SCRIPT_DIR)
        result = subprocess.run(
            ["git", "pull", GITHUB_REMOTE, GITHUB_BRANCH],
            capture_output=True, text=True
        )
        if result.returncode == 0:
            return "Successfully pulled from GitHub"
        return f"Failed: {result.stderr}"
    except Exception as e:
        return f"Error: {str(e)}"


# ==================================================
# CLI MODE
# ==================================================
def clear_screen():
    os.system("clear" if os.name != "nt" else "cls")


def print_banner():
    try:
        print(f"""
{Colors.CYAN}{Colors.BOLD}
╔═══════════════════════════════════════════════════════════════════════════╗
║                                                                           ║
║     ██╗██████╗     ██████╗██╗  ██╗███████╗ ██████╗██╗  ██╗███████╗██████╗ ║
║     ██║██╔══██╗   ██╔════╝██║  ██║██╔════╝██╔════╝██║ ██╔╝██╔════╝██╔══██╗║
║     ██║██████╔╝   ██║     ███████║█████╗  ██║     █████╔╝ █████╗  ██████╔╝║
║     ██║██╔═══╝    ██║     ██╔══██║██╔══╝  ██║     ██╔═██╗ ██╔══╝  ██╔══██╗║
║     ██║██║        ╚██████╗██║  ██║███████╗╚██████╗██║  ██╗███████╗██║  ██║║
║     ╚═╝╚═╝         ╚═════╝╚═╝  ╚═╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝║
║                                                                           ║
║              SOC AUTOMATION - IP REPUTATION CHECKER                       ║
║         VirusTotal + AbuseIPDB + GitHub Auto-Blacklist                    ║
║                                                                           ║
╚═══════════════════════════════════════════════════════════════════════════╝
{Colors.RESET}""")
    except UnicodeEncodeError:
        # Fallback untuk terminal yang tidak support Unicode
        print(f"""
{Colors.CYAN}{Colors.BOLD}
+===========================================================================+
|                                                                           |
|     IP CHECKER - SOC AUTOMATION                                           |
|     VirusTotal + AbuseIPDB + GitHub Auto-Blacklist                        |
|                                                                           |
|     BIOFARMA Security Operations Center                                   |
|                                                                           |
+===========================================================================+
{Colors.RESET}""")


def print_menu():
    try:
        print(f"""
{Colors.BOLD}{Colors.WHITE}╔═══════════════════════════════════════╗
║           MAIN MENU                   ║
╠═══════════════════════════════════════╣{Colors.RESET}
{Colors.GREEN}║  [1] Check Source IP                  ║{Colors.RESET}
{Colors.BLUE}║  [2] Check Destination IP             ║{Colors.RESET}
{Colors.YELLOW}║  [3] Check Single IP                  ║{Colors.RESET}
{Colors.MAGENTA}║  [4] View IP Blacklist                ║{Colors.RESET}
{Colors.CYAN}║  [5] Push to GitHub                   ║{Colors.RESET}
{Colors.WHITE}║  [6] Pull from GitHub                 ║{Colors.RESET}
{Colors.RED}║  [8] Force Blacklist IP (tanpa cek)   ║{Colors.RESET}
{Colors.GREEN}║  [9] Unblacklist IP (hapus dari list) ║{Colors.RESET}
{Colors.CYAN}║  [10] Dump IP by Date                 ║{Colors.RESET}
{Colors.BOLD}{Colors.WHITE}╠═══════════════════════════════════════╣
║         DOMAIN BLACKLIST              ║
╠═══════════════════════════════════════╣{Colors.RESET}
{Colors.MAGENTA}║  [11] View Domain Blacklist           ║{Colors.RESET}
{Colors.RED}║  [12] Add Domain to Blacklist         ║{Colors.RESET}
{Colors.GREEN}║  [13] Remove Domain from Blacklist    ║{Colors.RESET}
{Colors.CYAN}║  [14] Search Domain Blacklist         ║{Colors.RESET}
{Colors.BOLD}{Colors.WHITE}╠═══════════════════════════════════════╣{Colors.RESET}
{Colors.WHITE}║  [7] Help                             ║{Colors.RESET}
{Colors.RED}║  [0] Exit                             ║{Colors.RESET}
{Colors.BOLD}{Colors.WHITE}╚═══════════════════════════════════════╝{Colors.RESET}
""")
    except UnicodeEncodeError:
        print(f"""
{Colors.BOLD}{Colors.WHITE}+=======================================+
|           MAIN MENU                   |
+=======================================+{Colors.RESET}
{Colors.GREEN}|  [1] Check Source IP                  |{Colors.RESET}
{Colors.BLUE}|  [2] Check Destination IP             |{Colors.RESET}
{Colors.YELLOW}|  [3] Check Single IP                  |{Colors.RESET}
{Colors.MAGENTA}|  [4] View IP Blacklist                |{Colors.RESET}
{Colors.CYAN}|  [5] Push to GitHub                   |{Colors.RESET}
{Colors.WHITE}|  [6] Pull from GitHub                 |{Colors.RESET}
{Colors.RED}|  [8] Force Blacklist IP (tanpa cek)   |{Colors.RESET}
{Colors.GREEN}|  [9] Unblacklist IP (hapus dari list) |{Colors.RESET}
{Colors.CYAN}|  [10] Dump IP by Date                 |{Colors.RESET}
{Colors.BOLD}{Colors.WHITE}+=======================================+
|         DOMAIN BLACKLIST              |
+=======================================+{Colors.RESET}
{Colors.MAGENTA}|  [11] View Domain Blacklist           |{Colors.RESET}
{Colors.RED}|  [12] Add Domain to Blacklist         |{Colors.RESET}
{Colors.GREEN}|  [13] Remove Domain from Blacklist    |{Colors.RESET}
{Colors.CYAN}|  [14] Search Domain Blacklist         |{Colors.RESET}
{Colors.BOLD}{Colors.WHITE}+=======================================+{Colors.RESET}
{Colors.WHITE}|  [7] Help                             |{Colors.RESET}
{Colors.RED}|  [0] Exit                             |{Colors.RESET}
{Colors.BOLD}{Colors.WHITE}+=======================================+{Colors.RESET}
""")


def get_multiline_input():
    """Get multi-line input for SIEM data"""
    print(f"\n{Colors.YELLOW}Paste SIEM data below.")
    print(f"Type 'DONE' when finished:{Colors.RESET}\n")

    lines = []
    while True:
        try:
            line = input()
            if line.strip().upper() == 'DONE':
                break
            if line.strip():
                lines.append(line)
        except EOFError:
            break
    return '\n'.join(lines)


def print_result(ip: str, vt: dict, abuse: dict, index: int = None):
    """Print formatted result for CLI"""
    prefix = f"[{index}] " if index else ""

    try:
        print(f"\n{Colors.BOLD}{'─'*60}{Colors.RESET}")
        print(f"{Colors.BOLD}{prefix}IP: {Colors.CYAN}{ip}{Colors.RESET}")
        print(f"{Colors.BOLD}{'─'*60}{Colors.RESET}")
    except UnicodeEncodeError:
        print(f"\n{Colors.BOLD}{'-'*60}{Colors.RESET}")
        print(f"{Colors.BOLD}{prefix}IP: {Colors.CYAN}{ip}{Colors.RESET}")
        print(f"{Colors.BOLD}{'-'*60}{Colors.RESET}")

    # VirusTotal
    print(f"{Colors.MAGENTA}[VT]{Colors.RESET} ", end="")
    if "error" in vt:
        print(f"{Colors.YELLOW}{vt['error']}{Colors.RESET}")
    else:
        mal = vt['malicious']
        sus = vt['suspicious']
        mal_c = Colors.RED if mal > 0 else Colors.GREEN
        sus_c = Colors.YELLOW if sus > 0 else Colors.GREEN
        print(f"Mal:{mal_c}{mal}{Colors.RESET} Sus:{sus_c}{sus}{Colors.RESET} | {vt['country']} | {vt['as_owner'][:30]}")

    # AbuseIPDB
    print(f"{Colors.MAGENTA}[AB]{Colors.RESET} ", end="")
    if "error" in abuse:
        print(f"{Colors.YELLOW}{abuse['error']}{Colors.RESET}")
    else:
        score = abuse['abuse_score']
        score_c = Colors.RED if score >= 50 else (Colors.YELLOW if score > 0 else Colors.GREEN)
        print(f"Score:{score_c}{score}%{Colors.RESET} Reports:{abuse['total_reports']} | {abuse['isp'][:30]}")

    # Verdict
    is_malicious = False
    if "error" not in vt and vt.get("is_bad"):
        is_malicious = True
    if "error" not in abuse and abuse.get("is_bad"):
        is_malicious = True

    if is_malicious:
        print(f"{Colors.RED}{Colors.BOLD}>>> MALICIOUS <<<{Colors.RESET}")
    else:
        print(f"{Colors.GREEN}>>> CLEAN <<<{Colors.RESET}")

    return is_malicious


def process_ips_cli(ips: list, ip_type: str):
    """Process list of IPs in CLI mode"""
    if not ips:
        print(f"{Colors.YELLOW}[!] No valid IPs found{Colors.RESET}")
        return

    print(f"\n{Colors.CYAN}Found {len(ips)} unique {ip_type.upper()} IPs{Colors.RESET}")
    for i, ip in enumerate(ips, 1):
        print(f"  {i}. {ip}")

    print(f"\n{Colors.GREEN}Press Enter to start, or 'c' to cancel...{Colors.RESET}")
    if input().strip().lower() == 'c':
        return

    malicious_ips = []

    for i, ip in enumerate(ips, 1):
        print(f"\n{Colors.BLUE}[{i}/{len(ips)}] Checking {ip}...{Colors.RESET}")
        vt, abuse, is_mal = check_ip_reputation(ip)
        print_result(ip, vt, abuse, i)

        if is_mal:
            malicious_ips.append(ip)
            if add_to_blacklist(ip):
                print(f"{Colors.GREEN}  [+] Added to blacklist{Colors.RESET}")

    # Summary
    try:
        print(f"\n{Colors.BOLD}{'═'*60}")
        print(f"                    SUMMARY")
        print(f"{'═'*60}{Colors.RESET}")
    except UnicodeEncodeError:
        print(f"\n{Colors.BOLD}{'='*60}")
        print(f"                    SUMMARY")
        print(f"{'='*60}{Colors.RESET}")
    print(f"{Colors.GREEN}  Clean: {len(ips) - len(malicious_ips)}{Colors.RESET}")
    print(f"{Colors.RED}  Malicious: {len(malicious_ips)}{Colors.RESET}")

    if malicious_ips:
        print(f"\n{Colors.BLUE}[*] Auto-pushing to GitHub...{Colors.RESET}")
        result = git_push()
        print(f"{Colors.GREEN}  {result}{Colors.RESET}")

    input(f"\n{Colors.GREEN}Press Enter to continue...{Colors.RESET}")


def check_single_ip_cli():
    """Check single IP in CLI mode"""
    print(f"\n{Colors.CYAN}Enter IP address (or 'back'):{Colors.RESET}")
    ip = input(f"{Colors.GREEN}IP > {Colors.RESET}").strip()

    if ip.lower() == 'back':
        return

    if not validate_ip(ip):
        print(f"{Colors.RED}[ERROR] Invalid IP format{Colors.RESET}")
        input(f"{Colors.GREEN}Press Enter...{Colors.RESET}")
        return

    if is_private_ip(ip):
        print(f"{Colors.YELLOW}[!] Private IP - no need to check{Colors.RESET}")
        input(f"{Colors.GREEN}Press Enter...{Colors.RESET}")
        return

    print(f"\n{Colors.BLUE}[*] Checking {ip}...{Colors.RESET}")
    vt, abuse, is_mal = check_ip_reputation(ip)
    print_result(ip, vt, abuse)

    if is_mal:
        if add_to_blacklist(ip):
            print(f"{Colors.GREEN}[+] Added to blacklist{Colors.RESET}")
            print(f"{Colors.BLUE}[*] Auto-pushing to GitHub...{Colors.RESET}")
            result = git_push()
            print(f"{Colors.GREEN}  {result}{Colors.RESET}")

    input(f"\n{Colors.GREEN}Press Enter...{Colors.RESET}")


def show_blacklist_cli():
    """Show blacklist in CLI mode"""
    blacklist = load_blacklist()
    if not blacklist:
        print(f"{Colors.YELLOW}Blacklist is empty{Colors.RESET}")
    else:
        print(f"\n{Colors.CYAN}{Colors.BOLD}BLACKLIST ({len(blacklist)} IPs){Colors.RESET}\n")
        for i, ip in enumerate(sorted(blacklist), 1):
            print(f"  {Colors.RED}{i:3}.{Colors.RESET} {ip}")

    input(f"\n{Colors.GREEN}Press Enter...{Colors.RESET}")


def force_blacklist_cli():
    """Force blacklist IP without reputation check (for anomaly cases)
    Supports: single IP, CIDR (e.g. 10.0.0.0/24), range (e.g. 10.0.0.1-10.0.0.5 or 10.0.0.1-5)
    """
    print(f"\n{Colors.RED}{Colors.BOLD}=== FORCE BLACKLIST ==={Colors.RESET}")
    print(f"{Colors.YELLOW}Blacklist IP langsung tanpa cek VT/AbuseIPDB{Colors.RESET}")
    print(f"{Colors.YELLOW}Gunakan untuk IP dengan aktivitas anomaly{Colors.RESET}")
    print(f"{Colors.CYAN}Format yang didukung:{Colors.RESET}")
    print(f"  {Colors.WHITE}• Single IP  : 1.2.3.4{Colors.RESET}")
    print(f"  {Colors.WHITE}• CIDR       : 10.0.0.0/24{Colors.RESET}")
    print(f"  {Colors.WHITE}• Range      : 10.0.0.1-10.0.0.5 atau 10.0.0.1-5{Colors.RESET}\n")

    ip_input = input(f"{Colors.GREEN}Enter IP/CIDR/Range (or 'back') > {Colors.RESET}").strip()

    if ip_input.lower() == 'back':
        return

    # Parse input (supports single IP, CIDR, range)
    parsed = parse_ip_input(ip_input)

    if parsed["type"] == "error":
        print(f"{Colors.RED}[ERROR] {parsed['error']}{Colors.RESET}")
        input(f"{Colors.GREEN}Press Enter...{Colors.RESET}")
        return

    ip_list = parsed["ips"]
    existing_bl = load_blacklist()

    # Filter out private IPs and already blacklisted
    private_ips = [ip for ip in ip_list if is_private_ip(ip)]
    already_bl = [ip for ip in ip_list if ip in existing_bl and not is_private_ip(ip)]
    new_ips = [ip for ip in ip_list if not is_private_ip(ip) and ip not in existing_bl]

    if not new_ips:
        print(f"{Colors.YELLOW}[!] Tidak ada IP baru untuk di-blacklist{Colors.RESET}")
        if private_ips:
            print(f"  {Colors.YELLOW}• {len(private_ips)} IP private (skip){Colors.RESET}")
        if already_bl:
            print(f"  {Colors.YELLOW}• {len(already_bl)} IP sudah ada di blacklist{Colors.RESET}")
        input(f"{Colors.GREEN}Press Enter...{Colors.RESET}")
        return

    # Show summary
    print(f"\n{Colors.CYAN}=== Summary ==={Colors.RESET}")
    print(f"  {Colors.WHITE}Input       : {ip_input}{Colors.RESET}")
    print(f"  {Colors.WHITE}Type        : {parsed['type'].upper()}{Colors.RESET}")
    print(f"  {Colors.WHITE}Total IPs   : {len(ip_list)}{Colors.RESET}")
    print(f"  {Colors.GREEN}New (to add): {len(new_ips)}{Colors.RESET}")
    if private_ips:
        print(f"  {Colors.YELLOW}Private     : {len(private_ips)} (skip){Colors.RESET}")
    if already_bl:
        print(f"  {Colors.YELLOW}Already BL  : {len(already_bl)} (skip){Colors.RESET}")

    # Show IPs to be added (max 20 preview)
    if len(new_ips) <= 20:
        print(f"\n{Colors.WHITE}IPs to blacklist:{Colors.RESET}")
        for ip in new_ips:
            print(f"  • {ip}")
    else:
        print(f"\n{Colors.WHITE}IPs to blacklist (showing first 10 & last 5):{Colors.RESET}")
        for ip in new_ips[:10]:
            print(f"  • {ip}")
        print(f"  ... ({len(new_ips) - 15} more) ...")
        for ip in new_ips[-5:]:
            print(f"  • {ip}")

    reason = input(f"\n{Colors.GREEN}Alasan (optional) > {Colors.RESET}").strip()
    if not reason:
        reason = "Manual/Anomaly"

    confirm = input(f"\n{Colors.YELLOW}Blacklist {len(new_ips)} IP(s)? (y/n) > {Colors.RESET}").strip().lower()
    if confirm != 'y':
        print(f"{Colors.YELLOW}Dibatalkan{Colors.RESET}")
        input(f"{Colors.GREEN}Press Enter...{Colors.RESET}")
        return

    # Add all IPs
    success_count = 0
    fail_count = 0
    for ip in new_ips:
        if force_blacklist(ip, reason):
            success_count += 1
        else:
            fail_count += 1

    print(f"\n{Colors.GREEN}[+] {success_count} IP berhasil di-blacklist{Colors.RESET}")
    if fail_count > 0:
        print(f"{Colors.RED}[-] {fail_count} IP gagal{Colors.RESET}")

    print(f"{Colors.BLUE}[*] Auto-pushing to GitHub...{Colors.RESET}")
    result = git_push()
    print(f"{Colors.GREEN}  {result}{Colors.RESET}")

    input(f"\n{Colors.GREEN}Press Enter...{Colors.RESET}")


def unblacklist_cli():
    """Remove IP from blacklist"""
    print(f"\n{Colors.GREEN}{Colors.BOLD}=== UNBLACKLIST ==={Colors.RESET}")
    print(f"{Colors.YELLOW}Hapus IP dari blacklist{Colors.RESET}\n")

    blacklist = load_blacklist()
    if not blacklist:
        print(f"{Colors.YELLOW}Blacklist kosong{Colors.RESET}")
        input(f"{Colors.GREEN}Press Enter...{Colors.RESET}")
        return

    print(f"{Colors.CYAN}Blacklist saat ini ({len(blacklist)} IPs):{Colors.RESET}")
    sorted_bl = sorted(blacklist)
    for i, ip in enumerate(sorted_bl[:20], 1):
        print(f"  {i:3}. {ip}")
    if len(sorted_bl) > 20:
        print(f"  ... dan {len(sorted_bl) - 20} lainnya")

    print()
    ip = input(f"{Colors.GREEN}Enter IP to remove (or 'back') > {Colors.RESET}").strip()

    if ip.lower() == 'back':
        return

    if not validate_ip(ip):
        print(f"{Colors.RED}[ERROR] Invalid IP format{Colors.RESET}")
        input(f"{Colors.GREEN}Press Enter...{Colors.RESET}")
        return

    if ip not in blacklist:
        print(f"{Colors.YELLOW}[!] IP tidak ditemukan di blacklist{Colors.RESET}")
        input(f"{Colors.GREEN}Press Enter...{Colors.RESET}")
        return

    confirm = input(f"\n{Colors.YELLOW}Hapus {ip} dari blacklist? (y/n) > {Colors.RESET}").strip().lower()
    if confirm != 'y':
        print(f"{Colors.YELLOW}Dibatalkan{Colors.RESET}")
        input(f"{Colors.GREEN}Press Enter...{Colors.RESET}")
        return

    if remove_from_blacklist(ip):
        print(f"{Colors.GREEN}[+] {ip} berhasil dihapus dari blacklist{Colors.RESET}")
        print(f"{Colors.BLUE}[*] Auto-pushing to GitHub...{Colors.RESET}")
        result = git_push()
        print(f"{Colors.GREEN}  {result}{Colors.RESET}")
    else:
        print(f"{Colors.RED}[-] Gagal hapus IP{Colors.RESET}")

    input(f"\n{Colors.GREEN}Press Enter...{Colors.RESET}")


def dump_ip_cli():
    """Dump IP by date range in CLI mode"""
    print(f"\n{Colors.CYAN}{Colors.BOLD}=== DUMP IP BY DATE ==={Colors.RESET}")
    print(f"{Colors.YELLOW}Tampilkan IP yang di-blacklist berdasarkan tanggal{Colors.RESET}\n")
    
    # Sync existing blacklist to db
    sync_blacklist_db()
    
    # Show stats
    stats = get_blacklist_stats()
    print(f"{Colors.CYAN}Statistik:{Colors.RESET}")
    print(f"  Total IP: {stats['total']}")
    print(f"  Hari ini: {stats['today']}")
    print(f"  Minggu ini: {stats['this_week']}")
    print(f"  Bulan ini: {stats['this_month']}")
    print()
    
    print(f"{Colors.YELLOW}Pilih mode:{Colors.RESET}")
    print("  [1] Single date (contoh: 2025-01-15)")
    print("  [2] Date range (contoh: 2025-01-01 s/d 2025-01-07)")
    print("  [3] Hari ini")
    print("  [4] Minggu ini")
    print("  [5] Bulan ini")
    print()
    
    mode = input(f"{Colors.GREEN}Pilih [1-5] > {Colors.RESET}").strip()
    
    today = datetime.now()
    
    if mode == '1':
        date_str = input(f"{Colors.GREEN}Tanggal (YYYY-MM-DD) > {Colors.RESET}").strip()
        try:
            target_date = datetime.strptime(date_str, "%Y-%m-%d")
            ips = get_ips_by_single_date(target_date)
            title = f"IP Blacklist pada {date_str}"
        except ValueError:
            print(f"{Colors.RED}Format tanggal salah!{Colors.RESET}")
            input(f"{Colors.GREEN}Press Enter...{Colors.RESET}")
            return
    
    elif mode == '2':
        start_str = input(f"{Colors.GREEN}Tanggal awal (YYYY-MM-DD) > {Colors.RESET}").strip()
        end_str = input(f"{Colors.GREEN}Tanggal akhir (YYYY-MM-DD) > {Colors.RESET}").strip()
        try:
            start_date = datetime.strptime(start_str, "%Y-%m-%d")
            end_date = datetime.strptime(end_str, "%Y-%m-%d")
            ips = get_ips_by_date_range(start_date, end_date)
            title = f"IP Blacklist dari {start_str} s/d {end_str}"
        except ValueError:
            print(f"{Colors.RED}Format tanggal salah!{Colors.RESET}")
            input(f"{Colors.GREEN}Press Enter...{Colors.RESET}")
            return
    
    elif mode == '3':
        ips = get_ips_by_single_date(today)
        title = f"IP Blacklist Hari Ini ({today.strftime('%Y-%m-%d')})"
    
    elif mode == '4':
        week_start = today - timedelta(days=today.weekday())
        ips = get_ips_by_date_range(week_start, today)
        title = f"IP Blacklist Minggu Ini ({week_start.strftime('%Y-%m-%d')} s/d {today.strftime('%Y-%m-%d')})"
    
    elif mode == '5':
        month_start = today.replace(day=1)
        ips = get_ips_by_date_range(month_start, today)
        title = f"IP Blacklist Bulan Ini ({month_start.strftime('%Y-%m-%d')} s/d {today.strftime('%Y-%m-%d')})"
    
    else:
        print(f"{Colors.YELLOW}Dibatalkan{Colors.RESET}")
        input(f"{Colors.GREEN}Press Enter...{Colors.RESET}")
        return
    
    # Display results
    print(f"\n{Colors.CYAN}{Colors.BOLD}{title}{Colors.RESET}")
    print(f"{Colors.BOLD}{'─'*60}{Colors.RESET}")
    
    if not ips:
        print(f"{Colors.YELLOW}Tidak ada IP ditemukan pada periode ini.{Colors.RESET}")
    else:
        print(f"{Colors.GREEN}Total: {len(ips)} IP{Colors.RESET}\n")
        for i, item in enumerate(ips, 1):
            print(f"  {i:3}. {Colors.RED}{item['ip']}{Colors.RESET}")
            print(f"       Added: {item['added_at']} | Reason: {item['reason']}")
        
        # Option to export
        print()
        export = input(f"{Colors.GREEN}Export ke file? (y/n) > {Colors.RESET}").strip().lower()
        if export == 'y':
            filename = f"dump_ip_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            with open(filename, 'w') as f:
                for item in ips:
                    f.write(f"{item['ip']}\n")
            print(f"{Colors.GREEN}Exported to {filename}{Colors.RESET}")
    
    input(f"\n{Colors.GREEN}Press Enter...{Colors.RESET}")


# ==================================================
# DOMAIN BLACKLIST CLI FUNCTIONS
# ==================================================
def view_domain_blacklist_cli():
    """View domain blacklist in CLI mode"""
    print(f"\n{Colors.CYAN}{Colors.BOLD}=== DOMAIN BLACKLIST ==={Colors.RESET}")

    # Sync existing blacklist to db
    sync_domain_blacklist_db()

    domains = load_domain_blacklist()
    stats = get_domain_blacklist_stats()

    print(f"\n{Colors.CYAN}Statistik:{Colors.RESET}")
    print(f"  Total Domain: {stats['total']}")
    print(f"  Hari ini: {stats['today']}")
    print(f"  Minggu ini: {stats['this_week']}")
    print(f"  Bulan ini: {stats['this_month']}")
    print()

    if not domains:
        print(f"{Colors.YELLOW}Domain blacklist kosong.{Colors.RESET}")
    else:
        print(f"{Colors.GREEN}Total: {len(domains)} domain{Colors.RESET}\n")
        for i, domain in enumerate(sorted(domains), 1):
            print(f"  {i:3}. {Colors.RED}{domain}{Colors.RESET}")

    input(f"\n{Colors.GREEN}Press Enter...{Colors.RESET}")


def add_domain_blacklist_cli():
    """Add domain to blacklist via CLI"""
    print(f"\n{Colors.CYAN}{Colors.BOLD}=== ADD DOMAIN TO BLACKLIST ==={Colors.RESET}")
    print(f"{Colors.YELLOW}Masukkan domain yang ingin di-blacklist.{Colors.RESET}")
    print(f"{Colors.YELLOW}Bisa satu domain atau beberapa domain (pisahkan dengan koma/newline).{Colors.RESET}")
    print(f"{Colors.YELLOW}Ketik 'DONE' jika selesai:{Colors.RESET}\n")

    lines = []
    while True:
        try:
            line = input()
            if line.strip().upper() == 'DONE':
                break
            lines.append(line)
        except EOFError:
            break

    text = '\n'.join(lines)
    domains = extract_domains_from_text(text)

    # Also allow simple comma-separated input
    if not domains:
        for part in text.replace(',', '\n').split('\n'):
            part = part.strip().lower()
            if part and validate_domain(part):
                domains.append(part)

    if not domains:
        print(f"\n{Colors.YELLOW}Tidak ada domain valid ditemukan.{Colors.RESET}")
        input(f"{Colors.GREEN}Press Enter...{Colors.RESET}")
        return

    # Remove duplicates
    domains = list(set(domains))

    print(f"\n{Colors.CYAN}Ditemukan {len(domains)} domain:{Colors.RESET}")
    for d in domains:
        print(f"  - {d}")

    confirm = input(f"\n{Colors.GREEN}Blacklist semua domain ini? (y/n) > {Colors.RESET}").strip().lower()
    if confirm != 'y':
        print(f"{Colors.YELLOW}Dibatalkan.{Colors.RESET}")
        input(f"{Colors.GREEN}Press Enter...{Colors.RESET}")
        return

    added = 0
    skipped = 0
    for domain in domains:
        if force_domain_blacklist(domain, reason="Manual CLI"):
            added += 1
            print(f"  {Colors.GREEN}+ {domain}{Colors.RESET}")
        else:
            skipped += 1
            print(f"  {Colors.YELLOW}- {domain} (already blacklisted){Colors.RESET}")

    print(f"\n{Colors.CYAN}Result: {added} added, {skipped} skipped{Colors.RESET}")

    # Auto push
    push = input(f"\n{Colors.GREEN}Push ke GitHub? (y/n) > {Colors.RESET}").strip().lower()
    if push == 'y':
        result = git_push_domain()
        print(f"\n{Colors.CYAN}{result}{Colors.RESET}")

    input(f"\n{Colors.GREEN}Press Enter...{Colors.RESET}")


def remove_domain_blacklist_cli():
    """Remove domain from blacklist via CLI"""
    print(f"\n{Colors.CYAN}{Colors.BOLD}=== REMOVE DOMAIN FROM BLACKLIST ==={Colors.RESET}")

    domains = load_domain_blacklist()
    if not domains:
        print(f"{Colors.YELLOW}Domain blacklist kosong.{Colors.RESET}")
        input(f"{Colors.GREEN}Press Enter...{Colors.RESET}")
        return

    print(f"\n{Colors.CYAN}Domain saat ini ({len(domains)}):{Colors.RESET}")
    sorted_domains = sorted(domains)
    for i, domain in enumerate(sorted_domains, 1):
        print(f"  {i:3}. {domain}")

    print(f"\n{Colors.YELLOW}Masukkan domain yang ingin dihapus:")
    print(f"(bisa nomor, nama domain, atau beberapa dipisahkan koma){Colors.RESET}\n")

    user_input = input(f"{Colors.GREEN}Domain > {Colors.RESET}").strip()

    if not user_input:
        print(f"{Colors.YELLOW}Dibatalkan.{Colors.RESET}")
        input(f"{Colors.GREEN}Press Enter...{Colors.RESET}")
        return

    # Parse input - could be numbers or domain names
    to_remove = []
    for part in user_input.replace(',', ' ').split():
        part = part.strip()
        if part.isdigit():
            idx = int(part) - 1
            if 0 <= idx < len(sorted_domains):
                to_remove.append(sorted_domains[idx])
        else:
            part = part.lower()
            if part in domains:
                to_remove.append(part)

    if not to_remove:
        print(f"{Colors.YELLOW}Domain tidak ditemukan.{Colors.RESET}")
        input(f"{Colors.GREEN}Press Enter...{Colors.RESET}")
        return

    print(f"\n{Colors.CYAN}Akan dihapus:{Colors.RESET}")
    for d in to_remove:
        print(f"  - {d}")

    confirm = input(f"\n{Colors.GREEN}Konfirmasi hapus? (y/n) > {Colors.RESET}").strip().lower()
    if confirm != 'y':
        print(f"{Colors.YELLOW}Dibatalkan.{Colors.RESET}")
        input(f"{Colors.GREEN}Press Enter...{Colors.RESET}")
        return

    removed = 0
    for domain in to_remove:
        if remove_from_domain_blacklist(domain):
            removed += 1
            print(f"  {Colors.GREEN}Removed: {domain}{Colors.RESET}")

    print(f"\n{Colors.CYAN}Total dihapus: {removed}{Colors.RESET}")

    # Auto push
    push = input(f"\n{Colors.GREEN}Push ke GitHub? (y/n) > {Colors.RESET}").strip().lower()
    if push == 'y':
        result = git_push_domain()
        print(f"\n{Colors.CYAN}{result}{Colors.RESET}")

    input(f"\n{Colors.GREEN}Press Enter...{Colors.RESET}")


def search_domain_blacklist_cli():
    """Search domain in blacklist via CLI"""
    print(f"\n{Colors.CYAN}{Colors.BOLD}=== SEARCH DOMAIN BLACKLIST ==={Colors.RESET}")

    query = input(f"\n{Colors.GREEN}Cari domain > {Colors.RESET}").strip().lower()

    if not query:
        print(f"{Colors.YELLOW}Pencarian dibatalkan.{Colors.RESET}")
        input(f"{Colors.GREEN}Press Enter...{Colors.RESET}")
        return

    results = search_domain_blacklist(query)

    if not results:
        print(f"\n{Colors.YELLOW}Tidak ditemukan domain dengan keyword '{query}'{Colors.RESET}")
    else:
        print(f"\n{Colors.CYAN}Ditemukan {len(results)} domain:{Colors.RESET}")
        for i, domain in enumerate(sorted(results), 1):
            # Highlight the query match
            highlighted = domain.replace(query, f"{Colors.RED}{query}{Colors.RESET}")
            print(f"  {i:3}. {highlighted}")

    input(f"\n{Colors.GREEN}Press Enter...{Colors.RESET}")


def run_cli():
    """Run CLI mode"""
    clear_screen()
    print_banner()
    git_pull()

    # Sync blacklist db on startup
    sync_blacklist_db()
    sync_domain_blacklist_db()

    # Check API keys
    missing = []
    if not VT_API_KEY:
        missing.append("VIRUSTOTAL_API_KEY")
    if not ABUSEIPDB_API_KEY:
        missing.append("ABUSEIPDB_API_KEY")
    if missing:
        print(f"\n{Colors.YELLOW}[!] Missing: {', '.join(missing)}{Colors.RESET}")

    while True:
        try:
            clear_screen()
            print_banner()
            print_menu()

            choice = input(f"{Colors.GREEN}Select [0-10] > {Colors.RESET}").strip()

            if choice == '0':
                print(f"\n{Colors.CYAN}Goodbye!{Colors.RESET}\n")
                break
            elif choice == '1':
                clear_screen()
                print(f"\n{Colors.CYAN}{Colors.BOLD}=== CHECK SOURCE IP ==={Colors.RESET}")
                data = get_multiline_input()
                if data:
                    ips = extract_ips_from_text(data, "source")
                    process_ips_cli(ips, "source")
            elif choice == '2':
                clear_screen()
                print(f"\n{Colors.CYAN}{Colors.BOLD}=== CHECK DESTINATION IP ==={Colors.RESET}")
                data = get_multiline_input()
                if data:
                    ips = extract_ips_from_text(data, "dest")
                    process_ips_cli(ips, "destination")
            elif choice == '3':
                check_single_ip_cli()
            elif choice == '4':
                clear_screen()
                show_blacklist_cli()
            elif choice == '5':
                clear_screen()
                print(f"\n{Colors.CYAN}{Colors.BOLD}=== PUSH TO GITHUB ==={Colors.RESET}")
                result = git_push()
                print(f"\n{result}")
                input(f"\n{Colors.GREEN}Press Enter...{Colors.RESET}")
            elif choice == '6':
                clear_screen()
                print(f"\n{Colors.CYAN}{Colors.BOLD}=== PULL FROM GITHUB ==={Colors.RESET}")
                result = git_pull()
                print(f"\n{result}")
                input(f"\n{Colors.GREEN}Press Enter...{Colors.RESET}")
            elif choice == '7':
                clear_screen()
                print(f"""
{Colors.CYAN}{Colors.BOLD}HELP{Colors.RESET}

{Colors.YELLOW}DESCRIPTION:{Colors.RESET}
    Check IP reputation using VirusTotal & AbuseIPDB.
    Malicious IPs are auto-added to blacklist and pushed to GitHub.

{Colors.YELLOW}MENU IP:{Colors.RESET}
    [1] Check Source IP      - Extract first IP per line
    [2] Check Destination IP - Extract second IP per line
    [3] Check Single IP      - Manual single IP check
    [4] View IP Blacklist    - Show blocked IPs
    [5] Push to GitHub       - Manual push
    [6] Pull from GitHub     - Sync from remote
    [8] Force Blacklist IP   - Blacklist tanpa cek VT/AbuseIPDB
    [9] Unblacklist IP       - Hapus IP dari blacklist
    [10] Dump IP by Date     - Tampilkan IP berdasarkan tanggal

{Colors.YELLOW}MENU DOMAIN:{Colors.RESET}
    [11] View Domain Blacklist    - Lihat domain yang di-blacklist
    [12] Add Domain Blacklist     - Tambah domain ke blacklist
    [13] Remove Domain Blacklist  - Hapus domain dari blacklist
    [14] Search Domain Blacklist  - Cari domain di blacklist

{Colors.YELLOW}SIEM FORMAT:{Colors.RESET}
    Paste data from QRadar/Splunk directly.
    Tool will auto-extract IPs.

{Colors.YELLOW}THRESHOLD:{Colors.RESET}
    IP is MALICIOUS if:
    - VirusTotal: 1+ detection
    - AbuseIPDB: Score > 0 or Reports > 0

{Colors.YELLOW}FORCE BLACKLIST:{Colors.RESET}
    Untuk IP dengan aktivitas anomaly yang perlu
    di-blacklist langsung tanpa menunggu hasil cek.

{Colors.YELLOW}UNBLACKLIST:{Colors.RESET}
    Untuk menghapus IP/domain yang salah masuk blacklist
    atau sudah tidak lagi berbahaya.

{Colors.YELLOW}DUMP IP:{Colors.RESET}
    Menampilkan daftar IP yang di-blacklist
    berdasarkan rentang tanggal tertentu.

{Colors.YELLOW}DOMAIN BLACKLIST:{Colors.RESET}
    Untuk memblokir domain berbahaya seperti
    phishing, malware, atau domain mencurigakan.
    File: List-Domain-Blacklist.txt
""")
                input(f"{Colors.GREEN}Press Enter...{Colors.RESET}")
            elif choice == '8':
                clear_screen()
                force_blacklist_cli()
            elif choice == '9':
                clear_screen()
                unblacklist_cli()
            elif choice == '10':
                clear_screen()
                dump_ip_cli()
            elif choice == '11':
                clear_screen()
                view_domain_blacklist_cli()
            elif choice == '12':
                clear_screen()
                add_domain_blacklist_cli()
            elif choice == '13':
                clear_screen()
                remove_domain_blacklist_cli()
            elif choice == '14':
                clear_screen()
                search_domain_blacklist_cli()

        except KeyboardInterrupt:
            print(f"\n{Colors.CYAN}Use [0] to exit{Colors.RESET}")
            input()


# ==================================================
# TELEGRAM BOT MODE
# ==================================================
def run_telegram():
    """Run Telegram Bot mode"""
    try:
        from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
        from telegram.ext import (
            ApplicationBuilder, CommandHandler, MessageHandler,
            CallbackQueryHandler, ContextTypes, filters
        )
    except ImportError:
        print("Installing python-telegram-bot...")
        install_package("python-telegram-bot")
        from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
        from telegram.ext import (
            ApplicationBuilder, CommandHandler, MessageHandler,
            CallbackQueryHandler, ContextTypes, filters
        )

    if not BOT_TOKEN:
        print("ERROR: TELEGRAM_BOT_TOKEN not set in .env")
        sys.exit(1)
    
    # Sync blacklist db on startup
    sync_blacklist_db()
    sync_domain_blacklist_db()

    # User sessions
    user_sessions = {}

    # Auth helpers
    def check_access(update: Update) -> str:
        """Check user access level: admin, staff, group, or denied"""
        uid = update.effective_user.id
        cid = update.effective_chat.id

        # Check admin first
        if is_admin(uid):
            return "admin"

        # Check staff
        if is_staff(uid):
            return "staff"

        # Check allowed group
        if cid in ALLOWED_GROUP_IDS:
            return "group"

        # No access
        logger.warning(f"ACCESS_DENIED | USER={uid} | CHAT={cid}")
        return "denied"

    def require_admin(update: Update) -> bool:
        """Check if user is admin"""
        return is_admin(update.effective_user.id)

    def require_access(update: Update) -> bool:
        """Check if user has any access (admin, staff, or allowed group)"""
        return check_access(update) != "denied"

    # Keyboards
    def main_keyboard():
        return InlineKeyboardMarkup([
            [InlineKeyboardButton("\U0001F50D Check IP Satuan", callback_data="single")],
            [
                InlineKeyboardButton("\U0001F4E5 Source IP", callback_data="source"),
                InlineKeyboardButton("\U0001F4E4 Dest IP", callback_data="dest"),
            ],
            [InlineKeyboardButton("\U0001F4CB Check Semua IP", callback_data="all")],
            [InlineKeyboardButton("\U0001F4C4 Upload File TXT", callback_data="file_upload")],
            [
                InlineKeyboardButton("\U0001F4DC IP Blacklist", callback_data="blacklist"),
                InlineKeyboardButton("\U0001F50E Cari IP", callback_data="search"),
            ],
            [
                InlineKeyboardButton("\u26a0\ufe0f Force BL IP", callback_data="force_bl"),
                InlineKeyboardButton("\u2705 Unblacklist IP", callback_data="unblacklist"),
            ],
            [InlineKeyboardButton("\U0001F4C5 Dump IP", callback_data="dump_ip")],
            [InlineKeyboardButton("\U0001F310 Domain Blacklist", callback_data="domain_menu")],
            [InlineKeyboardButton("\u2139\ufe0f Help", callback_data="help")]
        ])

    def back_keyboard():
        return InlineKeyboardMarkup([
            [InlineKeyboardButton("\u2B05\ufe0f Menu", callback_data="menu")]
        ])

    def cancel_keyboard():
        return InlineKeyboardMarkup([
            [InlineKeyboardButton("\u274c Batal", callback_data="cancel")]
        ])

    def file_type_keyboard():
        return InlineKeyboardMarkup([
            [
                InlineKeyboardButton("\U0001F4E5 Source IP", callback_data="file_source"),
                InlineKeyboardButton("\U0001F4E4 Dest IP", callback_data="file_dest"),
            ],
            [InlineKeyboardButton("\U0001F4CB Semua IP", callback_data="file_all")],
            [InlineKeyboardButton("\u274c Batal", callback_data="cancel")]
        ])
    
    def dump_ip_keyboard():
        return InlineKeyboardMarkup([
            [InlineKeyboardButton("\U0001F4C5 Hari Ini", callback_data="dump_today")],
            [InlineKeyboardButton("\U0001F4C6 Minggu Ini", callback_data="dump_week")],
            [InlineKeyboardButton("\U0001F4C7 Bulan Ini", callback_data="dump_month")],
            [InlineKeyboardButton("\U0001F4C5 Pilih Tanggal", callback_data="dump_custom")],
            [InlineKeyboardButton("\U0001F4C5 Range Tanggal", callback_data="dump_range")],
            [InlineKeyboardButton("\u2B05\ufe0f Menu", callback_data="menu")]
        ])

    def domain_keyboard():
        return InlineKeyboardMarkup([
            [InlineKeyboardButton("\U0001F4DC View Domain Blacklist", callback_data="domain_view")],
            [InlineKeyboardButton("\u2795 Add Domain", callback_data="domain_add")],
            [InlineKeyboardButton("\u2796 Remove Domain", callback_data="domain_remove")],
            [InlineKeyboardButton("\U0001F50E Search Domain", callback_data="domain_search")],
            [InlineKeyboardButton("\U0001F4C5 Dump Domain", callback_data="domain_dump")],
            [InlineKeyboardButton("\u2B05\ufe0f Menu", callback_data="menu")]
        ])

    def domain_dump_keyboard():
        return InlineKeyboardMarkup([
            [InlineKeyboardButton("\U0001F4C5 Hari Ini", callback_data="domain_dump_today")],
            [InlineKeyboardButton("\U0001F4C6 Minggu Ini", callback_data="domain_dump_week")],
            [InlineKeyboardButton("\U0001F4C7 Bulan Ini", callback_data="domain_dump_month")],
            [InlineKeyboardButton("\u2B05\ufe0f Menu", callback_data="menu")]
        ])

    def admin_keyboard(uid: int = 0):
        rows = [
            [
                InlineKeyboardButton("\U0001F4E4 Push", callback_data="push"),
                InlineKeyboardButton("\U0001F4E5 Pull", callback_data="pull"),
            ],
            [InlineKeyboardButton("\U0001F465 List Staff", callback_data="list_staff")],
            [
                InlineKeyboardButton("\u2795 Add Staff", callback_data="add_staff"),
                InlineKeyboardButton("\u2796 Remove Staff", callback_data="remove_staff"),
            ],
            [InlineKeyboardButton("\U0001F50D Tracking IP", callback_data="admin_tracking")],
        ]
        if is_super_admin(uid):
            rows.append([InlineKeyboardButton("\U0001F451 List Admin", callback_data="list_admin")])
            rows.append([
                InlineKeyboardButton("\u2795 Add Admin", callback_data="add_admin"),
                InlineKeyboardButton("\u2796 Remove Admin", callback_data="remove_admin"),
            ])
        rows.append([InlineKeyboardButton("\u2B05\ufe0f Menu", callback_data="menu")])
        return InlineKeyboardMarkup(rows)

    def confirm_blacklist_keyboard(ip: str) -> InlineKeyboardMarkup:
        """YES/NO inline buttons for blacklist confirmation (single IP)"""
        ip_b64 = base64.urlsafe_b64encode(ip.encode()).decode()
        return InlineKeyboardMarkup([
            [
                InlineKeyboardButton("\u2705 YES - BLACKLIST", callback_data=f"confirm_bl_yes_{ip_b64}"),
                InlineKeyboardButton("\u274c NO - SKIP", callback_data=f"confirm_bl_no_{ip_b64}"),
            ]
        ])

    def confirm_force_bl_keyboard() -> InlineKeyboardMarkup:
        """YES/NO inline buttons for force blacklist confirmation (bulk/CIDR/range)"""
        return InlineKeyboardMarkup([
            [
                InlineKeyboardButton("\u2705 YES - FORCE BLACKLIST", callback_data="confirm_force_yes"),
                InlineKeyboardButton("\u274c NO - BATAL", callback_data="confirm_force_no"),
            ]
        ])

    # Safe message edit with retry
    def log_telegram_message(update: Update):
        """Log incoming telegram message dengan format yang clean"""
        try:
            user = update.effective_user
            chat = update.effective_chat
            message = update.message
            
            if not message:  # Skip callback queries
                return
            
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            
            # Get message text
            text = message.text if message.text else "[Non-text message]"
            
            # Format chat type emoji
            chat_type_emoji = {
                'private': '👤',
                'group': '👥',
                'supergroup': '👥',
                'channel': '📢'
            }.get(chat.type, '💬')
            
            # Print ke console dengan format yang clean
            print("\n" + "="*60)
            print(f"⏰ Time: {timestamp}")
            print(f"💬 Message from: {user.first_name} (ID: {user.id})")
            print(f"🆔 Chat ID: {chat.id}")
            print(f"{chat_type_emoji} Chat Type: {chat.type}")
            if chat.title:
                print(f"📝 Chat Name: {chat.title}")
            print(f"💭 Text: {text}")
            print("="*60)
            print()
            
            # Log ke file dengan format yang lebih ringkas
            logger.info(f"MSG | User={user.id} | Chat={chat.id} | Type={chat.type} | Text={text[:50]}")
            
        except Exception as e:
            logger.error(f"LOG_MESSAGE_ERROR | {str(e)}")

    async def safe_edit_message(msg, text, parse_mode="Markdown", reply_markup=None, max_retries=2):
        """Edit message with retry logic to handle timeout"""
        for attempt in range(max_retries):
            try:
                await msg.edit_text(text, parse_mode=parse_mode, reply_markup=reply_markup)
                return True
            except Exception as e:
                if attempt < max_retries - 1:
                    await asyncio.sleep(0.5)
                else:
                    logger.warning(f"MSG_EDIT_FAILED | {str(e)}")
                    return False
        return False

    # Format result
    def format_result(ip: str, vt: dict, abuse: dict) -> tuple:
        is_mal = False
        msg = f"{'='*35}\nIP: `{ip}`\n{'='*35}\n\n"

        msg += "**VirusTotal:**\n"
        if "error" in vt:
            msg += f"  Error: {vt['error']}\n"
        else:
            m_icon = "\u26a0\ufe0f" if vt['malicious'] > 0 else "\u2705"
            s_icon = "\u26a0\ufe0f" if vt['suspicious'] > 0 else "\u2705"
            msg += f"  {m_icon} Malicious: {vt['malicious']}\n"
            msg += f"  {s_icon} Suspicious: {vt['suspicious']}\n"
            msg += f"  Country: {vt['country']}\n"
            msg += f"  ASN: {vt['as_owner'][:40]}\n"
            if vt['is_bad']:
                is_mal = True

        msg += "\n**AbuseIPDB:**\n"
        if "error" in abuse:
            msg += f"  Error: {abuse['error']}\n"
        else:
            sc_icon = "\u26a0\ufe0f" if abuse['abuse_score'] > 0 else "\u2705"
            msg += f"  {sc_icon} Score: {abuse['abuse_score']}%\n"
            msg += f"  Reports: {abuse['total_reports']}\n"
            msg += f"  ISP: {abuse['isp'][:40]}\n"
            if abuse['is_tor']:
                msg += "  \u26a0\ufe0f TOR Exit Node!\n"
            if abuse['is_bad']:
                is_mal = True

        msg += f"\n{'='*35}\n"
        msg += "\u274c **MALICIOUS**\n" if is_mal else "\u2705 **CLEAN**\n"

        return msg, is_mal

    def get_blacklist_info_text(ip: str) -> str:
        """Return formatted text showing who blacklisted an IP (for admins)"""
        db = load_blacklist_db()
        if ip not in db:
            return ""
        info = db[ip]
        added_by = info.get("added_by")
        added_by_username = info.get("added_by_username", "unknown")
        added_at = info.get("added_at", "unknown")
        reason = info.get("reason", "unknown")
        if added_by:
            by_str = f"@{added_by_username} (ID: {added_by})"
        else:
            by_str = "Unknown (legacy entry)"
        return (
            f"\n\U0001F512 Blacklisted by: {by_str}\n"
            f"\U0001F4C5 Blacklisted at: {added_at}\n"
            f"\U0001F4CB Reason: {reason}\n"
        )

    def format_tracking_page(activities: list, page: int, per_page: int = 10) -> tuple:
        """Format a page of activity entries (activities already in display order).
        Returns (text, total_pages, page)."""
        total = len(activities)
        total_pages = max(1, (total + per_page - 1) // per_page)
        page = max(0, min(page, total_pages - 1))
        start = page * per_page
        chunk = activities[start:start + per_page]

        text = "\U0001F4CA TRACKING IP - BLACKLIST ACTIVITY\n"
        text += "\u2501" * 30 + "\n\n"
        if not activities:
            text += "Belum ada aktivitas tercatat.\n"
        else:
            emojis = {
                "blacklist": "\U0001F534",
                "force_blacklist": "\u26A0\uFE0F",
                "unblacklist": "\U0001F7E2",
            }
            for i, act in enumerate(chunk, start=start + 1):
                action_icon = emojis.get(act.get("action", ""), "\u2B55")
                action_label = act.get("action", "?").upper()
                ts = act.get("timestamp", "?")[:16]
                ip_val = act.get("ip", "?")
                uname_val = act.get("username", "?")
                uid_val = act.get("user_id", "?")
                reason_val = act.get("reason", "?")
                text += f"{i}. [{ts}] {action_icon} {action_label}\n"
                text += f"   \U0001F310 IP: {ip_val}\n"
                text += f"   \U0001F464 By: @{uname_val} (ID: {uid_val})\n"
                text += f"   \U0001F4CB Reason: {reason_val}\n\n"

        text += f"Halaman {page + 1}/{total_pages} | Total: {total}"
        return text, total_pages, page

    def tracking_nav_keyboard(page: int, total_pages: int) -> InlineKeyboardMarkup:
        """Navigation keyboard for tracking view"""
        nav_row = []
        if page > 0:
            nav_row.append(InlineKeyboardButton("\u25C0 Prev", callback_data=f"tracking_page_{page - 1}"))
        if page < total_pages - 1:
            nav_row.append(InlineKeyboardButton("\u25B6 Next", callback_data=f"tracking_page_{page + 1}"))
        rows = []
        if nav_row:
            rows.append(nav_row)
        rows.append([InlineKeyboardButton("\U0001F50E Cari by IP", callback_data="tracking_search")])
        rows.append([InlineKeyboardButton("\u2B05\uFE0F Admin", callback_data="admin_back")])
        return InlineKeyboardMarkup(rows)

    async def send_ip_file(update_or_query, ips: list, title: str, date_str: str):
        """Create and send IP file to Telegram"""
        if not ips:
            msg = f"**{title}**\n\n_Tidak ada IP ditemukan pada periode ini._"
            if hasattr(update_or_query, 'edit_message_text'):
                await update_or_query.edit_message_text(msg, parse_mode="Markdown", reply_markup=back_keyboard())
            else:
                await update_or_query.message.reply_text(msg, parse_mode="Markdown", reply_markup=back_keyboard())
            return
        
        # Create temporary file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as tmp_file:
            for item in ips:
                tmp_file.write(f"{item['ip']}\n")
            tmp_filename = tmp_file.name
        
        # Send file
        try:
            caption = f"📄 {title}\nTotal: {len(ips)} IP"
            
            # Open file for reading
            with open(tmp_filename, 'rb') as file:
                if hasattr(update_or_query, 'message'):
                    # This is a callback query
                    await update_or_query.message.reply_document(
                        document=file,
                        filename=f"ip_blacklist_{date_str}.txt",
                        caption=caption,
                        reply_markup=back_keyboard()
                    )
                else:
                    # This is an update message
                    await update_or_query.message.reply_document(
                        document=file,
                        filename=f"ip_blacklist_{date_str}.txt",
                        caption=caption,
                        reply_markup=back_keyboard()
                    )
        finally:
            # Clean up temporary file
            if os.path.exists(tmp_filename):
                os.remove(tmp_filename)

    # Handlers
    async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
        # Log command
        log_telegram_message(update)
        
        access = check_access(update)
        uid = update.effective_user.id
        uname = update.effective_user.username or update.effective_user.first_name

        if access == "denied":
            # Log unauthorized access attempt
            logger.warning(f"UNAUTHORIZED_START | USER={uid} | USERNAME={uname}")
            await update.message.reply_text(
                "\u274c **Akses Ditolak**\n\n"
                f"User ID: `{uid}`\n"
                f"Username: @{uname}\n\n"
                "_Hubungi admin untuk mendapatkan akses._",
                parse_mode="Markdown"
            )
            return

        role_label = {"admin": "\U0001F451 Admin", "staff": "\U0001F464 Staff", "group": "\U0001F465 Group"}
        msg = f"**SOC IP Reputation Bot**\nBIOFARMA Security Operations Center\n\n"
        msg += f"Role: {role_label.get(access, 'Unknown')}\n"
        msg += f"User: @{uname}\n\n"
        msg += "Pilih menu:"

        logger.info(f"START | USER={uid} | ROLE={access}")
        await update.message.reply_text(msg, parse_mode="Markdown", reply_markup=main_keyboard())

    async def admin_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
        if not require_admin(update):
            await update.message.reply_text("\u274c **Admin only**\n\nAnda tidak memiliki akses admin.", parse_mode="Markdown")
            return

        uid = update.effective_user.id
        staff_count = len(get_all_staff())
        await update.message.reply_text(
            f"**\U0001F6E1 Admin Panel**\n\n"
            f"Total Staff: {staff_count}\n\n"
            "Pilih aksi:",
            parse_mode="Markdown",
            reply_markup=admin_keyboard(uid)
        )

    async def button(update: Update, context: ContextTypes.DEFAULT_TYPE):
        query = update.callback_query
        await query.answer()

        if not require_access(update):
            await query.edit_message_text("\u274c Access denied")
            return

        data = query.data
        uid = update.effective_user.id
        uname = update.effective_user.username or update.effective_user.first_name

        # Staff management handlers (admin only)
        if data == "list_staff":
            if not require_admin(update):
                await query.edit_message_text("\u274c Admin only")
                return

            staff = get_all_staff()
            if not staff:
                msg = "\U0001F465 Daftar Staff\n\nBelum ada staff terdaftar."
            else:
                msg = f"\U0001F465 Daftar Staff ({len(staff)})\n\n"
                for i, (sid, info) in enumerate(staff.items(), 1):
                    username = info.get('username', 'Unknown')
                    added_at = info.get('added_at', 'Unknown')[:10]
                    msg += f"{i}. {sid} - {username}\n"
                    msg += f"   Added: {added_at}\n"

            await query.edit_message_text(msg, reply_markup=admin_keyboard(uid))
            return

        elif data == "add_staff":
            if not require_admin(update):
                await query.edit_message_text("\u274c Admin only")
                return

            user_sessions[uid] = {"mode": "add_staff"}
            await query.edit_message_text(
                "\u2795 Tambah Staff\n\n"
                "Kirim User ID yang ingin ditambahkan.\n\n"
                "Cara mendapatkan User ID:\n"
                "1. Minta user kirim /start ke bot\n"
                "2. User ID akan tampil di pesan denied\n\n"
                "Format: 123456789 atau 123456789 username",
                reply_markup=cancel_keyboard()
            )
            return

        elif data == "remove_staff":
            if not require_admin(update):
                await query.edit_message_text("\u274c Admin only")
                return

            staff = get_all_staff()
            if not staff:
                await query.edit_message_text(
                    "\u2796 Hapus Staff\n\nBelum ada staff terdaftar.",
                    reply_markup=admin_keyboard(uid)
                )
                return

            user_sessions[uid] = {"mode": "remove_staff"}
            msg = "\u2796 Hapus Staff\n\nPilih User ID yang ingin dihapus:\n\n"
            for sid, info in staff.items():
                username = info.get('username', 'Unknown')
                msg += f"\u2022 {sid} - {username}\n"
            msg += "\nKirim User ID untuk menghapus"

            await query.edit_message_text(msg, reply_markup=cancel_keyboard())
            return
        
        # Dump IP handlers
        elif data == "dump_ip":
            stats = get_blacklist_stats()
            msg = f"\U0001F4C5 **Dump IP Blacklist**\n\n"
            msg += f"**Statistik:**\n"
            msg += f"  \u2022 Total: {stats['total']} IP\n"
            msg += f"  \u2022 Hari ini: {stats['today']} IP\n"
            msg += f"  \u2022 Minggu ini: {stats['this_week']} IP\n"
            msg += f"  \u2022 Bulan ini: {stats['this_month']} IP\n\n"
            msg += "Pilih periode:"
            
            await query.edit_message_text(msg, parse_mode="Markdown", reply_markup=dump_ip_keyboard())
            return
        
        elif data == "dump_today":
            today = datetime.now()
            ips = get_ips_by_single_date(today)
            date_str = today.strftime('%Y%m%d')
            title = f"IP Blacklist Hari Ini ({today.strftime('%Y-%m-%d')})"
            await send_ip_file(query, ips, title, date_str)
            return
        
        elif data == "dump_week":
            today = datetime.now()
            week_start = today - timedelta(days=today.weekday())
            ips = get_ips_by_date_range(week_start, today)
            date_str = f"{week_start.strftime('%Y%m%d')}_{today.strftime('%Y%m%d')}"
            title = f"IP Blacklist Minggu Ini ({week_start.strftime('%Y-%m-%d')} s/d {today.strftime('%Y-%m-%d')})"
            await send_ip_file(query, ips, title, date_str)
            return
        
        elif data == "dump_month":
            today = datetime.now()
            month_start = today.replace(day=1)
            ips = get_ips_by_date_range(month_start, today)
            date_str = f"{month_start.strftime('%Y%m%d')}_{today.strftime('%Y%m%d')}"
            title = f"IP Blacklist Bulan Ini ({month_start.strftime('%Y-%m-%d')} s/d {today.strftime('%Y-%m-%d')})"
            await send_ip_file(query, ips, title, date_str)
            return
        
        elif data == "dump_custom":
            user_sessions[uid] = {"mode": "dump_custom"}
            await query.edit_message_text(
                "\U0001F4C5 **Pilih Tanggal**\n\n"
                "Kirim tanggal dalam format:\n"
                "`YYYY-MM-DD`\n\n"
                "Contoh: `2025-01-15`",
                parse_mode="Markdown",
                reply_markup=cancel_keyboard()
            )
            return
        
        elif data == "dump_range":
            user_sessions[uid] = {"mode": "dump_range_start"}
            await query.edit_message_text(
                "\U0001F4C5 **Range Tanggal**\n\n"
                "Kirim **tanggal awal** dalam format:\n"
                "`YYYY-MM-DD`\n\n"
                "Contoh: `2025-01-01`",
                parse_mode="Markdown",
                reply_markup=cancel_keyboard()
            )
            return

        if data == "menu":
            if uid in user_sessions:
                del user_sessions[uid]
            await query.edit_message_text(
                "**SOC IP Reputation Bot**\n\nPilih menu:",
                parse_mode="Markdown", reply_markup=main_keyboard()
            )

        elif data == "cancel":
            if uid in user_sessions:
                del user_sessions[uid]
            await query.edit_message_text(
                "Dibatalkan.\n\nPilih menu:",
                parse_mode="Markdown", reply_markup=main_keyboard()
            )

        elif data == "single":
            user_sessions[uid] = {"mode": "single"}
            await query.edit_message_text(
                "**Check IP Satuan**\n\nKirim IP:\n_Contoh: 8.8.8.8_",
                parse_mode="Markdown", reply_markup=cancel_keyboard()
            )

        elif data in ["source", "dest", "all"]:
            user_sessions[uid] = {"mode": "bulk", "ips": [], "type": data}
            labels = {"source": "Source IP", "dest": "Destination IP", "all": "Semua IP"}
            await query.edit_message_text(
                f"**Check {labels[data]}**\n\n"
                "Paste data SIEM, ketik `DONE` jika selesai.",
                parse_mode="Markdown", reply_markup=cancel_keyboard()
            )

        elif data == "blacklist":
            bl = load_blacklist()
            if not bl:
                msg = "Blacklist kosong."
            else:
                sorted_bl = sorted(bl)
                msg = f"**Blacklist** ({len(bl)} IP)\n\n"
                for i, ip in enumerate(sorted_bl[:50], 1):
                    msg += f"{i}. `{ip}`\n"
                if len(sorted_bl) > 50:
                    msg += f"\n_...dan {len(sorted_bl)-50} lainnya_"
            await query.edit_message_text(msg, parse_mode="Markdown", reply_markup=back_keyboard())

        elif data == "search":
            user_sessions[uid] = {"mode": "search"}
            await query.edit_message_text(
                "**Cari Blacklist**\n\nKirim IP/keyword:",
                parse_mode="Markdown", reply_markup=cancel_keyboard()
            )

        elif data == "force_bl":
            user_sessions[uid] = {"mode": "force_bl"}
            await query.edit_message_text(
                "\u26a0\ufe0f **Force Blacklist**\n\n"
                "Blacklist IP langsung **tanpa cek** VT/AbuseIPDB.\n"
                "Gunakan untuk IP dengan aktivitas anomaly.\n\n"
                "**Format yang didukung:**\n"
                "• Single IP: `1.2.3.4`\n"
                "• CIDR: `10.0.0.0/24`\n"
                "• Range: `10.0.0.1-10.0.0.5` atau `10.0.0.1-5`\n\n"
                "Kirim IP/CIDR/Range yang ingin di-blacklist:",
                parse_mode="Markdown", reply_markup=cancel_keyboard()
            )

        elif data == "unblacklist":
            user_sessions[uid] = {"mode": "unblacklist"}
            bl = load_blacklist()
            if not bl:
                await query.edit_message_text(
                    "\u26a0\ufe0f Blacklist kosong.",
                    reply_markup=back_keyboard()
                )
                del user_sessions[uid]
                return

            await query.edit_message_text(
                "\u2705 **Unblacklist**\n\n"
                f"Total IP di blacklist: **{len(bl)}**\n\n"
                "Kirim IP yang ingin dihapus dari blacklist:",
                parse_mode="Markdown", reply_markup=cancel_keyboard()
            )

        elif data == "file_upload":
            await query.edit_message_text(
                "**\U0001F4C4 Upload File TXT**\n\n"
                "Pilih tipe IP yang ingin di-check:\n\n"
                "\u2022 **Source IP** - IP pertama tiap baris\n"
                "\u2022 **Dest IP** - IP kedua tiap baris\n"
                "\u2022 **Semua IP** - Semua IP dalam file",
                parse_mode="Markdown",
                reply_markup=file_type_keyboard()
            )

        elif data in ["file_source", "file_dest", "file_all"]:
            ip_type = data.replace("file_", "")
            user_sessions[uid] = {"mode": "file_upload", "type": ip_type}
            labels = {"source": "Source IP", "dest": "Destination IP", "all": "Semua IP"}
            await query.edit_message_text(
                f"**Upload File TXT - {labels[ip_type]}**\n\n"
                "Kirim file `.txt` yang berisi daftar IP.\n\n"
                "**Format file:**\n"
                "```\n"
                "192.168.1.1  8.8.8.8\n"
                "10.0.0.1     1.1.1.1\n"
                "```\n"
                "atau langsung IP per baris:\n"
                "```\n"
                "8.8.8.8\n"
                "1.1.1.1\n"
                "```",
                parse_mode="Markdown",
                reply_markup=cancel_keyboard()
            )

        elif data == "help":
            help_msg = """
**SOC Bot Help**

**Check IP:**
\u2022 IP Satuan - Cek 1 IP
\u2022 Source IP - IP pertama tiap baris
\u2022 Dest IP - IP kedua tiap baris
\u2022 Semua IP - Semua IP

**Upload File TXT:**
\u2022 Untuk check IP massal via file
\u2022 Format: IP per baris atau SIEM data
\u2022 Max size: 1MB

**Force Blacklist:**
\u2022 Blacklist IP langsung tanpa cek VT/AbuseIPDB
\u2022 Untuk IP dengan aktivitas anomaly

**Unblacklist:**
\u2022 Hapus IP dari blacklist
\u2022 Untuk IP yang salah masuk atau sudah aman

**Dump IP:**
\u2022 Tampilkan IP berdasarkan tanggal
\u2022 Bisa pilih hari ini, minggu, bulan
\u2022 Atau pilih range tanggal custom

**Domain Blacklist:**
\u2022 View, Add, Remove, Search domain
\u2022 Untuk blokir domain berbahaya
\u2022 File: List-Domain-Blacklist.txt

**Format SIEM:**
**Auto:**
\u2022 IP malicious \u2192 blacklist
\u2022 Auto-push ke GitHub
"""
            await query.edit_message_text(help_msg, parse_mode="Markdown", reply_markup=back_keyboard())

        elif data == "push":
            if not require_admin(update):
                return
            result = git_push()
            await query.edit_message_text(f"**Git Push**\n\n{result}", parse_mode="Markdown", reply_markup=admin_keyboard(uid))

        elif data == "pull":
            if not require_admin(update):
                return
            result = git_pull()
            await query.edit_message_text(f"**Git Pull**\n\n{result}", parse_mode="Markdown", reply_markup=admin_keyboard(uid))

        # Domain Blacklist handlers
        elif data == "domain_menu":
            stats = get_domain_blacklist_stats()
            await query.edit_message_text(
                f"\U0001F310 **Domain Blacklist Menu**\n\n"
                f"**Statistik:**\n"
                f"\u2022 Total: {stats['total']} domain\n"
                f"\u2022 Hari ini: {stats['today']}\n"
                f"\u2022 Minggu ini: {stats['this_week']}\n"
                f"\u2022 Bulan ini: {stats['this_month']}\n\n"
                f"Pilih aksi:",
                parse_mode="Markdown",
                reply_markup=domain_keyboard()
            )

        elif data == "domain_view":
            domains = load_domain_blacklist()
            if not domains:
                msg = "\U0001F310 **Domain Blacklist**\n\nDomain blacklist kosong."
            else:
                sorted_domains = sorted(domains)
                msg = f"\U0001F310 **Domain Blacklist** ({len(domains)} domain)\n\n"
                for i, domain in enumerate(sorted_domains[:50], 1):
                    msg += f"{i}. `{domain}`\n"
                if len(sorted_domains) > 50:
                    msg += f"\n_...dan {len(sorted_domains)-50} lainnya_"
            await query.edit_message_text(msg, parse_mode="Markdown", reply_markup=domain_keyboard())

        elif data == "domain_add":
            user_sessions[uid] = {"mode": "domain_add"}
            await query.edit_message_text(
                "\u2795 **Add Domain to Blacklist**\n\n"
                "Kirim domain yang ingin di-blacklist.\n"
                "Bisa satu domain atau beberapa domain.\n\n"
                "Contoh:\n"
                "```\n"
                "malware.example.com\n"
                "phishing-site.net\n"
                "```",
                parse_mode="Markdown",
                reply_markup=cancel_keyboard()
            )

        elif data == "domain_remove":
            user_sessions[uid] = {"mode": "domain_remove"}
            domains = load_domain_blacklist()
            if not domains:
                await query.edit_message_text(
                    "\u26a0\ufe0f Domain blacklist kosong.",
                    reply_markup=domain_keyboard()
                )
                del user_sessions[uid]
                return

            await query.edit_message_text(
                "\u2796 **Remove Domain from Blacklist**\n\n"
                f"Total domain di blacklist: **{len(domains)}**\n\n"
                "Kirim domain yang ingin dihapus dari blacklist:",
                parse_mode="Markdown",
                reply_markup=cancel_keyboard()
            )

        elif data == "domain_search":
            user_sessions[uid] = {"mode": "domain_search"}
            await query.edit_message_text(
                "\U0001F50E **Search Domain Blacklist**\n\n"
                "Kirim keyword untuk mencari domain:",
                parse_mode="Markdown",
                reply_markup=cancel_keyboard()
            )

        elif data == "domain_dump":
            await query.edit_message_text(
                "\U0001F4C5 **Dump Domain by Date**\n\n"
                "Pilih periode:",
                parse_mode="Markdown",
                reply_markup=domain_dump_keyboard()
            )

        elif data == "domain_dump_today":
            today = datetime.now()
            domains = get_domains_by_date_range(today, today)
            if not domains:
                msg = f"\U0001F4C5 **Domain Blacklist Hari Ini**\n\n_Tidak ada domain ditemukan._"
            else:
                msg = f"\U0001F4C5 **Domain Blacklist Hari Ini** ({len(domains)})\n\n"
                for item in domains[:50]:
                    msg += f"\u2022 `{item['domain']}`\n"
            await query.edit_message_text(msg, parse_mode="Markdown", reply_markup=domain_keyboard())

        elif data == "domain_dump_week":
            today = datetime.now()
            week_start = today - timedelta(days=today.weekday())
            domains = get_domains_by_date_range(week_start, today)
            if not domains:
                msg = f"\U0001F4C6 **Domain Blacklist Minggu Ini**\n\n_Tidak ada domain ditemukan._"
            else:
                msg = f"\U0001F4C6 **Domain Blacklist Minggu Ini** ({len(domains)})\n\n"
                for item in domains[:50]:
                    msg += f"\u2022 `{item['domain']}`\n"
            await query.edit_message_text(msg, parse_mode="Markdown", reply_markup=domain_keyboard())

        elif data == "domain_dump_month":
            today = datetime.now()
            month_start = today.replace(day=1)
            domains = get_domains_by_date_range(month_start, today)
            if not domains:
                msg = f"\U0001F4C7 **Domain Blacklist Bulan Ini**\n\n_Tidak ada domain ditemukan._"
            else:
                msg = f"\U0001F4C7 **Domain Blacklist Bulan Ini** ({len(domains)})\n\n"
                for item in domains[:50]:
                    msg += f"\u2022 `{item['domain']}`\n"
            await query.edit_message_text(msg, parse_mode="Markdown", reply_markup=domain_keyboard())

        # ----- Super Admin: Manage Admins -----
        elif data == "list_admin":
            if not is_super_admin(uid):
                await query.edit_message_text("\u274c Super Admin only")
                return
            admins = get_all_admins()
            msg = f"\U0001F451 Daftar Admin\n\n"
            msg += f"0. {SUPER_ADMIN_ID} — Super Admin \U0001F451\n"
            if admins:
                for i, (aid, info) in enumerate(admins.items(), 1):
                    uname_a = info.get("username", "unknown")
                    added_at = info.get("added_at", "?")[:10]
                    msg += f"{i}. {aid} — @{uname_a} (added: {added_at})\n"
            else:
                msg += "\nBelum ada admin tambahan."
            await query.edit_message_text(msg, reply_markup=admin_keyboard(uid))

        elif data == "add_admin":
            if not is_super_admin(uid):
                await query.edit_message_text("\u274c Super Admin only")
                return
            user_sessions[uid] = {"mode": "add_admin"}
            await query.edit_message_text(
                "\u2795 **Tambah Admin**\n\n"
                "Kirim User ID yang ingin dijadikan admin.\n"
                "Format: `123456789` atau `123456789 username`",
                parse_mode="Markdown", reply_markup=cancel_keyboard()
            )

        elif data == "remove_admin":
            if not is_super_admin(uid):
                await query.edit_message_text("\u274c Super Admin only")
                return
            admins = get_all_admins()
            if not admins:
                await query.edit_message_text(
                    "\u2796 **Hapus Admin**\n\nBelum ada admin tambahan.",
                    reply_markup=admin_keyboard(uid)
                )
                return
            user_sessions[uid] = {"mode": "remove_admin"}
            msg = "\u2796 **Hapus Admin**\n\nPilih User ID admin yang ingin dihapus:\n\n"
            for aid, info in admins.items():
                msg += f"\u2022 {aid} — @{info.get('username','?')}\n"
            msg += "\nKirim User ID untuk menghapus:"
            await query.edit_message_text(msg, parse_mode="Markdown", reply_markup=cancel_keyboard())

        # ----- Admin Tracking IP -----
        elif data == "admin_tracking":
            if not require_admin(update):
                await query.edit_message_text("\u274c Admin only")
                return
            acts = load_activity_db().get("activities", [])
            acts_rev = list(reversed(acts))
            text, total_pages, page = format_tracking_page(acts_rev, 0)
            await query.edit_message_text(text, reply_markup=tracking_nav_keyboard(page, total_pages))

        elif data.startswith("tracking_page_"):
            if not require_admin(update):
                await query.edit_message_text("\u274c Admin only")
                return
            try:
                page = int(data.split("tracking_page_")[1])
            except ValueError:
                page = 0
            acts = load_activity_db().get("activities", [])
            acts_rev = list(reversed(acts))
            text, total_pages, page = format_tracking_page(acts_rev, page)
            await query.edit_message_text(text, reply_markup=tracking_nav_keyboard(page, total_pages))

        elif data == "tracking_search":
            if not require_admin(update):
                await query.edit_message_text("\u274c Admin only")
                return
            user_sessions[uid] = {"mode": "tracking_search"}
            await query.edit_message_text(
                "\U0001F50E **Cari Aktivitas by IP**\n\nKirim IP yang ingin dicari:",
                parse_mode="Markdown",
                reply_markup=cancel_keyboard()
            )

        elif data == "admin_back":
            if not require_admin(update):
                await query.edit_message_text("\u274c Admin only")
                return
            staff_count = len(get_all_staff())
            await query.edit_message_text(
                f"**\U0001F6E1 Admin Panel**\n\nTotal Staff: {staff_count}\n\nPilih aksi:",
                parse_mode="Markdown",
                reply_markup=admin_keyboard(uid)
            )

        # ----- Confirm Blacklist YES/NO -----
        elif data.startswith("confirm_bl_yes_") or data.startswith("confirm_bl_no_"):
            try:
                prefix = "confirm_bl_yes_" if data.startswith("confirm_bl_yes_") else "confirm_bl_no_"
                ip_b64 = data[len(prefix):]
                ip = base64.urlsafe_b64decode(ip_b64.encode()).decode()
            except Exception:
                await query.edit_message_text("\u274c Error decoding IP", reply_markup=back_keyboard())
                return

            action = "yes" if data.startswith("confirm_bl_yes_") else "no"
            reason = "Manual - Confirmed via Telegram"

            if action == "yes":
                added = add_to_blacklist(ip, reason, added_by=uid, added_by_username=uname)
                if added:
                    push_result = git_push(silent=True)
                    pushed = push_result and "Success" in push_result
                    reply = f"\u2705 `{ip}` **diblacklist**"
                    if pushed:
                        reply += "\n\U0001F680 _Pushed to GitHub_"
                else:
                    reply = f"\u26a0\ufe0f `{ip}` sudah ada di blacklist"
            else:
                reply = f"\u274c `{ip}` **diskip**"

            await query.edit_message_text(reply, parse_mode="Markdown", reply_markup=back_keyboard())

        # ----- Confirm Force Blacklist YES/NO -----
        elif data in ("confirm_force_yes", "confirm_force_no"):
            session = user_sessions.get(uid, {})
            if session.get("mode") != "pending_force_bl":
                await query.edit_message_text("\u274c Sesi sudah kadaluarsa. Ulangi Force BL.", reply_markup=back_keyboard())
                return

            if data == "confirm_force_no":
                del user_sessions[uid]
                await query.edit_message_text("\u274c **Force Blacklist dibatalkan.**", parse_mode="Markdown", reply_markup=back_keyboard())
                return

            # YES — execute force blacklist
            new_ips = session["new_ips"]
            parsed = session["parsed"]
            private_ips = session.get("private_ips", [])
            already_bl = session.get("already_bl", [])
            del user_sessions[uid]

            success_count = 0
            fail_count = 0
            for ip in new_ips:
                if force_blacklist(ip, "Manual/Anomaly - Telegram", added_by=uid, added_by_username=uname):
                    success_count += 1
                else:
                    fail_count += 1

            result = f"\u2705 **Force Blacklist Berhasil**\n\n"
            result += f"\U0001F4CB Input: `{parsed['original']}`\n"
            result += f"\U0001F4CC Type: {parsed['type'].upper()}\n"
            result += f"\u2705 Ditambahkan: {success_count} IP\n"
            if fail_count > 0:
                result += f"\u274c Gagal: {fail_count} IP\n"
            if private_ips:
                result += f"\U0001F512 Private (skip): {len(private_ips)}\n"
            if already_bl:
                result += f"\u26a0\ufe0f Sudah ada (skip): {len(already_bl)}\n"

            if success_count <= 15:
                result += f"\n**IPs added:**\n"
                for ip in new_ips[:success_count]:
                    result += f"• `{ip}`\n"
            else:
                result += f"\n**Sample IPs added:**\n"
                for ip in new_ips[:5]:
                    result += f"• `{ip}`\n"
                result += f"_... dan {success_count - 5} lainnya_\n"

            result += f"\n\U0001F4BE _Added to blacklist_"

            push_result = git_push(silent=True)
            if push_result and "Success" in push_result:
                result += "\n\U0001F680 _Pushed to GitHub_"

            await query.edit_message_text(result, parse_mode="Markdown", reply_markup=back_keyboard())

    async def message(update: Update, context: ContextTypes.DEFAULT_TYPE):
        # Log setiap message yang masuk
        log_telegram_message(update)

        if not require_access(update):
            return

        uid = update.effective_user.id
        uname = update.effective_user.username or update.effective_user.first_name
        text = update.message.text.strip()

        if uid not in user_sessions:
            await update.message.reply_text("Gunakan /start", reply_markup=main_keyboard())
            return

        session = user_sessions[uid]
        mode = session.get("mode")

        # Handle add_staff mode (admin only)
        if mode == "add_staff":
            del user_sessions[uid]

            if not require_admin(update):
                await update.message.reply_text("\u274c Admin only", reply_markup=admin_keyboard(uid))
                return

            try:
                # Parse input: "123456789" or "123456789 @username"
                parts = text.split()
                try:
                    new_uid = int(parts[0])
                except ValueError:
                    await update.message.reply_text(
                        "\u274c Format salah. Gunakan: `123456789` atau `123456789 @username`",
                        parse_mode="Markdown",
                        reply_markup=admin_keyboard(uid)
                    )
                    return

                username = parts[1].replace("@", "") if len(parts) > 1 else f"user_{new_uid}"

                if is_admin(new_uid):
                    await update.message.reply_text(
                        "\u26a0\ufe0f User ini sudah admin!",
                        reply_markup=admin_keyboard(uid)
                    )
                    return

                if add_staff(new_uid, username, uid):
                    await update.message.reply_text(
                        f"\u2705 Staff Ditambahkan\n\n"
                        f"User ID: {new_uid}\n"
                        f"Username: {username}",
                        reply_markup=admin_keyboard(uid)
                    )
                else:
                    await update.message.reply_text(
                        f"\u26a0\ufe0f User {new_uid} sudah terdaftar sebagai staff",
                        reply_markup=admin_keyboard(uid)
                    )
            except Exception as e:
                logger.error(f"ADD_STAFF_ERROR | USER={uid} | ERROR={str(e)}")
                await update.message.reply_text(
                    f"\u274c Error: {str(e)}",
                    reply_markup=admin_keyboard(uid)
                )
            return

        # Handle remove_staff mode (admin only)
        elif mode == "remove_staff":
            del user_sessions[uid]

            if not require_admin(update):
                await update.message.reply_text("\u274c Admin only", reply_markup=admin_keyboard(uid))
                return

            try:
                try:
                    target_uid = int(text.strip())
                except ValueError:
                    await update.message.reply_text(
                        "\u274c Format salah. Kirim User ID dalam format angka.",
                        reply_markup=admin_keyboard(uid)
                    )
                    return

                if remove_staff(target_uid):
                    await update.message.reply_text(
                        f"\u2705 Staff Dihapus\n\nUser ID: {target_uid}",
                        reply_markup=admin_keyboard(uid)
                    )
                else:
                    await update.message.reply_text(
                        f"\u274c User {target_uid} tidak ditemukan di daftar staff",
                        reply_markup=admin_keyboard(uid)
                    )
            except Exception as e:
                logger.error(f"REMOVE_STAFF_ERROR | USER={uid} | ERROR={str(e)}")
                await update.message.reply_text(
                    f"\u274c Error: {str(e)}",
                    reply_markup=admin_keyboard(uid)
                )
            return
        
        # Handle add_admin mode (super admin only)
        elif mode == "add_admin":
            del user_sessions[uid]
            if not is_super_admin(uid):
                await update.message.reply_text("\u274c Super Admin only", reply_markup=admin_keyboard(uid))
                return
            try:
                parts = text.split()
                new_uid = int(parts[0])
                username_a = parts[1].replace("@", "") if len(parts) > 1 else f"admin_{new_uid}"
                if is_admin(new_uid):
                    await update.message.reply_text(f"\u26a0\ufe0f User {new_uid} sudah admin!", reply_markup=admin_keyboard(uid))
                elif add_admin(new_uid, username_a, uid):
                    await update.message.reply_text(
                        f"\u2705 **Admin Ditambahkan**\n\nUser ID: {new_uid}\nUsername: @{username_a}",
                        parse_mode="Markdown", reply_markup=admin_keyboard(uid)
                    )
                else:
                    await update.message.reply_text(f"\u274c Gagal menambahkan admin {new_uid}", reply_markup=admin_keyboard(uid))
            except (ValueError, IndexError):
                await update.message.reply_text("\u274c Format salah. Kirim: `123456789` atau `123456789 username`",
                                                parse_mode="Markdown", reply_markup=admin_keyboard(uid))
            return

        # Handle remove_admin mode (super admin only)
        elif mode == "remove_admin":
            del user_sessions[uid]
            if not is_super_admin(uid):
                await update.message.reply_text("\u274c Super Admin only", reply_markup=admin_keyboard(uid))
                return
            try:
                target_uid = int(text.strip())
                if remove_admin(target_uid):
                    await update.message.reply_text(
                        f"\u2705 **Admin Dihapus**\n\nUser ID: {target_uid}",
                        parse_mode="Markdown", reply_markup=admin_keyboard(uid)
                    )
                else:
                    await update.message.reply_text(
                        f"\u274c User {target_uid} tidak ditemukan sebagai admin (atau adalah Super Admin)",
                        reply_markup=admin_keyboard(uid)
                    )
            except ValueError:
                await update.message.reply_text("\u274c Format salah. Kirim User ID angka.", reply_markup=admin_keyboard(uid))
            return

        # Handle dump_custom mode
        elif mode == "dump_custom":
            del user_sessions[uid]
            
            try:
                target_date = datetime.strptime(text, "%Y-%m-%d")
                ips = get_ips_by_single_date(target_date)
                date_str = target_date.strftime('%Y%m%d')
                title = f"IP Blacklist pada {text}"
                await send_ip_file(update, ips, title, date_str)
            except ValueError:
                await update.message.reply_text(
                    "\u274c Format tanggal salah!\n\nGunakan format: `YYYY-MM-DD`\nContoh: `2025-01-15`",
                    parse_mode="Markdown",
                    reply_markup=back_keyboard()
                )
            return
        
        # Handle dump_range_start mode
        elif mode == "dump_range_start":
            try:
                start_date = datetime.strptime(text, "%Y-%m-%d")
                user_sessions[uid] = {"mode": "dump_range_end", "start_date": start_date}
                await update.message.reply_text(
                    f"\U0001F4C5 **Range Tanggal**\n\n"
                    f"Tanggal awal: `{text}`\n\n"
                    "Sekarang kirim **tanggal akhir**:\n"
                    "`YYYY-MM-DD`\n\n"
                    "Contoh: `2025-01-07`",
                    parse_mode="Markdown",
                    reply_markup=cancel_keyboard()
                )
            except ValueError:
                await update.message.reply_text(
                    "\u274c Format tanggal salah!\n\nGunakan format: `YYYY-MM-DD`\nContoh: `2025-01-01`",
                    parse_mode="Markdown",
                    reply_markup=cancel_keyboard()
                )
            return
        
        # Handle dump_range_end mode
        elif mode == "dump_range_end":
            start_date = session.get("start_date")
            del user_sessions[uid]
            
            try:
                end_date = datetime.strptime(text, "%Y-%m-%d")
                
                # Validate date range
                if end_date < start_date:
                    await update.message.reply_text(
                        "\u274c Tanggal akhir tidak boleh lebih kecil dari tanggal awal!",
                        reply_markup=back_keyboard()
                    )
                    return
                
                ips = get_ips_by_date_range(start_date, end_date)
                date_str = f"{start_date.strftime('%Y%m%d')}_{end_date.strftime('%Y%m%d')}"
                title = f"IP Blacklist ({start_date.strftime('%Y-%m-%d')} s/d {end_date.strftime('%Y-%m-%d')})"
                await send_ip_file(update, ips, title, date_str)
            except ValueError:
                await update.message.reply_text(
                    "\u274c Format tanggal salah!\n\nGunakan format: `YYYY-MM-DD`\nContoh: `2025-01-07`",
                    parse_mode="Markdown",
                    reply_markup=back_keyboard()
                )
            return

        elif mode == "single":
            del user_sessions[uid]

            if not validate_ip(text):
                await update.message.reply_text("\u274c Format IP tidak valid", reply_markup=back_keyboard())
                return

            if is_private_ip(text):
                await update.message.reply_text("\u26a0\ufe0f IP private", reply_markup=back_keyboard())
                return

            if text in load_blacklist():
                base_msg = f"\u26a0\ufe0f `{text}` sudah di blacklist"
                if is_admin(uid):
                    base_msg += get_blacklist_info_text(text)
                await update.message.reply_text(base_msg, parse_mode="Markdown", reply_markup=back_keyboard())
                return

            msg = await update.message.reply_text(f"\u23f3 Checking `{text}`...", parse_mode="Markdown")
            vt, abuse, is_mal = check_ip_reputation(text)
            result, _ = format_result(text, vt, abuse)

            if is_mal:
                isp = abuse.get("isp", "Unknown")[:50] if "error" not in abuse else "Unknown"
                confirm_msg = (
                    result +
                    f"\n\u26a0\ufe0f ISP: {isp}\n\n"
                    "\u203C\uFE0F LU UDAH CHEK BELUM INI IP ? JANGAN SALAH BLOKIR LAGI!!!"
                )
                await msg.edit_text(confirm_msg, parse_mode="Markdown",
                                    reply_markup=confirm_blacklist_keyboard(text))
            else:
                await msg.edit_text(result, parse_mode="Markdown", reply_markup=back_keyboard())

        elif mode == "bulk":
            if text.upper() == "DONE":
                ips = list(dict.fromkeys(session.get("ips", [])))
                del user_sessions[uid]

                if not ips:
                    await update.message.reply_text("\u274c No IPs found", reply_markup=back_keyboard())
                    return

                bl = load_blacklist()
                new_ips = [ip for ip in ips if ip not in bl]
                skipped = len(ips) - len(new_ips)

                if not new_ips:
                    await update.message.reply_text(f"\u26a0\ufe0f All {len(ips)} IPs already blacklisted", reply_markup=back_keyboard())
                    return

                msg = await update.message.reply_text(
                    f"\u23f3 Checking {len(new_ips)} IPs (parallel mode)...\n_Skipped: {skipped}_",
                    parse_mode="Markdown"
                )

                # Use parallel checking for speed (5 IPs at a time)
                try:
                    raw_results = await check_multiple_ips_async(new_ips, batch_size=5)
                    results = []
                    for ip, vt, abuse, is_mal in raw_results:
                        results.append({"ip": ip, "vt": vt, "abuse": abuse, "mal": is_mal})
                        if is_mal:
                            add_to_blacklist(ip, "Auto-Detected SIEM - Telegram", added_by=uid, added_by_username=uname)
                except Exception as e:
                    logger.error(f"PARALLEL_CHECK_ERROR | {str(e)}")
                    await safe_edit_message(msg, f"\u274c Error checking IPs: {str(e)}", reply_markup=back_keyboard())
                    return

                # Summary
                mal_list = [r for r in results if r['mal']]
                clean_list = [r for r in results if not r['mal']]

                summary = f"**HASIL CHECK**\n{'='*35}\n\n"
                summary += f"Total: {len(results)} IP\n"
                summary += f"\u2705 Clean: {len(clean_list)}\n"
                summary += f"\u274c Malicious: {len(mal_list)}\n\n"

                if mal_list:
                    summary += "**MALICIOUS:**\n"
                    for r in mal_list[:30]:  # Limit to 30 to avoid message too long
                        summary += f"\u274c `{r['ip']}`\n"
                    if len(mal_list) > 30:
                        summary += f"\n_...dan {len(mal_list)-30} lainnya_\n"
                    summary += f"\n\U0001F4BE _{len(mal_list)} added to blacklist_"

                    push_result = git_push(silent=True)
                    if push_result and "Success" in push_result:
                        summary += "\n\U0001F680 _Pushed to GitHub_"

                await safe_edit_message(msg, summary, reply_markup=back_keyboard())

            else:
                ip_type = session.get("type", "all")
                new_ips = extract_ips_from_text(text, ip_type)
                if new_ips:
                    session["ips"].extend(new_ips)
                    total = len(session["ips"])

                    # Edit existing message or create new one
                    if "msg_id" in session:
                        try:
                            await context.bot.edit_message_text(
                                chat_id=update.effective_chat.id,
                                message_id=session["msg_id"],
                                text=f"✅ Total: **{total} IP** terkumpul\n\nKetik `DONE` jika selesai",
                                parse_mode="Markdown"
                            )
                        except:
                            pass  # Ignore if edit fails
                    else:
                        msg = await update.message.reply_text(
                            f"✅ Total: **{total} IP** terkumpul\n\nKetik `DONE` jika selesai",
                            parse_mode="Markdown"
                        )
                        session["msg_id"] = msg.message_id
                else:
                    # Only notify if no IP found and no previous IPs collected
                    if not session.get("ips"):
                        await update.message.reply_text("⚠️ No valid IP found\nKetik `DONE`")

        elif mode == "search":
            del user_sessions[uid]
            results = search_blacklist(text)
            if results:
                msg = f"**Found {len(results)} IP:**\n\n"
                for ip in results[:20]:
                    msg += f"• `{ip}`\n"
            else:
                msg = f"No match for `{text}`"
            await update.message.reply_text(msg, parse_mode="Markdown", reply_markup=back_keyboard())

        elif mode == "force_bl":
            del user_sessions[uid]

            # Parse input (supports single IP, CIDR, range)
            parsed = parse_ip_input(text)

            if parsed["type"] == "error":
                await update.message.reply_text(
                    f"❌ {parsed['error']}\n\n"
                    f"**Format yang didukung:**\n"
                    f"• Single IP: `1.2.3.4`\n"
                    f"• CIDR: `10.0.0.0/24`\n"
                    f"• Range: `10.0.0.1-10.0.0.5` atau `10.0.0.1-5`",
                    parse_mode="Markdown",
                    reply_markup=back_keyboard()
                )
                return

            ip_list = parsed["ips"]
            existing_bl = load_blacklist()

            # Filter out private IPs and already blacklisted
            private_ips = [ip for ip in ip_list if is_private_ip(ip)]
            already_bl = [ip for ip in ip_list if ip in existing_bl and not is_private_ip(ip)]
            new_ips = [ip for ip in ip_list if not is_private_ip(ip) and ip not in existing_bl]

            if not new_ips:
                msg = "⚠️ **Tidak ada IP baru untuk di-blacklist**\n\n"
                if private_ips:
                    msg += f"• {len(private_ips)} IP private (skip)\n"
                if already_bl:
                    msg += f"• {len(already_bl)} IP sudah ada di blacklist\n"
                await update.message.reply_text(
                    msg,
                    parse_mode="Markdown",
                    reply_markup=back_keyboard()
                )
                return

            # Store pending in session, show confirmation
            user_sessions[uid] = {
                "mode": "pending_force_bl",
                "new_ips": new_ips,
                "parsed": parsed,
                "private_ips": private_ips,
                "already_bl": already_bl,
            }

            preview = f"\u26a0\ufe0f **Force Blacklist Konfirmasi**\n\n"
            preview += f"\U0001F4CB Input: `{parsed['original']}`\n"
            preview += f"\U0001F4CC Type: {parsed['type'].upper()}\n"
            preview += f"\U0001F534 Akan diblacklist: **{len(new_ips)} IP**\n"
            if private_ips:
                preview += f"\U0001F512 Private (skip): {len(private_ips)}\n"
            if already_bl:
                preview += f"\u26a0\ufe0f Sudah ada (skip): {len(already_bl)}\n"
            if len(new_ips) <= 15:
                preview += f"\n**IPs yang akan diblacklist:**\n"
                for ip in new_ips:
                    preview += f"• `{ip}`\n"
            else:
                preview += f"\n**Sample (5 dari {len(new_ips)}):**\n"
                for ip in new_ips[:5]:
                    preview += f"• `{ip}`\n"
                preview += f"_...dan {len(new_ips)-5} lainnya_\n"
            preview += f"\n\u203C\uFE0F LU UDAH CHEK BELUM INI IP ? JANGAN SALAH BLOKIR LAGI!!!"

            await update.message.reply_text(
                preview,
                parse_mode="Markdown",
                reply_markup=confirm_force_bl_keyboard()
            )

        elif mode == "unblacklist":
            del user_sessions[uid]

            if not validate_ip(text):
                await update.message.reply_text(
                    "❌ Format IP tidak valid",
                    reply_markup=back_keyboard()
                )
                return

            if text not in load_blacklist():
                await update.message.reply_text(
                    f"⚠️ `{text}` tidak ditemukan di blacklist",
                    parse_mode="Markdown",
                    reply_markup=back_keyboard()
                )
                return

            if remove_from_blacklist(text, removed_by=uid, removed_by_username=uname):
                result = f"✅ **Unblacklist Berhasil**\n\n"
                result += f"IP: `{text}`\n"
                result += "IP telah dihapus dari blacklist.\n\n"

                push_result = git_push(silent=True)
                if push_result and "Success" in push_result:
                    result += "🚀 _Pushed to GitHub_"

                await update.message.reply_text(
                    result,
                    parse_mode="Markdown",
                    reply_markup=back_keyboard()
                )
            else:
                await update.message.reply_text(
                    "❌ Gagal menghapus dari blacklist",
                    reply_markup=back_keyboard()
                )

        # Domain message handlers
        elif mode == "domain_add":
            del user_sessions[uid]

            # Extract domains from text
            domains = extract_domains_from_text(text)

            # Also allow simple comma-separated input
            if not domains:
                for part in text.replace(',', '\n').split('\n'):
                    part = part.strip().lower()
                    if part and validate_domain(part):
                        domains.append(part)

            if not domains:
                await update.message.reply_text(
                    "❌ Tidak ada domain valid ditemukan.\n\n"
                    "Format contoh:\n"
                    "• malware.example.com\n"
                    "• phishing-site.net",
                    reply_markup=domain_keyboard()
                )
                return

            # Remove duplicates
            domains = list(set(domains))

            added = 0
            skipped = 0
            result = "\U0001F310 **Add Domain Result**\n\n"

            for domain in domains:
                if force_domain_blacklist(domain, "Manual - Telegram"):
                    added += 1
                    result += f"✅ `{domain}`\n"
                else:
                    skipped += 1
                    result += f"⚠️ `{domain}` (sudah ada)\n"

            result += f"\n**Total:** {added} added, {skipped} skipped"

            push_result = git_push_domain(silent=True)
            if push_result and "Success" in push_result:
                result += "\n🚀 _Pushed to GitHub_"

            await update.message.reply_text(
                result,
                parse_mode="Markdown",
                reply_markup=domain_keyboard()
            )

        elif mode == "domain_remove":
            del user_sessions[uid]

            domain = text.strip().lower()

            if not validate_domain(domain):
                await update.message.reply_text(
                    "❌ Format domain tidak valid",
                    reply_markup=domain_keyboard()
                )
                return

            if domain not in load_domain_blacklist():
                await update.message.reply_text(
                    f"⚠️ `{domain}` tidak ditemukan di blacklist",
                    parse_mode="Markdown",
                    reply_markup=domain_keyboard()
                )
                return

            if remove_from_domain_blacklist(domain):
                result = f"✅ **Domain Removed**\n\n"
                result += f"Domain: `{domain}`\n"
                result += "Domain telah dihapus dari blacklist.\n\n"

                push_result = git_push_domain(silent=True)
                if push_result and "Success" in push_result:
                    result += "🚀 _Pushed to GitHub_"

                await update.message.reply_text(
                    result,
                    parse_mode="Markdown",
                    reply_markup=domain_keyboard()
                )
            else:
                await update.message.reply_text(
                    "❌ Gagal menghapus domain dari blacklist",
                    reply_markup=domain_keyboard()
                )

        elif mode == "domain_search":
            del user_sessions[uid]

            query = text.strip().lower()
            results = search_domain_blacklist(query)

            if results:
                msg = f"\U0001F50E **Found {len(results)} domain:**\n\n"
                for domain in sorted(results)[:30]:
                    msg += f"• `{domain}`\n"
                if len(results) > 30:
                    msg += f"\n_...dan {len(results)-30} lainnya_"
            else:
                msg = f"\U0001F50E No domain match for `{query}`"

            await update.message.reply_text(msg, parse_mode="Markdown", reply_markup=domain_keyboard())

        elif mode == "tracking_search":
            del user_sessions[uid]
            if not is_admin(uid):
                await update.message.reply_text("\u274c Admin only", reply_markup=back_keyboard())
                return
            ip_query = text.strip()
            acts = load_activity_db().get("activities", [])
            filtered = [a for a in acts if a.get("ip") == ip_query]
            if not filtered:
                await update.message.reply_text(
                    f"\U0001F50E Tidak ada aktivitas untuk IP `{ip_query}`",
                    parse_mode="Markdown",
                    reply_markup=back_keyboard()
                )
                return
            text_out = f"\U0001F50E Aktivitas IP: {ip_query}\n\n"
            emojis = {"blacklist": "\U0001F534", "force_blacklist": "\u26A0\uFE0F", "unblacklist": "\U0001F7E2"}
            for act in reversed(filtered[-20:]):
                icon = emojis.get(act.get("action", ""), "\u2B55")
                text_out += (
                    f"{icon} [{act.get('timestamp','?')[:16]}] {act.get('action','?').upper()}\n"
                    f"   \U0001F464 @{act.get('username','?')} (ID: {act.get('user_id','?')})\n"
                    f"   \U0001F4CB {act.get('reason','?')}\n\n"
                )
            await update.message.reply_text(text_out, reply_markup=back_keyboard())

    async def handle_document(update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle uploaded TXT file for bulk IP check"""
        if not require_access(update):
            return

        uid = update.effective_user.id
        document = update.message.document

        # Check if user is in file_upload mode
        if uid not in user_sessions or user_sessions[uid].get("mode") != "file_upload":
            await update.message.reply_text(
                "\u26a0\ufe0f Gunakan menu **Upload File TXT** terlebih dahulu.",
                parse_mode="Markdown",
                reply_markup=main_keyboard()
            )
            return

        # Validate file type
        if not document.file_name.lower().endswith('.txt'):
            await update.message.reply_text(
                "\u274c File harus berformat `.txt`",
                parse_mode="Markdown",
                reply_markup=cancel_keyboard()
            )
            return

        # Check file size (max 1MB)
        if document.file_size > 1024 * 1024:
            await update.message.reply_text(
                "\u274c File terlalu besar (max 1MB)",
                reply_markup=cancel_keyboard()
            )
            return

        session = user_sessions[uid]
        ip_type = session.get("type", "all")
        del user_sessions[uid]

        try:
            # Download file
            file = await context.bot.get_file(document.file_id)
            file_bytes = await file.download_as_bytearray()
            file_content = file_bytes.decode('utf-8')

            # Extract IPs from file content
            ips = extract_ips_from_text(file_content, ip_type)

            if not ips:
                await update.message.reply_text(
                    "\u274c Tidak ada IP valid ditemukan dalam file.",
                    reply_markup=back_keyboard()
                )
                return

            # Check against existing blacklist
            bl = load_blacklist()
            new_ips = [ip for ip in ips if ip not in bl]
            skipped = len(ips) - len(new_ips)

            if not new_ips:
                await update.message.reply_text(
                    f"\u26a0\ufe0f Semua {len(ips)} IP sudah ada di blacklist.",
                    reply_markup=back_keyboard()
                )
                return

            labels = {"source": "Source", "dest": "Destination", "all": "All"}
            msg = await update.message.reply_text(
                f"\U0001F4C4 File: `{document.file_name}`\n"
                f"\U0001F50D Tipe: **{labels[ip_type]} IP**\n"
                f"\U0001F4CA Total: **{len(new_ips)} IP** akan di-check\n"
                f"\u23ed Skipped: {skipped} (sudah blacklist)\n\n"
                f"\u23f3 Memproses (parallel mode)...",
                parse_mode="Markdown"
            )

            # Use parallel checking for speed (5 IPs at a time)
            file_uid = update.effective_user.id
            file_uname = update.effective_user.username or update.effective_user.first_name
            try:
                raw_results = await check_multiple_ips_async(new_ips, batch_size=5)
                results = []
                for ip, vt, abuse, is_mal in raw_results:
                    results.append({"ip": ip, "vt": vt, "abuse": abuse, "mal": is_mal})
                    if is_mal:
                        add_to_blacklist(ip, "Auto-Detected File Upload - Telegram",
                                         added_by=file_uid, added_by_username=file_uname)
            except Exception as e:
                logger.error(f"FILE_PARALLEL_CHECK_ERROR | {str(e)}")
                await safe_edit_message(msg, f"\u274c Error checking IPs: {str(e)}", reply_markup=back_keyboard())
                return

            # Summary
            mal_list = [r for r in results if r['mal']]
            clean_list = [r for r in results if not r['mal']]

            summary = f"**\U0001F4C4 HASIL CHECK FILE**\n{'='*35}\n\n"
            summary += f"File: `{document.file_name}`\n"
            summary += f"Tipe: {labels[ip_type]} IP\n\n"
            summary += f"Total: {len(results)} IP\n"
            summary += f"\u2705 Clean: {len(clean_list)}\n"
            summary += f"\u274c Malicious: {len(mal_list)}\n\n"

            if mal_list:
                summary += "**MALICIOUS:**\n"
                for r in mal_list[:30]:  # Limit to 30 to avoid message too long
                    summary += f"\u274c `{r['ip']}`\n"
                if len(mal_list) > 30:
                    summary += f"\n_...dan {len(mal_list)-30} lainnya_\n"
                summary += f"\n\U0001F4BE _{len(mal_list)} added to blacklist_"

                push_result = git_push(silent=True)
                if push_result and "Success" in push_result:
                    summary += "\n\U0001F680 _Pushed to GitHub_"

            await safe_edit_message(msg, summary, reply_markup=back_keyboard())

        except UnicodeDecodeError:
            await update.message.reply_text(
                "\u274c File tidak dapat dibaca. Pastikan file berformat UTF-8.",
                reply_markup=back_keyboard()
            )
        except Exception as e:
            logger.error(f"FILE_UPLOAD_ERROR | {str(e)}")
            await update.message.reply_text(
                f"\u274c Terjadi kesalahan saat memproses file: {str(e)}",
                reply_markup=back_keyboard()
            )

    async def quick_check(update: Update, context: ContextTypes.DEFAULT_TYPE):
        log_telegram_message(update)

        if not require_access(update):
            return

        if not context.args:
            await update.message.reply_text("Usage: `/check 8.8.8.8`", parse_mode="Markdown")
            return

        ip = context.args[0]
        if not validate_ip(ip):
            await update.message.reply_text("❌ Invalid IP")
            return

        if is_private_ip(ip):
            await update.message.reply_text("⚠️ Private IP")
            return

        if ip in load_blacklist():
            base_msg = f"\u26a0\ufe0f `{ip}` sudah di blacklist"
            chk_uid = update.effective_user.id
            if is_admin(chk_uid):
                base_msg += get_blacklist_info_text(ip)
            await update.message.reply_text(base_msg, parse_mode="Markdown", reply_markup=back_keyboard())
            return

        msg = await update.message.reply_text(f"⏳ Checking `{ip}`...", parse_mode="Markdown")
        vt, abuse, is_mal = check_ip_reputation(ip)
        result, _ = format_result(ip, vt, abuse)

        if is_mal:
            isp = abuse.get("isp", "Unknown")[:50] if "error" not in abuse else "Unknown"
            confirm_msg = (
                result +
                f"\n\u26a0\ufe0f ISP: {isp}\n\n"
                "\u203C\uFE0F LU UDAH CHEK BELUM INI IP ? JANGAN SALAH BLOKIR LAGI!!!"
            )
            await msg.edit_text(confirm_msg, parse_mode="Markdown",
                                reply_markup=confirm_blacklist_keyboard(ip))
        else:
            await msg.edit_text(result, parse_mode="Markdown", reply_markup=back_keyboard())

    async def debug_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
        log_telegram_message(update)
        
        await update.message.reply_text(
            f"Chat: `{update.effective_chat.id}`\nUser: `{update.effective_user.id}`",
            parse_mode="Markdown"
        )

    # Build and run
    print("\n" + "="*60)
    print("🚀 Starting Telegram Bot (SOC IP Reputation Checker)")
    print("="*60)
    print()
    
    logger.info("TELEGRAM_BOT_STARTING")

    # Load extra admins from DB into ADMIN_IDS at startup
    for uid_str in get_all_admins():
        try:
            ADMIN_IDS.add(int(uid_str))
        except ValueError:
            pass

    app = ApplicationBuilder().token(BOT_TOKEN).build()

    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("menu", start))
    app.add_handler(CommandHandler("admin", admin_cmd))
    app.add_handler(CommandHandler("check", quick_check))
    app.add_handler(CommandHandler("debug", debug_cmd))
    app.add_handler(CallbackQueryHandler(button))
    app.add_handler(MessageHandler(filters.Document.ALL, handle_document))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, message))

    # Test bot connection
    try:
        bot_info = asyncio.get_event_loop().run_until_complete(app.bot.get_me())
        print("🔍 Testing bot connection...")
        print(f"✅ Bot connected successfully!")
        print(f"   Bot Name: {bot_info.first_name}")
        print(f"   Username: @{bot_info.username}")
        print()
        print("📋 Commands:")
        print("   /start  - Tampilkan menu utama")
        print("   /check  - Quick IP check")
        print("   /admin  - Admin panel (admins only)")
        print()
        print("💡 Setiap pesan akan menampilkan info di console")
        print()
        print("="*60)
        print("✅ Bot is running... (Press Ctrl+C to stop)")
        print()
    except Exception as e:
        print(f"❌ Failed to connect: {e}")
        return

    logger.info("TELEGRAM_BOT_RUNNING")
    print("\n[BOT] SOC IP Reputation Bot is running...")
    print("[BOT] Press Ctrl+C to stop\n")

    app.run_polling(drop_pending_updates=True)


def main():
    parser = argparse.ArgumentParser(
        description="SOC IP Reputation Checker - BIOFARMA",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 soc_bot.py              # Run CLI mode
  python3 soc_bot.py --telegram   # Run Telegram Bot
  python3 soc_bot.py --bot        # Run Telegram Bot (alias)
"""
    )
    parser.add_argument('--telegram', '--bot', '-t', '-b',
                        action='store_true',
                        help='Run in Telegram Bot mode')
    args = parser.parse_args()

    if args.telegram:
        run_telegram()
    else:
        run_cli()


if __name__ == "__main__":
    main()
