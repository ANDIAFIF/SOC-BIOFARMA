#!/usr/bin/env python3
"""
IP Reputation Checker with VirusTotal & AbuseIPDB Integration
Auto-push malicious IPs to GitHub blacklist
SOC Automation Tool - BIOFARMA
"""

import os
import sys
import re
import subprocess
from datetime import datetime

try:
    from dotenv import load_dotenv
except ImportError:
    print("Installing python-dotenv...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "python-dotenv", "-q"])
    from dotenv import load_dotenv

try:
    import requests
except ImportError:
    print("Installing requests...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "requests", "-q"])
    import requests

# Load environment variables
load_dotenv()

# Configuration
VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")

# Paths - blacklist is in parent directory (repo root)
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
GITHUB_REPO_PATH = os.path.dirname(SCRIPT_DIR)  # Parent of automation folder
BLACKLIST_FILE = os.path.join(GITHUB_REPO_PATH, "List-IP-Blacklist.txt")

# GitHub Configuration
GITHUB_REMOTE = os.getenv("GITHUB_REMOTE", "origin")
GITHUB_BRANCH = os.getenv("GITHUB_BRANCH", "main")

# API Endpoints
VT_URL = "https://www.virustotal.com/api/v3/ip_addresses/{}"
ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"


class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    RESET = '\033[0m'


def clear_screen():
    """Clear terminal screen"""
    os.system("clear" if os.name != "nt" else "cls")


def print_banner():
    """Print application banner"""
    banner = f"""
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
{Colors.RESET}"""
    print(banner)


def print_main_menu():
    """Print main menu with options"""
    print(f"""
{Colors.BOLD}{Colors.WHITE}╔═══════════════════════════════════════╗
║           MAIN MENU                   ║
╠═══════════════════════════════════════╣{Colors.RESET}
{Colors.GREEN}║  [1] Check Source IP                  ║{Colors.RESET}
{Colors.BLUE}║  [2] Check Destination IP             ║{Colors.RESET}
{Colors.YELLOW}║  [3] Check Single IP                  ║{Colors.RESET}
{Colors.MAGENTA}║  [4] View Blacklist                   ║{Colors.RESET}
{Colors.CYAN}║  [5] Push Blacklist to GitHub         ║{Colors.RESET}
{Colors.WHITE}║  [6] Pull from GitHub                 ║{Colors.RESET}
{Colors.WHITE}║  [7] Help & Documentation             ║{Colors.RESET}
{Colors.RED}║  [0] Exit                             ║{Colors.RESET}
{Colors.BOLD}{Colors.WHITE}╚═══════════════════════════════════════╝{Colors.RESET}
""")


def print_help():
    """Print detailed help documentation"""
    help_text = f"""
{Colors.CYAN}{Colors.BOLD}
╔═══════════════════════════════════════════════════════════════════════════╗
║                          HELP & DOCUMENTATION                             ║
╚═══════════════════════════════════════════════════════════════════════════╝{Colors.RESET}

{Colors.YELLOW}{Colors.BOLD}DESKRIPSI:{Colors.RESET}
    Tool ini digunakan untuk mengecek reputasi IP address menggunakan:
    • VirusTotal - Scanning multi-engine untuk deteksi malicious IP
    • AbuseIPDB  - Database laporan abuse dari komunitas global

    IP yang terdeteksi malicious akan otomatis ditambahkan ke blacklist
    dan di-push ke GitHub repository untuk automation firewall/WAF.

{Colors.YELLOW}{Colors.BOLD}MENU OPTIONS:{Colors.RESET}

    {Colors.GREEN}[1] Check Source IP{Colors.RESET}
        Paste data dari SIEM (QRadar/Splunk) yang memiliki Source IP.
        Tool akan otomatis mengekstrak semua Source IP dari kolom pertama.

    {Colors.BLUE}[2] Check Destination IP{Colors.RESET}
        Paste data dari SIEM untuk mengekstrak Destination IP.
        Tool akan mencari IP di kolom Destination IP.

    {Colors.YELLOW}[3] Check Single IP{Colors.RESET}
        Input satu IP address secara manual untuk dicek.

    {Colors.MAGENTA}[4] View Blacklist{Colors.RESET}
        Menampilkan daftar IP yang sudah ada di blacklist.

    {Colors.CYAN}[5] Push Blacklist to GitHub{Colors.RESET}
        Manual push file blacklist.txt ke GitHub repository.

    {Colors.WHITE}[6] Pull from GitHub{Colors.RESET}
        Sync/pull perubahan terbaru dari GitHub repository.

{Colors.YELLOW}{Colors.BOLD}FORMAT DATA SIEM:{Colors.RESET}
    Anda bisa langsung copy-paste data dari QRadar/Splunk dalam format:

    Source IP    Event Name    Log Source    Event Count    ...
    103.224.76.8    SSL exit error    FortiGate...
    45.76.141.6     Brute Force       Firewall...

    Tool akan otomatis mendeteksi dan mengekstrak IP address.

{Colors.YELLOW}{Colors.BOLD}THRESHOLD MALICIOUS:{Colors.RESET}
    IP dianggap MALICIOUS jika:
    • VirusTotal: Ada 1+ detection malicious/suspicious
    • AbuseIPDB: Confidence Score > 0 ATAU Total Reports > 0

{Colors.YELLOW}{Colors.BOLD}AUTO-BLACKLIST:{Colors.RESET}
    Ketika IP terdeteksi malicious:
    1. IP otomatis ditambahkan ke blacklist.txt
    2. File di-commit ke git
    3. Di-push ke GitHub repository

{Colors.YELLOW}{Colors.BOLD}SETUP API KEYS:{Colors.RESET}
    Buat file .env dengan isi:

    VIRUSTOTAL_API_KEY=your_key_here
    ABUSEIPDB_API_KEY=your_key_here

    Dapatkan API Key gratis di:
    • VirusTotal: https://www.virustotal.com/gui/join-us
    • AbuseIPDB:  https://www.abuseipdb.com/register

{Colors.GREEN}Press Enter to go back to menu...{Colors.RESET}"""
    print(help_text)
    input()


def validate_ip(ip):
    """Validate IP address format"""
    pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if re.match(pattern, ip):
        parts = ip.split('.')
        return all(0 <= int(part) <= 255 for part in parts)
    return False


def is_private_ip(ip):
    """Check if IP is private/internal"""
    parts = list(map(int, ip.split('.')))

    # 10.0.0.0/8
    if parts[0] == 10:
        return True
    # 172.16.0.0/12
    if parts[0] == 172 and 16 <= parts[1] <= 31:
        return True
    # 192.168.0.0/16
    if parts[0] == 192 and parts[1] == 168:
        return True
    # 127.0.0.0/8 (localhost)
    if parts[0] == 127:
        return True

    return False


def extract_ips_from_text(text, ip_type="source"):
    """Extract IPs from SIEM data"""
    # Pattern to find all IPs in text
    ip_pattern = r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b'

    lines = text.strip().split('\n')
    found_ips = []

    for line in lines:
        if not line.strip():
            continue

        # Find all IPs in the line
        ips_in_line = re.findall(ip_pattern, line)

        if not ips_in_line:
            continue

        if ip_type == "source":
            # Source IP is usually the first IP in the line
            ip = ips_in_line[0]
        else:
            # Destination IP - look for IP after "192.168" pattern or take second IP
            # Skip internal IPs for destination
            for potential_ip in ips_in_line:
                if not is_private_ip(potential_ip):
                    ip = potential_ip
                    break
            else:
                # If all are private, take the last one
                ip = ips_in_line[-1] if len(ips_in_line) > 1 else ips_in_line[0]

        # Validate and add
        if validate_ip(ip) and not is_private_ip(ip):
            if ip not in found_ips:
                found_ips.append(ip)

    return found_ips


def get_multiline_input():
    """Get multi-line input from user"""
    print(f"\n{Colors.YELLOW}Paste data SIEM Anda di bawah ini.")
    print(f"Setelah selesai paste, tekan Enter 2x atau ketik 'DONE' lalu Enter:{Colors.RESET}\n")

    lines = []
    empty_count = 0

    while True:
        try:
            line = input()

            if line.strip().upper() == 'DONE':
                break

            if not line.strip():
                empty_count += 1
                if empty_count >= 2:
                    break
            else:
                empty_count = 0
                lines.append(line)

        except EOFError:
            break

    return '\n'.join(lines)


def check_virustotal(ip):
    """Check IP reputation on VirusTotal"""
    if not VT_API_KEY:
        return {"error": "VirusTotal API key not configured"}

    headers = {"x-apikey": VT_API_KEY}

    try:
        response = requests.get(VT_URL.format(ip), headers=headers, timeout=30)

        if response.status_code == 200:
            data = response.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})

            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            harmless = stats.get("harmless", 0)
            undetected = stats.get("undetected", 0)

            country = data.get("data", {}).get("attributes", {}).get("country", "Unknown")
            asn = data.get("data", {}).get("attributes", {}).get("asn", "Unknown")
            as_owner = data.get("data", {}).get("attributes", {}).get("as_owner", "Unknown")

            return {
                "malicious": malicious,
                "suspicious": suspicious,
                "harmless": harmless,
                "undetected": undetected,
                "country": country,
                "asn": asn,
                "as_owner": as_owner,
                "is_bad": malicious > 0 or suspicious > 0
            }
        elif response.status_code == 401:
            return {"error": "Invalid VirusTotal API key"}
        elif response.status_code == 429:
            return {"error": "VT Rate limit exceeded. Wait a moment."}
        else:
            return {"error": f"VT API error: {response.status_code}"}

    except requests.exceptions.Timeout:
        return {"error": "VirusTotal request timeout"}
    except Exception as e:
        return {"error": f"VT error: {str(e)}"}


def check_abuseipdb(ip):
    """Check IP reputation on AbuseIPDB"""
    if not ABUSEIPDB_API_KEY:
        return {"error": "AbuseIPDB API key not configured"}

    headers = {
        "Key": ABUSEIPDB_API_KEY,
        "Accept": "application/json"
    }

    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90,
        "verbose": True
    }

    try:
        response = requests.get(ABUSEIPDB_URL, headers=headers, params=params, timeout=30)

        if response.status_code == 200:
            data = response.json().get("data", {})

            abuse_score = data.get("abuseConfidenceScore", 0)
            total_reports = data.get("totalReports", 0)
            country = data.get("countryCode", "Unknown")
            isp = data.get("isp", "Unknown")
            domain = data.get("domain", "Unknown")
            is_tor = data.get("isTor", False)

            return {
                "abuse_score": abuse_score,
                "total_reports": total_reports,
                "country": country,
                "isp": isp,
                "domain": domain,
                "is_tor": is_tor,
                "is_bad": abuse_score > 0 or total_reports > 0
            }
        elif response.status_code == 401:
            return {"error": "Invalid AbuseIPDB API key"}
        elif response.status_code == 429:
            return {"error": "AbuseIPDB Rate limit exceeded"}
        else:
            return {"error": f"AbuseIPDB API error: {response.status_code}"}

    except requests.exceptions.Timeout:
        return {"error": "AbuseIPDB request timeout"}
    except Exception as e:
        return {"error": f"AbuseIPDB error: {str(e)}"}


def add_to_blacklist(ip):
    """Add IP to blacklist file"""
    existing_ips = load_blacklist()
    if ip in existing_ips:
        return False

    with open(BLACKLIST_FILE, "a") as f:
        f.write(f"{ip}\n")

    return True


def load_blacklist():
    """Load existing blacklist IPs"""
    if not os.path.exists(BLACKLIST_FILE):
        return set()

    with open(BLACKLIST_FILE, "r") as f:
        ips = set()
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                ip = line.split()[0] if line else ""
                if ip and validate_ip(ip):
                    ips.add(ip)
        return ips


def show_blacklist():
    """Display current blacklist"""
    if not os.path.exists(BLACKLIST_FILE):
        print(f"{Colors.YELLOW}[INFO] Blacklist file is empty{Colors.RESET}")
        return

    with open(BLACKLIST_FILE, "r") as f:
        content = f.read().strip()

    if not content:
        print(f"{Colors.YELLOW}[INFO] Blacklist is empty{Colors.RESET}")
        return

    print(f"\n{Colors.CYAN}{Colors.BOLD}╔═══════════════════════════════════════╗")
    print(f"║         CURRENT BLACKLIST             ║")
    print(f"╚═══════════════════════════════════════╝{Colors.RESET}")

    lines = [l for l in content.split("\n") if l.strip() and not l.startswith("#")]
    for i, line in enumerate(lines, 1):
        print(f"  {Colors.RED}{i:3}.{Colors.RESET} {line}")

    print(f"\n{Colors.CYAN}Total: {len(lines)} IPs{Colors.RESET}")
    input(f"\n{Colors.GREEN}Press Enter to continue...{Colors.RESET}")


def git_push_blacklist():
    """Push blacklist to GitHub"""
    try:
        os.chdir(GITHUB_REPO_PATH)

        result = subprocess.run(["git", "status"], capture_output=True, text=True)
        if result.returncode != 0:
            print(f"{Colors.RED}[ERROR] Not a git repository{Colors.RESET}")
            return False

        # Add List-IP-Blacklist.txt
        subprocess.run(["git", "add", "List-IP-Blacklist.txt"], capture_output=True)

        result = subprocess.run(["git", "status", "--porcelain", "List-IP-Blacklist.txt"],
                              capture_output=True, text=True)

        if not result.stdout.strip():
            print(f"{Colors.YELLOW}[INFO] No changes to commit{Colors.RESET}")
            return False

        # Commit changes
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        commit_msg = f"Update List-IP-Blacklist.txt - {timestamp}"
        subprocess.run(["git", "commit", "-m", commit_msg], capture_output=True)

        # Push to configured remote and branch
        print(f"{Colors.BLUE}[*] Pushing to {GITHUB_REMOTE}/{GITHUB_BRANCH}...{Colors.RESET}")
        result = subprocess.run(
            ["git", "push", GITHUB_REMOTE, GITHUB_BRANCH],
            capture_output=True, text=True
        )

        if result.returncode == 0:
            print(f"{Colors.GREEN}[+] Successfully pushed blacklist to GitHub{Colors.RESET}")
            print(f"{Colors.CYAN}    Raw URL: https://raw.githubusercontent.com/ANDIAFIF/SOC-BIOFARMA/{GITHUB_BRANCH}/List-IP-Blacklist.txt{Colors.RESET}")
            return True
        else:
            print(f"{Colors.RED}[ERROR] Failed to push: {result.stderr}{Colors.RESET}")
            return False

    except Exception as e:
        print(f"{Colors.RED}[ERROR] Git operation failed: {str(e)}{Colors.RESET}")
        return False


def git_pull():
    """Pull latest changes from GitHub"""
    try:
        os.chdir(GITHUB_REPO_PATH)

        print(f"{Colors.BLUE}[*] Pulling from {GITHUB_REMOTE}/{GITHUB_BRANCH}...{Colors.RESET}")
        result = subprocess.run(
            ["git", "pull", GITHUB_REMOTE, GITHUB_BRANCH],
            capture_output=True, text=True
        )

        if result.returncode == 0:
            print(f"{Colors.GREEN}[+] Successfully pulled from GitHub{Colors.RESET}")
            if result.stdout.strip():
                print(f"    {result.stdout.strip()}")
            return True
        else:
            # Try without specifying remote/branch (for initial setup)
            if "couldn't find remote ref" in result.stderr or "fatal" in result.stderr:
                print(f"{Colors.YELLOW}[INFO] No remote branch yet. Will create on first push.{Colors.RESET}")
                return True
            print(f"{Colors.YELLOW}[WARN] Pull result: {result.stderr}{Colors.RESET}")
            return False

    except Exception as e:
        print(f"{Colors.RED}[ERROR] Git pull failed: {str(e)}{Colors.RESET}")
        return False


def print_single_result(ip, vt_result, abuse_result, index=None):
    """Print formatted result for single IP"""
    prefix = f"[{index}] " if index else ""

    print(f"\n{Colors.BOLD}{'─'*60}{Colors.RESET}")
    print(f"{Colors.BOLD}{prefix}IP: {Colors.CYAN}{ip}{Colors.RESET}")
    print(f"{Colors.BOLD}{'─'*60}{Colors.RESET}")

    # VirusTotal
    print(f"{Colors.MAGENTA}[VT]{Colors.RESET} ", end="")
    if "error" in vt_result:
        print(f"{Colors.YELLOW}{vt_result['error']}{Colors.RESET}")
    else:
        mal = vt_result['malicious']
        sus = vt_result['suspicious']
        mal_color = Colors.RED if mal > 0 else Colors.GREEN
        sus_color = Colors.YELLOW if sus > 0 else Colors.GREEN
        print(f"Mal:{mal_color}{mal}{Colors.RESET} Sus:{sus_color}{sus}{Colors.RESET} | {vt_result['country']} | {vt_result['as_owner'][:30]}")

    # AbuseIPDB
    print(f"{Colors.MAGENTA}[AB]{Colors.RESET} ", end="")
    if "error" in abuse_result:
        print(f"{Colors.YELLOW}{abuse_result['error']}{Colors.RESET}")
    else:
        score = abuse_result['abuse_score']
        reports = abuse_result['total_reports']
        score_color = Colors.RED if score >= 50 else (Colors.YELLOW if score > 0 else Colors.GREEN)
        print(f"Score:{score_color}{score}%{Colors.RESET} Reports:{reports} | {abuse_result['isp'][:30]}")

    # Verdict
    is_malicious = False
    if "error" not in vt_result and vt_result.get("is_bad"):
        is_malicious = True
    if "error" not in abuse_result and abuse_result.get("is_bad"):
        is_malicious = True

    if is_malicious:
        print(f"{Colors.RED}{Colors.BOLD}>>> MALICIOUS <<<{Colors.RESET}")
    else:
        print(f"{Colors.GREEN}>>> CLEAN <<<{Colors.RESET}")

    return is_malicious


def check_api_keys():
    """Check if API keys are configured"""
    missing = []
    if not VT_API_KEY:
        missing.append("VIRUSTOTAL_API_KEY")
    if not ABUSEIPDB_API_KEY:
        missing.append("ABUSEIPDB_API_KEY")

    if missing:
        print(f"\n{Colors.YELLOW}[!] Missing API keys: {', '.join(missing)}")
        print(f"    Configure them in .env file{Colors.RESET}")
        return False
    return True


def process_ips(ips, ip_type="source"):
    """Process list of IPs and check reputation"""
    if not ips:
        print(f"{Colors.YELLOW}[!] No valid IPs found in the data{Colors.RESET}")
        return

    print(f"\n{Colors.CYAN}{Colors.BOLD}╔═══════════════════════════════════════════════════════════════╗")
    print(f"║  Found {len(ips)} unique {ip_type.upper()} IPs to check")
    print(f"╚═══════════════════════════════════════════════════════════════╝{Colors.RESET}")

    print(f"\n{Colors.WHITE}IPs to check:{Colors.RESET}")
    for i, ip in enumerate(ips, 1):
        print(f"  {i}. {ip}")

    print(f"\n{Colors.GREEN}Press Enter to start checking, or 'c' to cancel...{Colors.RESET}")
    confirm = input().strip().lower()

    if confirm == 'c':
        print(f"{Colors.YELLOW}Cancelled.{Colors.RESET}")
        return

    malicious_ips = []
    clean_ips = []

    print(f"\n{Colors.BLUE}[*] Starting reputation check...{Colors.RESET}\n")

    for i, ip in enumerate(ips, 1):
        print(f"{Colors.BLUE}[{i}/{len(ips)}] Checking {ip}...{Colors.RESET}")

        vt_result = check_virustotal(ip)
        abuse_result = check_abuseipdb(ip)

        is_malicious = print_single_result(ip, vt_result, abuse_result, i)

        if is_malicious:
            malicious_ips.append(ip)
            added = add_to_blacklist(ip)
            if added:
                print(f"{Colors.GREEN}    [+] Added to blacklist{Colors.RESET}")
        else:
            clean_ips.append(ip)

    # Summary
    print(f"\n{Colors.BOLD}{'═'*60}")
    print(f"                    SUMMARY")
    print(f"{'═'*60}{Colors.RESET}")
    print(f"{Colors.GREEN}  Clean IPs:     {len(clean_ips)}{Colors.RESET}")
    print(f"{Colors.RED}  Malicious IPs: {len(malicious_ips)}{Colors.RESET}")

    if malicious_ips:
        print(f"\n{Colors.RED}  Malicious IPs added to blacklist:{Colors.RESET}")
        for ip in malicious_ips:
            print(f"    • {ip}")

        print(f"\n{Colors.BLUE}[*] Auto-pushing blacklist to GitHub...{Colors.RESET}")
        git_push_blacklist()

    input(f"\n{Colors.GREEN}Press Enter to continue...{Colors.RESET}")


def check_single_ip_mode():
    """Mode for checking single IP"""
    print(f"\n{Colors.CYAN}Enter IP address to check (or 'back' to return):{Colors.RESET}")
    ip = input(f"{Colors.GREEN}IP > {Colors.RESET}").strip()

    if ip.lower() == 'back':
        return

    if not validate_ip(ip):
        print(f"{Colors.RED}[ERROR] Invalid IP address format{Colors.RESET}")
        input(f"{Colors.GREEN}Press Enter to continue...{Colors.RESET}")
        return

    if is_private_ip(ip):
        print(f"{Colors.YELLOW}[!] This is a private/internal IP address{Colors.RESET}")
        input(f"{Colors.GREEN}Press Enter to continue...{Colors.RESET}")
        return

    print(f"\n{Colors.BLUE}[*] Checking {ip}...{Colors.RESET}")

    vt_result = check_virustotal(ip)
    abuse_result = check_abuseipdb(ip)

    is_malicious = print_single_result(ip, vt_result, abuse_result)

    if is_malicious:
        added = add_to_blacklist(ip)
        if added:
            print(f"{Colors.GREEN}[+] Added to blacklist{Colors.RESET}")
            print(f"{Colors.BLUE}[*] Auto-pushing to GitHub...{Colors.RESET}")
            git_push_blacklist()

    input(f"\n{Colors.GREEN}Press Enter to continue...{Colors.RESET}")


def main():
    """Main function"""
    clear_screen()
    print_banner()

    # Initial git pull
    git_pull()

    # Check API keys
    check_api_keys()

    while True:
        try:
            clear_screen()
            print_banner()
            print_main_menu()

            choice = input(f"{Colors.GREEN}Select option [0-7] > {Colors.RESET}").strip()

            if choice == '0':
                print(f"\n{Colors.CYAN}Goodbye! Stay safe.{Colors.RESET}\n")
                break

            elif choice == '1':
                # Check Source IP
                clear_screen()
                print(f"\n{Colors.CYAN}{Colors.BOLD}=== CHECK SOURCE IP ==={Colors.RESET}")
                data = get_multiline_input()
                if data:
                    ips = extract_ips_from_text(data, "source")
                    process_ips(ips, "source")

            elif choice == '2':
                # Check Destination IP
                clear_screen()
                print(f"\n{Colors.CYAN}{Colors.BOLD}=== CHECK DESTINATION IP ==={Colors.RESET}")
                data = get_multiline_input()
                if data:
                    ips = extract_ips_from_text(data, "destination")
                    process_ips(ips, "destination")

            elif choice == '3':
                # Check Single IP
                check_single_ip_mode()

            elif choice == '4':
                # View Blacklist
                clear_screen()
                show_blacklist()

            elif choice == '5':
                # Push to GitHub
                clear_screen()
                print(f"\n{Colors.CYAN}{Colors.BOLD}=== PUSH TO GITHUB ==={Colors.RESET}")
                git_push_blacklist()
                input(f"\n{Colors.GREEN}Press Enter to continue...{Colors.RESET}")

            elif choice == '6':
                # Pull from GitHub
                clear_screen()
                print(f"\n{Colors.CYAN}{Colors.BOLD}=== PULL FROM GITHUB ==={Colors.RESET}")
                git_pull()
                input(f"\n{Colors.GREEN}Press Enter to continue...{Colors.RESET}")

            elif choice == '7':
                # Help
                clear_screen()
                print_help()

            else:
                print(f"{Colors.RED}Invalid option. Please select 0-7{Colors.RESET}")
                input(f"{Colors.GREEN}Press Enter to continue...{Colors.RESET}")

        except KeyboardInterrupt:
            print(f"\n{Colors.CYAN}Use option [0] to exit{Colors.RESET}")
            input(f"{Colors.GREEN}Press Enter to continue...{Colors.RESET}")
            continue
        except EOFError:
            break


if __name__ == "__main__":
    main()
