#!/usr/bin/env python3
"""
generate_license.py — Create RSA-signed license files for your clients.

Key model (asymmetric — much harder to forge):
  private_key.pem  ← YOU keep this SECRET, never distribute it
  public_key.pem   ← embed in the protected script (verify-only, cannot forge)

License file format (.lic):
  base64url(json_payload) + "." + base64url(RSA-PSS SHA-256 signature)

Auto-Activation (Hybrid):
  The RSA signature covers machine_id="ACTIVATE".
  On first run the protected script generates a local activation proof file
  (HMAC-SHA256 of machine_id:license_id, keyed on a machine-derived secret)
  and stores it as  license_activation.dat  next to the .lic file.
  Subsequent runs verify BOTH the RSA sig AND the activation proof.

Usage: python generate_license.py
"""

import os, sys, json, uuid, hashlib, datetime, platform, socket, base64
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend

R="\033[91m"; G="\033[92m"; Y="\033[93m"; C="\033[96m"; W="\033[0m"

# ── RSA key size — 2048 is standard; 4096 is extra-hardened ──────────────────
KEY_BITS = 2048

def banner():
    print(f"""
{C}╔══════════════════════════════════════════════════════╗
║       🔑  LICENSE GENERATOR v3.0  (RSA Edition)      ║
║   Supports: Manual Lock | Auto-Activation | Unlocked  ║
╚══════════════════════════════════════════════════════╝{W}
""")

def prompt(label, default=""):
    val = input(f"  {label}{f' [{default}]' if default else ''}: ").strip()
    return val if val else default

# ── Key management ────────────────────────────────────────────────────────────

def load_or_create_keys():
    priv_path = Path("private_key.pem")
    pub_path  = Path("public_key.pem")

    if priv_path.exists() and pub_path.exists():
        print(f"  {G}✓ Loaded existing RSA key pair{W}")
        private_key = serialization.load_pem_private_key(
            priv_path.read_bytes(), password=None, backend=default_backend()
        )
        public_key = serialization.load_pem_public_key(
            pub_path.read_bytes(), backend=default_backend()
        )
        return private_key, public_key

    # Generate fresh 2048-bit RSA key pair
    print(f"  {Y}⚙  Generating {KEY_BITS}-bit RSA key pair...{W}", end=" ", flush=True)
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=KEY_BITS, backend=default_backend()
    )
    public_key = private_key.public_key()

    priv_path.write_bytes(
        private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption()
        )
    )
    pub_path.write_bytes(
        public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )
    print(f"{G}done{W}")
    print(f"  {G}✓ private_key.pem  ← KEEP SECRET{W}")
    print(f"  {G}✓ public_key.pem   ← embed in protected script{W}")
    return private_key, public_key

# ── Signing ───────────────────────────────────────────────────────────────────

def sign_license(private_key, data: dict) -> bytes:
    """
    Returns bytes in the format:
        <base64url(json)>.<base64url(RSA-PSS signature)>
    """
    payload = json.dumps(data, separators=(",", ":"), sort_keys=True).encode()
    signature = private_key.sign(
        payload,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    b64_payload = base64.urlsafe_b64encode(payload)
    b64_sig     = base64.urlsafe_b64encode(signature)
    return b64_payload + b"." + b64_sig

# ── Machine ID helper (matches what the protected script uses) ────────────────

def get_my_machine_id():
    mac     = str(uuid.getnode())
    host    = socket.gethostname()
    os_name = platform.system()
    lid     = ""
    if os_name == "Linux":
        for p in ["/etc/machine-id", "/var/lib/dbus/machine-id"]:
            try: lid = Path(p).read_text().strip(); break
            except: pass
    raw = f"{mac}:{host}:{os_name}:{lid}".encode()
    return hashlib.sha256(raw).hexdigest()[:32]

# ── Main flow ─────────────────────────────────────────────────────────────────

def generate():
    banner()

    print(f"{Y}── RSA Keys ───────────────────────────────────────{W}")
    private_key, _ = load_or_create_keys()

    print(f"\n{Y}── Client Details ─────────────────────────────────{W}")
    client_name  = prompt("Client name / company")
    client_email = prompt("Client email (optional)")

    print(f"\n{Y}── License Duration ───────────────────────────────{W}")
    print("  1) 30 days\n  2) 90 days\n  3) 180 days\n  4) 1 year\n  5) Custom (YYYY-MM-DD)")
    choice = prompt("Choice", "1")
    dur_map = {"1": 30, "2": 90, "3": 180, "4": 365}
    if choice in dur_map:
        expiry = datetime.datetime.now() + datetime.timedelta(days=dur_map[choice])
    else:
        expiry = datetime.datetime.fromisoformat(prompt("Enter expiry date (YYYY-MM-DD)"))

    print(f"""
{Y}── Machine Lock ───────────────────────────────────{W}
  1) {G}Auto-Activate{W}  — locks to FIRST machine client runs it on {C}(recommended){W}
  2) {Y}Manual Lock{W}    — you provide the client's MAC + hostname now
  3) {R}No Lock{W}        — works on any machine (least secure)
""")
    lock_choice = prompt("Choice", "1")
    machine_id  = "ANY"

    if lock_choice == "1":
        machine_id = "ACTIVATE"
        print(f"  {G}✓ Set to Auto-Activate on first run{W}")

    elif lock_choice == "2":
        print(f"""
  {Y}Ask your client to run this one-liner and send you the output:{W}
  {C}python -c "import uuid,socket,hashlib,platform; mac=str(uuid.getnode()); host=socket.gethostname(); os_n=platform.system(); print('MAC:',mac,'Host:',host,'OS:',os_n)"{W}
""")
        client_mac  = prompt("Client MAC address")
        client_host = prompt("Client hostname")
        client_os   = prompt("Client OS (Windows / Linux / Darwin)", "Windows")
        linux_id    = ""
        if client_os == "Linux":
            linux_id = prompt("Client /etc/machine-id (optional)", "")
        raw = f"{client_mac}:{client_host}:{client_os}:{linux_id}".encode()
        machine_id = hashlib.sha256(raw).hexdigest()[:32]
        print(f"  {G}✓ Machine ID: {machine_id[:16]}...{W}")

    elif lock_choice == "3":
        machine_id = "ANY"
        print(f"  {Y}⚠ No machine lock — license works on any machine{W}")

    notes = prompt(f"\n  Notes / product name (optional)")

    # Build license payload
    lic_id = uuid.uuid4().hex[:12].upper()
    data = {
        "client_name":  client_name,
        "client_email": client_email,
        "issued_at":    datetime.datetime.now().isoformat(),
        "expiry":       expiry.isoformat(),
        "machine_id":   machine_id,
        "notes":        notes,
        "license_id":   lic_id
    }

    # RSA-sign and save
    signed = sign_license(private_key, data)
    safe_name = client_name.replace(" ", "_").lower()
    named_lic = f"license_{safe_name}.lic"
    Path(named_lic).write_bytes(signed)
    Path("license.lic").write_bytes(signed)   # generic copy for client

    # Summary labels
    if machine_id == "ACTIVATE":
        lock_label = f"{G}Auto-Activate (locks on first run){W}"
    elif machine_id == "ANY":
        lock_label = f"{R}No lock (any machine){W}"
    else:
        lock_label = f"{Y}Manually locked to specific machine{W}"

    print(f"""
{C}══════════════════════════════════════════════════
  ✅  LICENSE CREATED  (RSA-signed, tamper-proof)
══════════════════════════════════════════════════{W}
  👤  Client     : {client_name}
  📧  Email      : {client_email or "N/A"}
  🆔  License ID : {lic_id}
  📅  Issued     : {datetime.datetime.now().strftime('%d %b %Y')}
  ⏰  Expires    : {expiry.strftime('%d %b %Y')}  ({(expiry - datetime.datetime.now()).days} days)
  🔒  Lock type  : {lock_label}
  📝  Notes      : {notes or "N/A"}

  {G}Files saved:{W}
  📄  {named_lic}   (your backup)
  📄  license.lic            (send to client)

{Y}  Send your client these 2 files:{W}
    protected_script.py
    license.lic

  {R}⚠  public_key.pem is EMBEDDED inside protected_script.py — no key file needed by client!{W}
  {R}⚠  NEVER share private_key.pem{W}

{C}  Client folder should look like:{W}
    📁 my_tool/
       ├── protected_yourscript.py
       └── license.lic
""")

    if machine_id == "ACTIVATE":
        print(f"""{Y}  ℹ  Auto-Activation (Hybrid RSA) Info:{W}
  • First run : client sees "[✓] License activated and locked to this machine!"
               A  license_activation.dat  file is written locally.
  • All future runs : verified via RSA sig + local activation proof.
  • To reset (e.g. client changed PC): generate a fresh license.lic (and delete
               the old license_activation.dat on the client machine).
""")

if __name__ == "__main__":
    generate()
