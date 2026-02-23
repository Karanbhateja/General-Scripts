#!/usr/bin/env python3
"""
protect_script.py — Obfuscates your Python script and injects RSA license checker.

Key model:
  private_key.pem  — you keep this (signs licenses via generate_license.py)
  public_key.pem   — embedded INTO the protected script at protect-time
                     (verifies signatures; cannot forge licenses)

Auto-Activation (Hybrid RSA):
  The RSA sig covers machine_id="ACTIVATE".  On first run the script writes a
  local  license_activation.dat  (HMAC proof of machine binding).  Subsequent
  runs verify BOTH the RSA signature AND the activation proof file.

Usage: python protect_script.py <your_script.py>
"""

import sys, os, base64, zlib, marshal
from pathlib import Path

R="\033[91m"; G="\033[92m"; Y="\033[93m"; C="\033[96m"; W="\033[0m"

def banner():
    print(f"""
{C}╔═════════════════════════════════════════════════════╗
║       🔒  PYTHON SCRIPT PROTECTOR v3.0                ║
║   RSA-Signed License | Obfuscation | Auto-Activation   ║
║           Author: Karan Bhateja | Version: 3.0         ║
╚══════════════════════════════════════════════════════╝{W}
""")

def obfuscate_code(source_code):
    code_obj   = compile(source_code, "<protected>", "exec")
    bytecode   = marshal.dumps(code_obj)
    compressed = zlib.compress(bytecode, level=9)
    encoded    = base64.b85encode(compressed).decode()
    chunks     = [encoded[i:i+64] for i in range(0, len(encoded), 64)]
    chunk_lines = "\n    ".join(f'"{c}"' for c in chunks)
    return f"""import base64,zlib,marshal
_x=(
    {chunk_lines}
)
exec(marshal.loads(zlib.decompress(base64.b85decode("".join(_x)))))
"""

# ─────────────────────────────────────────────────────────────────────────────
# LICENSE_CHECKER template — {PUBLIC_KEY_PEM} is filled in at protect-time.
# ─────────────────────────────────────────────────────────────────────────────
LICENSE_CHECKER_TEMPLATE = r'''
import os, sys, json, uuid, hashlib, datetime, platform, socket, base64, hmac
from pathlib import Path

# RSA public key — embedded at build time (verify-only, cannot forge)
_PUBLIC_KEY_PEM = b"""{PUBLIC_KEY_PEM}"""

def _get_machine_id():
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

def _machine_secret():
    """Stable per-machine secret derived from hardware identifiers."""
    mid = _get_machine_id()
    return hashlib.sha256(f"activation:{mid}:v1".encode()).digest()

def _verify_rsa(payload: bytes, signature: bytes):
    """Verify RSA-PSS SHA-256 signature using the embedded public key."""
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.backends import default_backend
    pub = serialization.load_pem_public_key(_PUBLIC_KEY_PEM, backend=default_backend())
    pub.verify(
        signature, payload,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

def _load_license():
    lic_path = Path(__file__).parent / "license.lic"
    if not lic_path.exists():
        print("\n[ERROR] License file not found. Contact your vendor.\n"); sys.exit(1)
    raw = lic_path.read_bytes().strip()
    try:
        b64_payload, b64_sig = raw.split(b".")
        payload   = base64.urlsafe_b64decode(b64_payload)
        signature = base64.urlsafe_b64decode(b64_sig)
    except Exception:
        print("\n[ERROR] License file is malformed.\n"); sys.exit(1)
    try:
        _verify_rsa(payload, signature)
    except Exception:
        print("\n[ERROR] License signature is invalid or the file has been tampered with.\n"); sys.exit(1)
    return json.loads(payload)

def _activation_path():
    return Path(__file__).parent / "license_activation.dat"

def _write_activation(license_id: str, machine_id: str):
    secret = _machine_secret()
    token  = hmac.new(secret, f"{license_id}:{machine_id}".encode(), "sha256").digest()
    _activation_path().write_bytes(base64.b64encode(token))

def _verify_activation(license_id: str, machine_id: str) -> bool:
    ap = _activation_path()
    if not ap.exists():
        return False
    secret   = _machine_secret()
    expected = hmac.new(secret, f"{license_id}:{machine_id}".encode(), "sha256").digest()
    stored   = base64.b64decode(ap.read_bytes())
    return hmac.compare_digest(expected, stored)

def _check_license():
    data = _load_license()

    # ── HYBRID AUTO-ACTIVATION ────────────────────────────────────────────────
    if data.get("machine_id") == "ACTIVATE":
        mid        = _get_machine_id()
        license_id = data.get("license_id", "")
        if _verify_activation(license_id, mid):
            # Already activated on this machine — allow
            data["machine_id"] = mid
        else:
            # First run — write activation proof
            try:
                _write_activation(license_id, mid)
                print("[✓] License activated and locked to this machine!")
                data["machine_id"] = mid
            except Exception:
                print("[!] Activation proof could not be saved (check folder write permissions).")
                data["machine_id"] = mid   # allow this run; will retry next time
    # ─────────────────────────────────────────────────────────────────────────

    # Expiry check
    try:
        expiry = datetime.datetime.fromisoformat(data["expiry"])
    except Exception:
        print("\n[ERROR] License data corrupted.\n"); sys.exit(1)

    if datetime.datetime.now() > expiry:
        d = (datetime.datetime.now() - expiry).days
        print(f"\n[ERROR] License expired {d} day(s) ago. Contact your vendor to renew.\n"); sys.exit(1)

    # Machine lock check
    mid = data.get("machine_id", "ANY")
    if mid not in ("ANY", "") and _get_machine_id() != mid:
        print("\n[ERROR] This license is not valid for this machine.\n"); sys.exit(1)

    client    = data.get("client_name", "User")
    exp_str   = expiry.strftime("%d %b %Y")
    days_left = (expiry - datetime.datetime.now()).days
    locked    = "Machine-Locked" if mid not in ("ANY", "") else "Any Machine"
    print(f"[OK] License valid | Client: {client} | Expires: {exp_str} ({days_left}d left) | {locked}")

_check_license()
'''

def protect(input_path):
    banner()
    if not os.path.exists(input_path):
        print(f"{R}[ERROR] File not found: {input_path}{W}"); sys.exit(1)

    # Load public key
    pub_path = Path("public_key.pem")
    if not pub_path.exists():
        print(f"{R}[ERROR] public_key.pem not found!{W}")
        print(f"{Y}  Run  python generate_license.py  first to generate the RSA key pair.{W}")
        sys.exit(1)

    pub_key_pem = pub_path.read_text().strip()
    print(f"  {G}✓ Loaded public_key.pem — will be embedded into protected script{W}")

    print(f"{Y}[1/3] Reading: {input_path}{W}")
    source = open(input_path, "r", encoding="utf-8").read()

    print(f"{Y}[2/3] Obfuscating (3-layer encoding)...{W}")
    obfuscated = obfuscate_code(source)

    print(f"{Y}[3/3] Injecting RSA license checker...{W}")
    base_name = os.path.splitext(os.path.basename(input_path))[0]
    output    = f"protected_{base_name}.py"

    # Embed the public key into the checker
    license_checker = LICENSE_CHECKER_TEMPLATE.replace("{PUBLIC_KEY_PEM}", pub_key_pem)

    final_code = f"""#!/usr/bin/env python3
# Protected script — unauthorized use prohibited.
# Requires: license.lic in the same folder.  (Public key is embedded — no extra key file needed.)
# Generated by Python Script Protector v3.0
{license_checker}
# ── PROTECTED PAYLOAD ────────────────────────────────────────────────────────
{obfuscated}"""
    open(output, "w", encoding="utf-8").write(final_code)

    print(f"""
{C}══════════════════════════════════════════════════
  ✅  DONE
══════════════════════════════════════════════════{W}
  📄  {output}   ← give to client
  🔑  private_key.pem    ← {R}KEEP SECRET — never share{W}
  📢  public_key.pem     ← {G}embedded inside {output}{W}

  Next: run  python generate_license.py
  Then send client:
    {output}
    license.lic

  {C}Client folder should look like:{W}
    📁 my_tool/
       ├── protected_{base_name}.py
       └── license.lic
  {Y}(No license.key file needed — public key is baked in!){W}
""")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"{R}Usage: python protect_script.py <script.py>{W}"); sys.exit(1)
    protect(sys.argv[1])
