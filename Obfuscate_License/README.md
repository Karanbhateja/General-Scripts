# RSA License System — Walkthrough

## What Changed

The license system was upgraded from **symmetric Fernet AES** to **RSA-PSS asymmetric signing**.

| | Old (v2) | New (v3) |
|---|---|---|
| Crypto | Fernet (AES-128 symmetric) | RSA-PSS 2048-bit asymmetric |
| Client receives | `license.key` (can encrypt + decrypt) | `public_key.pem` embedded in script (verify only) |
| Can client forge license? | **Yes** — with `license.key` in hand | **No** — public key cannot sign |
| License format | Fernet ciphertext blob | `base64url(JSON) . base64url(RSA signature)` |

---

## File Summary

### [generate_license.py](file:///c:/Users/karan/Downloads/Obfuscate_License/generate_license.py)
- Auto-generates `private_key.pem` + `public_key.pem` on first run (2048-bit RSA)
- Builds a JSON license payload, signs it with **RSA-PSS SHA-256**
- Saves `.lic` as `<base64url(json)>.<base64url(signature)>`
- `private_key.pem` never leaves the vendor

### [protect_script.py](file:///c:/Users/karan/Downloads/Obfuscate_License/protect_script.py)
- Reads `public_key.pem` at protect-time and **hardcodes it** into the `LICENSE_CHECKER` block
- Client receives **no key file** — the public key is baked into the script
- `LICENSE_CHECKER` verifies RSA sig; rejects any tampered `.lic` file with `InvalidSignature`

---

## Auto-Activation (Hybrid RSA)

Since the protected script only has the public key (can't re-sign), activation uses a separate HMAC proof:

```
First run (machine_id == "ACTIVATE"):
  → Script writes  license_activation.dat
    = base64( HMAC-SHA256(key=machine-secret, msg="license_id:machine_id") )

Subsequent runs:
  → RSA sig verified  ✓  (covers original ACTIVATE payload)
  → HMAC proof re-computed and compared  ✓  (proves this is the activation machine)
```

To reset a client (new PC): delete `license_activation.dat` on their machine and issue a fresh `license.lic`.

---

## Verification Results

All 4 automated checks passed:

| Test | Result |
|---|---|
| License created (base64url.sig format) | ✅ PASS |
| Good RSA signature verifies | ✅ PASS |
| Tampered payload rejected (`InvalidSignature`) | ✅ PASS |
| HMAC activation proof matches | ✅ PASS |

---

## Vendor Workflow

```bash
# Step 1 — generate RSA keys + license
python generate_license.py
# → creates private_key.pem, public_key.pem, license.lic

# Step 2 — protect your script (embeds public key inside)
python protect_script.py my_tool.py
# → creates protected_my_tool.py

# Step 3 — send client ONLY these two files:
#   protected_my_tool.py
#   license.lic
```
