#!/usr/bin/env python3
"""
Deterministic Verification Oracle for the Official Commercial Profile Avatar Patent
and Cryptographic Signatures under the sole identity of Pavan Kumar Sadashiv.
"""
import hashlib
import json
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
MANIFEST_PATH = os.path.join(ROOT, "assets/patent-avatar/CRYPTOGRAPHIC_SIGNATURE_MANIFEST.json")
PUB_KEY = os.path.join(ROOT, "assets/patent-avatar/Pavan_Kumar_Sadashiv_Public_Key.pem")
CERT_PATH = os.path.join(ROOT, "assets/patent-avatar/Pavan_Kumar_Sadashiv_X509_Certificate.pem")
SSH_PUB = os.path.join(ROOT, "assets/patent-avatar/Pavan_Kumar_Sadashiv_Ed25519_Signing_Key.pub")

with open(MANIFEST_PATH, "r") as f:
    manifest = json.load(f)

signatory = manifest["sole_applicant_inventor_and_signatory"]
assert signatory["full_legal_name"] == "Pavan Kumar Sadashiv", "Signatory name mismatch!"
assert "CN=Pavan Kumar Sadashiv" in signatory["x509_certificate_subject"], "X.509 CN mismatch!"

# Verify X.509 Certificate Subject via OpenSSL
cert_out = subprocess.check_output(
    ["openssl", "x509", "-in", CERT_PATH, "-noout", "-subject"], text=True
)
assert "Pavan Kumar Sadashiv" in cert_out, f"Certificate subject invalid: {cert_out}"

# Verify OpenSSH Ed25519 Public Key attribution
with open(SSH_PUB, "r") as f:
    ssh_pub_text = f.read().strip()
assert "Pavan Kumar Sadashiv" in ssh_pub_text, "SSH public key missing Pavan Kumar Sadashiv identity!"

# Verify Manifest signature
subprocess.run(
    [
        "openssl", "dgst", "-sha256", "-verify", PUB_KEY,
        "-signature", MANIFEST_PATH + ".sig", MANIFEST_PATH,
    ],
    check=True,
    stdout=subprocess.DEVNULL,
)

# Verify each protected asset's SHA-256, SHA-512, and detached RSA-4096 cryptographic signature
for key, item in manifest["protected_assets"].items():
    asset_path = os.path.join(ROOT, item["path"])
    sig_path = os.path.join(ROOT, item["detached_signature_path"])
    with open(asset_path, "rb") as af:
        data = af.read()
    assert hashlib.sha256(data).hexdigest() == item["sha256"], f"SHA-256 mismatch on {key}"
    assert hashlib.sha512(data).hexdigest() == item["sha512"], f"SHA-512 mismatch on {key}"
    subprocess.run(
        ["openssl", "dgst", "-sha256", "-verify", PUB_KEY, "-signature", sig_path, asset_path],
        check=True,
        stdout=subprocess.DEVNULL,
    )
    # Also verify OpenSSH Ed25519 detached signature (.sshsig)
    sshsig_path = sig_path + ".sshsig"
    assert os.path.exists(sshsig_path), f"Missing OpenSSH signature: {sshsig_path}"
    allowed_signers = os.path.join(ROOT, "assets/patent-avatar/allowed_signers")
    subprocess.run(
        [
            "ssh-keygen", "-Y", "verify",
            "-f", allowed_signers,
            "-I", "Pavan_Kumar_Sadashiv",
            "-n", "file",
            "-s", sshsig_path,
        ],
        input=data,
        check=True,
        stdout=subprocess.DEVNULL,
    )

print("VERIFIED OK: All Patent Documents, Commercial Profile Image Hashes, X.509 RSA-4096 & OpenSSH Ed25519 Signatures confirmed under Pavan Kumar Sadashiv.")
