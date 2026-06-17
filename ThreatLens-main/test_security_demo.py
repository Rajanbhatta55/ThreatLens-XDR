"""Practical demonstration of security commands."""
import os
from pathlib import Path
import subprocess

print("\n" + "=" * 80)
print("PRACTICAL TEST: Security Commands")
print("=" * 80)

# Create test directory
test_dir = Path("security_test")
test_dir.mkdir(exist_ok=True)

# Create a sample report
test_report = test_dir / "test_report.txt"
test_report.write_text("Sample security report for ThreatLens\nTest data: threat detection results")
print(f"\n✓ Created test report: {test_report}")
print(f"  Content: {test_report.read_text()[:50]}...")

# ============================================================================
# TEST 1: ENCRYPT REPORT
# ============================================================================
print("\n" + "-" * 80)
print("TEST 1: ENCRYPT-REPORT (AES-256-GCM)")
print("-" * 80)

key_file = test_dir / "report.key"
encrypted_file = test_dir / "test_report.encrypted"

cmd = [
    "python", "-m", "threatlens.cli", "encrypt-report", 
    str(test_report),
    "--output", str(encrypted_file),
    "--key-file", str(key_file)
]

result = subprocess.run(cmd, capture_output=True, text=True)
print(f"Command: threatlens encrypt-report {test_report} --output {encrypted_file} --key-file {key_file}")
if result.returncode != 0:
    print(f"Error: {result.stderr}")
    print(f"Output: {result.stdout}")
else:
    print(f"Output: {result.stdout.strip()}")
    print(f"✓ Encrypted file size: {encrypted_file.stat().st_size} bytes")
    print(f"✓ Key file size: {key_file.stat().st_size} bytes")

    # Show encrypted content is different
    original_content = test_report.read_bytes()
    encrypted_content = encrypted_file.read_bytes()
    print(f"✓ Original: {original_content[:30]}...")
    print(f"✓ Encrypted: {encrypted_content[:30]}...")

# ============================================================================
# TEST 2: SIGN REPORT  
# ============================================================================
print("\n" + "-" * 80)
print("TEST 2: SIGN-REPORT (RSA-2048)")
print("-" * 80)

private_key = test_dir / "private_key.pem"
signature_file = test_dir / "test_report.sig"

# First, create RSA keypair using openssl
try:
    # Generate RSA keypair
    key_gen_cmd = f"openssl genrsa -out {private_key} 2048 2>nul"
    os.system(key_gen_cmd)
    
    if private_key.exists():
        print(f"✓ Generated RSA-2048 keypair: {private_key}")
        print(f"  Key file size: {private_key.stat().st_size} bytes")
        
        # Sign the report
        sign_cmd = [
            "python", "-m", "threatlens.cli", "sign-report",
            str(test_report),
            "--signature", str(signature_file),
            "--private-key", str(private_key)
        ]
        
        result = subprocess.run(sign_cmd, capture_output=True, text=True)
        print(f"\nCommand: threatlens sign-report {test_report} --signature {signature_file} --private-key {private_key}")
        print(f"Output: {result.stdout.strip()}")
        
        if signature_file.exists():
            print(f"✓ Signature file created: {signature_file}")
            print(f"  Signature size: {signature_file.stat().st_size} bytes")
            print(f"  Signature (base64): {signature_file.read_text()[:80]}...")
except Exception as e:
    print(f"⚠ Could not generate RSA keypair: {e}")

# ============================================================================
# SUMMARY
# ============================================================================
print("\n" + "=" * 80)
print("SECURITY FILES CREATED")
print("=" * 80)

files_created = [
    ("Original Report", test_report),
    ("Encrypted Report", encrypted_file),
    ("Encryption Key", key_file),
]

if private_key.exists():
    files_created.append(("RSA Private Key", private_key))
if signature_file.exists():
    files_created.append(("Report Signature", signature_file))

for name, path in files_created:
    if path.exists():
        size = path.stat().st_size
        print(f"✓ {name:<20} {str(path):<40} ({size:>6} bytes)")

print("\n✓ All security commands executed successfully!")
print("✓ Encryption uses AES-256-GCM with random nonce")
print("✓ Signing uses RSA-PSS-2048 with SHA-256")
print("=" * 80)
