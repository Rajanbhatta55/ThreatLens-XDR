#!/usr/bin/env python
"""
Demonstration of ThreatLens Security Commands:
1. verify-chain (SHA-256 hash chain)
2. encrypt-report (AES-256 encryption)
3. sign-report (RSA-2048 signing)
"""

import sys
from pathlib import Path

print("=" * 80)
print("THREATLENS SECURITY COMMANDS - HOW THEY WORK")
print("=" * 80)
print()

# ============================================================================
# 1. VERIFY-CHAIN: SHA-256 Hash Chain
# ============================================================================
print("1. VERIFY-CHAIN: SHA-256 Tamper-Evident Hash Chain")
print("-" * 80)
print("""
PURPOSE: Verify the integrity of stored events using a hash chain.

HOW IT WORKS:
  • Each event is hashed using SHA-256
  • Hash includes: previous_hash + current_event_data
  • Creates a chain: Event1 → Event2 → Event3 → ...
  • If any event is modified, the chain breaks
  • Tamper-evident: Can detect any unauthorized changes

ALGORITHM:
  1. Load all hash records from database
  2. For each record:
     - Recalculate hash: SHA256(previous_hash + event_payload)
     - Compare with stored hash
     - Verify previous_hash reference
  3. Return success or list of errors

SECURITY BENEFIT:
  • Proves events haven't been altered
  • Proves events haven't been deleted (breaks chain)
  • Proves events haven't been reordered

EXAMPLE:
  $ threatlens verify-chain --database threatlens.db
  Hash chain integrity verified
  (or)
  Record 5 hash mismatch
  Record 6 previous hash mismatch
""")

# ============================================================================
# 2. ENCRYPT-REPORT: AES-256-GCM Encryption
# ============================================================================
print("\n2. ENCRYPT-REPORT: AES-256-GCM Encryption")
print("-" * 80)
print("""
PURPOSE: Encrypt reports and evidence files for confidentiality.

ALGORITHM:
  • Cipher: AES-256-GCM (Galois/Counter Mode)
  • Key Size: 256-bit (32 bytes)
  • Nonce: Random 96-bit (12 bytes) per encryption
  • Authentication: Built-in with GCM

ENCRYPTION PROCESS:
  1. Generate random 12-byte nonce
  2. Encrypt plaintext with AES-256-GCM(key, nonce)
  3. Encode as JSON envelope:
     {
       "nonce": "base64(nonce)",
       "ciphertext": "base64(encrypted_data)"
     }

KEY MANAGEMENT:
  • If key file exists: Use existing key
  • If key file missing: Generate new random key
  • Key stored separately from encrypted file
  • File permissions: 0600 (read/write owner only)

SECURITY PROPERTIES:
  • Confidentiality: Only key holder can decrypt
  • Authenticity: GCM detects tampering
  • Integrity: Fails if encrypted data modified

EXAMPLE:
  $ threatlens encrypt-report report.pdf \\
      --output report.pdf.encrypted \\
      --key-file report.key
  
  Encrypted report.pdf -> report.pdf.encrypted
  
  Decrypt:
  $ openssl enc -d -aes-256-gcm -in report.pdf.encrypted -K <key_hex> -iv <nonce_hex>
""")

# ============================================================================
# 3. SIGN-REPORT: RSA-2048 Digital Signature
# ============================================================================
print("\n3. SIGN-REPORT: RSA-2048 Digital Signature")
print("-" * 80)
print("""
PURPOSE: Sign reports for non-repudiation and authenticity verification.

ALGORITHM:
  • Algorithm: RSA-PSS (Probabilistic Signature Scheme)
  • Key Size: RSA-2048 bits
  • Hash: SHA-256
  • Padding: PSS with MGF1-SHA256, max salt length

SIGNATURE PROCESS:
  1. Load private key (may require passphrase)
  2. Hash file: SHA256(file_contents)
  3. Sign hash with RSA-PSS/SHA-256
  4. Encode signature as base64
  5. Write to signature file (0600 permissions)

KEYPAIR GENERATION:
  • RSA-2048: 2048-bit modulus
  • Public exponent: 65537
  • Can be password-protected with PKCS8 encryption

SECURITY PROPERTIES:
  • Authentication: Only private key holder can sign
  • Non-repudiation: Signer cannot deny signing
  • Integrity: Any file modification breaks signature
  • Verification: Anyone with public key can verify

EXAMPLE WORKFLOW:
  1. Generate keypair (first time):
     $ openssl genrsa -out private_key.pem 2048
     $ openssl rsa -in private_key.pem -pubout -out public_key.pem

  2. Sign report:
     $ threatlens sign-report report.pdf \\
         --signature report.pdf.sig \\
         --private-key private_key.pem
     
     Signed report.pdf -> report.pdf.sig

  3. Verify signature (external tools):
     $ openssl dgst -sha256 -verify public_key.pem \\
         -signature report.pdf.sig report.pdf
""")

# ============================================================================
# COMPLETE WORKFLOW
# ============================================================================
print("\n" + "=" * 80)
print("COMPLETE FORENSIC WORKFLOW")
print("=" * 80)
print("""
Step 1: Collect logs and detect threats
  $ threatlens scan logs/ --output report.json

Step 2: Generate PDF forensic report
  $ threatlens forensic-report --database threatlens.db --output report.pdf

Step 3: Verify hash chain integrity (tamper detection)
  $ threatlens verify-chain --database threatlens.db
  ✓ Hash chain integrity verified

Step 4: Sign report (non-repudiation)
  $ threatlens sign-report report.pdf \\
      --signature report.pdf.sig \\
      --private-key private_key.pem

Step 5: Encrypt signed report (confidentiality)
  $ threatlens encrypt-report report.pdf \\
      --output report.pdf.encrypted \\
      --key-file report.key

Result:
  ✓ report.pdf.sig (signature, verifies authenticity)
  ✓ report.pdf.encrypted (encrypted, ensures confidentiality)
  ✓ report.key (decryption key, store securely)
  ✓ private_key.pem (signature key, store securely)

Security Properties Achieved:
  ✓ Authenticity: Signed with RSA-2048
  ✓ Non-repudiation: Private key proves origin
  ✓ Confidentiality: AES-256-GCM encrypted
  ✓ Integrity: Hash chain + signature verification
  ✓ Tamper-evident: Any modification detected
""")

print("\n" + "=" * 80)
