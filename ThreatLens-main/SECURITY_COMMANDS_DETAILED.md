# ThreatLens Security Commands - Complete Technical Analysis

## Overview

ThreatLens provides three advanced security commands for forensic evidence protection:

1. **verify-chain** - SHA-256 Tamper-Detection Hash Chain
2. **encrypt-report** - AES-256-GCM Confidential Encryption  
3. **sign-report** - RSA-2048 Digital Signing

---

## 1. VERIFY-CHAIN: SHA-256 Hash Chain

### Purpose
Verify the integrity of stored events using a tamper-evident hash chain mechanism.

### How It Works

```
Database Events:
Event 1 → Hash1 = SHA256("" + Event1_data)
Event 2 → Hash2 = SHA256(Hash1 + Event2_data)
Event 3 → Hash3 = SHA256(Hash2 + Event3_data)
Event 4 → Hash4 = SHA256(Hash3 + Event4_data)
```

### Algorithm

```python
def verify_chain():
    records = load_all_records()
    previous_hash = ""
    errors = []
    
    for index, record in enumerate(records):
        payload = record['payload']
        # Recalculate expected hash
        expected_hash = SHA256(previous_hash + JSON(payload))
        actual_hash = record['event_hash']
        
        # Verify chain continuity
        if expected_hash != actual_hash:
            errors.append(f"Record {index} hash mismatch")
        
        if record['previous_hash'] != previous_hash:
            errors.append(f"Record {index} previous hash broken")
        
        previous_hash = actual_hash
    
    return (len(errors) == 0, errors)
```

### Security Properties

| Property | Guarantee |
|----------|-----------|
| **Tamper Detection** | Any event modification breaks chain |
| **Event Deletion** | Removing events breaks continuity |
| **Event Reordering** | Changes hash references |
| **Forensic Evidence** | Proves events in original order, unmodified |

### Command Usage

```bash
# Verify hash chain integrity
$ threatlens verify-chain --database threatlens.db
Hash chain integrity verified

# If tampering detected:
Record 5 hash mismatch
Record 6 previous hash mismatch
```

---

## 2. ENCRYPT-REPORT: AES-256-GCM

### Purpose
Encrypt reports and evidence files for confidentiality and integrity protection.

### Algorithm Details

| Component | Value |
|-----------|-------|
| **Cipher** | AES-256-GCM (Galois/Counter Mode) |
| **Key Size** | 256-bit (32 bytes) |
| **Nonce** | 96-bit (12 bytes), random per encryption |
| **Block Size** | 128-bit |
| **Authentication** | Built-in with GCM (detects tampering) |

### Encryption Process

```python
def encrypt_artifact(input_file, output_file, key):
    plaintext = read_file(input_file)
    
    # Generate random nonce
    nonce = os.urandom(12)  # 96 bits
    
    # Encrypt using AES-256-GCM
    cipher = AESGCM(key)
    ciphertext = cipher.encrypt(nonce, plaintext, None)
    
    # Create JSON envelope
    envelope = {
        "nonce": base64(nonce),
        "ciphertext": base64(ciphertext)
    }
    
    write_file(output_file, JSON(envelope))
```

### Key Features

1. **Random Nonce**: Each encryption uses unique random nonce
2. **Authenticated Encryption**: GCM provides both encryption and authentication
3. **Key Management**: 
   - If key file exists: Use existing key
   - If key file missing: Generate new 256-bit key
4. **File Permissions**: Created with 0600 (owner read/write only)

### Security Properties

```
┌─────────────────────────────────────────────────────┐
│          AES-256-GCM Security Properties            │
├─────────────────────────────────────────────────────┤
│ • Confidentiality: Only key holder can decrypt      │
│ • Authenticity: Signature built-in to ciphertext    │
│ • Integrity: Fails if ciphertext is modified        │
│ • Non-malleability: Cannot alter encrypted data     │
│ • Forward Secrecy: Random nonce per encryption      │
└─────────────────────────────────────────────────────┘
```

### Command Usage

```bash
# Encrypt a report
$ threatlens encrypt-report report.pdf \
    --output report.pdf.encrypted \
    --key-file report.key

Encrypted report.pdf -> report.pdf.encrypted

# If key file doesn't exist:
# → Generated new AES-256 key (32 bytes)
# → Saved to report.key with 0600 permissions

# Decrypt (using standard tools):
$ openssl enc -d -aes-256-gcm \
    -in report.pdf.encrypted \
    -K <hex_key> -iv <hex_nonce>
```

---

## 3. SIGN-REPORT: RSA-2048 Digital Signature

### Purpose
Sign reports for non-repudiation, authenticity, and integrity verification.

### Algorithm Details

| Component | Value |
|-----------|-------|
| **Algorithm** | RSA-PSS (Probabilistic Signature Scheme) |
| **Key Size** | 2048-bit RSA modulus |
| **Public Exponent** | 65537 (standard) |
| **Hash Algorithm** | SHA-256 |
| **Padding** | PSS with MGF1-SHA256, max salt length |

### Signature Process

```python
def sign_artifact(input_file, signature_file, private_key_file):
    # Load private key
    private_key = load_pem_private_key(
        read_file(private_key_file),
        password=passphrase if provided else None
    )
    
    # Sign the file
    file_data = read_file(input_file)
    signature = private_key.sign(
        file_data,
        padding=PSS(
            mgf=MGF1(SHA256()),
            salt_length=PSS.MAX_LENGTH
        ),
        algorithm=SHA256()
    )
    
    # Save signature as base64
    write_file(signature_file, base64_encode(signature))
```

### Verification Process

```python
def verify_artifact(input_file, signature_file, public_key_file):
    public_key = load_pem_public_key(read_file(public_key_file))
    signature = base64_decode(read_file(signature_file))
    
    try:
        public_key.verify(
            signature,
            read_file(input_file),
            padding=PSS(...),
            algorithm=SHA256()
        )
        return True
    except InvalidSignature:
        return False
```

### Security Properties

```
┌──────────────────────────────────────────────────────┐
│         RSA-2048-PSS Security Properties             │
├──────────────────────────────────────────────────────┤
│ • Authentication: Only private key holder can sign   │
│ • Non-repudiation: Signer cannot deny signing        │
│ • Integrity: Any file change breaks signature        │
│ • Verification: Anyone with public key can verify    │
│ • Probabilistic: Different signature per run (PSS)   │
│ • Resistance: Immune to padding oracle attacks       │
└──────────────────────────────────────────────────────┘
```

### Command Usage

```bash
# Generate RSA-2048 keypair (first time)
$ openssl genrsa -out private_key.pem 2048
$ openssl rsa -in private_key.pem -pubout -out public_key.pem

# Sign a report
$ threatlens sign-report report.pdf \
    --signature report.pdf.sig \
    --private-key private_key.pem

Signed report.pdf -> report.pdf.sig

# Verify signature (using OpenSSL)
$ openssl dgst -sha256 -verify public_key.pem \
    -signature report.pdf.sig report.pdf
```

---

## Complete Forensic Workflow

### Scenario: Incident Investigation

```bash
# Step 1: Collect and analyze logs
$ threatlens scan /logs --output report.json

# Step 2: Store alerts in database
$ threatlens seed-db --database incident.db

# Step 3: Verify data integrity (chain not tampered)
$ threatlens verify-chain --database incident.db
Hash chain integrity verified ✓

# Step 4: Generate PDF forensic report
$ threatlens forensic-report \
    --database incident.db \
    --output incident_report.pdf

# Step 5: Sign report (prove authenticity)
$ threatlens sign-report incident_report.pdf \
    --signature incident_report.pdf.sig \
    --private-key investigator_private_key.pem

# Step 6: Encrypt report (confidential storage)
$ threatlens encrypt-report incident_report.pdf \
    --output incident_report.pdf.enc \
    --key-file incident.key

# Result: Chain of custody established
```

### Artifacts Created

| File | Purpose | Key Property |
|------|---------|--------------|
| `incident.db` | Evidence database | Hash chain integrity |
| `incident_report.pdf` | Human-readable report | Original evidence |
| `incident_report.pdf.sig` | Digital signature | Non-repudiation |
| `incident_report.pdf.enc` | Encrypted report | Confidentiality |
| `investigator_private_key.pem` | Signing key | Authentication |
| `incident.key` | Decryption key | Secure storage |

---

## Security Comparison Matrix

```
┌──────────────┬──────────────┬────────────────┬──────────────────┐
│   Command    │  Algorithm   │  Primary Goal  │  Side Benefits   │
├──────────────┼──────────────┼────────────────┼──────────────────┤
│ verify-chain │ SHA-256 chain│ Tamper         │ Event ordering   │
│              │              │ detection      │ verification     │
├──────────────┼──────────────┼────────────────┼──────────────────┤
│encrypt-report│ AES-256-GCM  │ Confidentiality│ Integrity check  │
│              │              │ (privacy)      │ (authentication) │
├──────────────┼──────────────┼────────────────┼──────────────────┤
│sign-report   │RSA-PSS-2048  │ Non-repudiation│ Authenticity     │
│              │              │ (proof)        │ verification     │
└──────────────┴──────────────┴────────────────┴──────────────────┘
```

---

## Implementation Details

### File Locations

| Module | File |
|--------|------|
| Encryption/Signing | `threatlens/security/crypto_utils.py` |
| Hash Chain | `threatlens/detections/hash_chain.py` |
| CLI Integration | `threatlens/cli.py` |

### Dependencies

- **cryptography**: Provides AES-GCM, RSA, and cryptographic primitives
- **pathlib**: File handling
- **json**: Envelope serialization
- **hashlib**: SHA-256 hashing

---

## Best Practices

### For verify-chain
✓ Run immediately after log collection
✓ Verify database hasn't been accessed by unauthorized users
✓ Compare with known-good baseline hashes

### For encrypt-report
✓ Store keys separately from encrypted files
✓ Use strong key management practices
✓ Rotate keys periodically
✓ Never commit keys to version control

### For sign-report
✓ Protect private keys with passphrases
✓ Use hardware security modules for critical investigations
✓ Distribute public keys through secure channels
✓ Maintain audit log of who signed what reports

---

## Compliance & Forensic Standards

These commands support:
- **NIST SP 800-86**: Guide to Integrating Forensic Techniques
- **ISO/IEC 27035**: Information Security Incident Management
- **RFC 2104**: HMAC (basis for integrity verification)
- **RFC 3394**: AES Key Wrap (key protection)

