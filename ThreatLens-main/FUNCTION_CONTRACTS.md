"""
ThreatLens Function Contracts Documentation
Coursework: Function Specifications and Contracts
"""

# ============================================================================
# MODULE: threatlens.cli
# ============================================================================

# function: build_parser()
# ============================================================================
"""
FUNCTION CONTRACT: build_parser

SIGNATURE:
    def build_parser() -> argparse.ArgumentParser

PURPOSE:
    Create and configure the argument parser for the ThreatLens CLI.

PARAMETERS:
    None

RETURN VALUE:
    ArgumentParser: Configured parser with all 14 subcommands

SIDE EFFECTS:
    - Creates parser with subcommands (scan, follow, rules, etc.)
    - Registers all command-line options and arguments
    - Sets default values for various options

PRECONDITIONS:
    - argparse module must be importable
    - All command handlers must be defined

POSTCONDITIONS:
    - Returns non-null ArgumentParser object
    - Parser has exactly 14 subcommands
    - Each subcommand has its own argument set

EXCEPTIONS:
    None (parser construction is deterministic)

EXAMPLE USAGE:
    parser = build_parser()
    args = parser.parse_args(['scan', 'logs/', '--output', 'report.json'])
"""

# function: run_rules()
# ============================================================================
"""
FUNCTION CONTRACT: run_rules

SIGNATURE:
    def run_rules() -> int

PURPOSE:
    List all available detection rules and print them to stdout.

PARAMETERS:
    None

RETURN VALUE:
    int: Exit code (0 = success)

SIDE EFFECTS:
    - Prints ThreatLens banner
    - Prints list of all available detectors
    - Each detector prints: name, description, MITRE mapping

PRECONDITIONS:
    - ALL_DETECTORS list must be populated
    - Each detector must have: name, description, mitre_tactic, mitre_technique

POSTCONDITIONS:
    - At least 13+ detector rules printed
    - Return code is 0
    - Banner and header text displayed

EXCEPTIONS:
    None (only prints)

STDOUT FORMAT:
    _____ _                    _   _
    |_   _| |__  _ __ ___  __ _| |_| |    ___ _ __  ___
      | | | '_ \\| '__/ _ \\/ _` | __| |   / _ \\ '_ \\/ __|
      | | | | | | | |  __/ (_| | |_| |__|  __/ | | \\__ \\
      |_| |_| |_|_|  \\___|\__,_|\\__|_____\\___|_| |_|___/
    
    Available Detection Rules:
    - Rule Name
      Description text
      MITRE: Tactic / Technique

EXAMPLE USAGE:
    exit_code = run_rules()
    assert exit_code == 0
"""

# function: run_summary(args)
# ============================================================================
"""
FUNCTION CONTRACT: run_summary

SIGNATURE:
    def run_summary(args: argparse.Namespace) -> int

PURPOSE:
    Print a summary of a previously generated JSON report without re-scanning.

PARAMETERS:
    args (argparse.Namespace): Contains:
        - args.report (str): Path to JSON report file
        - args.no_color (bool, optional): Disable colored output

RETURN VALUE:
    int: Exit code
        0 = Report printed successfully
        1 = Error (file not found, invalid JSON, etc.)

SIDE EFFECTS:
    - Reads JSON file from disk
    - Prints report metadata, severity summary, top rules to stdout
    - May set no_color flag globally

PRECONDITIONS:
    - args.report must be a valid path (or will return 1)
    - Report file must be valid JSON

POSTCONDITIONS:
    - If successful: Banner, metadata, severity breakdown, top rules printed
    - If failed: Error message logged, return code 1

EXCEPTIONS:
    - OSError: File not found → return 1
    - json.JSONDecodeError: Invalid JSON → return 1

VALIDATES:
    - Report file exists
    - JSON is valid
    - Required fields present: report_metadata, severity_summary, alerts

EXAMPLE USAGE:
    args = argparse.Namespace(report='report.json', no_color=False)
    exit_code = run_summary(args)
    # Output:
    # Report:        report.json
    # Generated:     2026-06-17T10:30:00
    # Tool version:  2.3.0
    # Events:        1000
    # Alerts:        42
    # Severity breakdown:
    #   CRITICAL   5
    #   HIGH       10
    #   MEDIUM     15
    #   LOW        12
"""

# function: run_verify_chain(args)
# ============================================================================
"""
FUNCTION CONTRACT: run_verify_chain

SIGNATURE:
    def run_verify_chain(args: argparse.Namespace) -> int

PURPOSE:
    Verify the SHA-256 hash chain integrity of stored events.

PARAMETERS:
    args (argparse.Namespace): Contains:
        - args.database (str): Path to SQLite database

RETURN VALUE:
    int: Exit code
        0 = Hash chain integrity verified (no tampering)
        1 = Hash chain verification failed (tampering detected)

SIDE EFFECTS:
    - Loads all hash records from database
    - Recalculates SHA-256 hashes for each record
    - Prints verification result and any errors

PRECONDITIONS:
    - Database file must exist and be accessible
    - Database must have hash_records table

POSTCONDITIONS:
    - If valid chain (all hashes match):
        - Prints: "Hash chain integrity verified"
        - Returns 0
    - If invalid chain (hashes don't match):
        - Prints: "Hash chain integrity failed"
        - Lists each error: "Record N hash mismatch"
        - Returns 1

ALGORITHM:
    for each hash_record:
        expected_hash = SHA256(previous_hash + record_payload)
        if expected_hash != record_hash:
            errors.append("Record N hash mismatch")
        if record_previous_hash != previous_hash:
            errors.append("Record N previous hash mismatch")
        previous_hash = record_hash
    
    return (len(errors) == 0, errors)

SECURITY PROPERTIES:
    - Detects: Any event modification
    - Detects: Event deletion (breaks continuity)
    - Detects: Event reordering (changes hash references)
    - Cannot detect: Future additions (chain can grow)

EXAMPLE USAGE:
    args = argparse.Namespace(database='evidence.db')
    exit_code = run_verify_chain(args)
    
    if exit_code == 0:
        print("Evidence chain is intact and unmodified")
    else:
        print("Warning: Evidence chain has been tampered with!")
"""

# function: run_encrypt_report(args)
# ============================================================================
"""
FUNCTION CONTRACT: run_encrypt_report

SIGNATURE:
    def run_encrypt_report(args: argparse.Namespace) -> int

PURPOSE:
    Encrypt a report file using AES-256-GCM for confidentiality protection.

PARAMETERS:
    args (argparse.Namespace): Contains:
        - args.input (str): Path to plaintext file to encrypt
        - args.output (str): Path to write encrypted file
        - args.key_file (str): Path to AES-256 key file

RETURN VALUE:
    int: Exit code (0 = success)

SIDE EFFECTS:
    - Reads plaintext file from disk
    - Reads or generates encryption key
    - Writes encrypted JSON envelope to output file
    - Creates key file if it doesn't exist (with 0600 permissions)

PRECONDITIONS:
    - args.input file must exist and be readable
    - args.output path must be writable

POSTCONDITIONS:
    - output file created with encrypted data
    - key file created/updated
    - Message printed: "Encrypted {input} -> {output}"

KEY GENERATION:
    if key_file.exists():
        key = read_bytes(key_file)  # Existing 256-bit key
    else:
        key = os.urandom(32)  # Generate new random key
        write_bytes(key_file, key)  # Save for future use
        chmod(key_file, 0o600)  # Owner-only permissions

ENCRYPTION:
    nonce = os.urandom(12)  # Random 96-bit nonce
    cipher = AESGCM(key)
    ciphertext = cipher.encrypt(nonce, plaintext, None)
    
    envelope = {
        "nonce": base64(nonce),
        "ciphertext": base64(ciphertext)
    }
    write_file(output, JSON(envelope))

SECURITY PROPERTIES:
    - Confidentiality: AES-256 (256-bit symmetric encryption)
    - Authentication: GCM mode detects tampering
    - Key reuse: Uses same key for repeated encryptions
    - Nonce uniqueness: New random nonce each time

FILE FORMATS:
    Input: Any binary or text file
    Output: JSON envelope with base64 fields
    
    Example output:
    {
      "nonce": "cJ3kLm+4p/vQ==",
      "ciphertext": "xY7zBc9dEf/Gh..."
    }

EXAMPLE USAGE:
    args = argparse.Namespace(
        input='sensitive_report.pdf',
        output='sensitive_report.pdf.encrypted',
        key_file='sensitive_report.key'
    )
    exit_code = run_encrypt_report(args)
    
    # Creates two files:
    # - sensitive_report.pdf.encrypted (encrypted data)
    # - sensitive_report.key (256-bit key, keep secure!)
"""

# function: run_sign_report(args)
# ============================================================================
"""
FUNCTION CONTRACT: run_sign_report

SIGNATURE:
    def run_sign_report(args: argparse.Namespace) -> int

PURPOSE:
    Create a digital signature for a report file using RSA-2048-PSS.

PARAMETERS:
    args (argparse.Namespace): Contains:
        - args.input (str): Path to file to sign
        - args.signature (str): Path to write signature file
        - args.private_key (str): Path to RSA private key (PEM format)
        - args.passphrase (str, optional): Passphrase for encrypted key

RETURN VALUE:
    int: Exit code (0 = success)

SIDE EFFECTS:
    - Reads input file from disk
    - Loads RSA private key (may prompt for passphrase)
    - Computes signature
    - Writes base64-encoded signature to file

PRECONDITIONS:
    - args.input file must exist
    - args.private_key file must exist and be valid RSA PEM
    - If key is encrypted, args.passphrase must be correct

POSTCONDITIONS:
    - Signature file created at args.signature path
    - Message printed: "Signed {input} -> {signature}"

ALGORITHM:
    private_key = load_pem_private_key(key_file, passphrase)
    file_data = read_bytes(input)
    
    signature = private_key.sign(
        file_data,
        padding=PSS(
            mgf=MGF1(SHA256()),
            salt_length=PSS.MAX_LENGTH
        ),
        algorithm=SHA256()
    )
    
    write_file(signature_file, base64_encode(signature))

SIGNING ALGORITHM:
    - Algorithm: RSA-PSS (Probabilistic Signature Scheme)
    - Key Size: 2048-bit RSA
    - Hash: SHA-256
    - Padding: PSS with MGF1-SHA256

SIGNATURE PROPERTIES:
    - Deterministic: No, PSS includes randomization
    - Unique per run: Yes, different salt each time
    - File binding: Yes, tied to specific file content
    - Key binding: Yes, only private key can create

FILE FORMATS:
    Input: Any file (binary or text)
    Output: Base64-encoded RSA-PSS signature
    
    Example signature file content:
    xY7zBc9dEf/GhIjKlMnOpQrStUvWxYzAbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGh==

VERIFICATION:
    # Can verify with OpenSSL:
    $ openssl dgst -sha256 -verify public_key.pem \
        -signature file.sig file
    # Output: Verified OK or Verification Failure

EXAMPLE USAGE:
    # Generate keypair (first time only)
    $ openssl genrsa -out private.pem 2048
    $ openssl rsa -in private.pem -pubout -out public.pem
    
    # Sign report
    args = argparse.Namespace(
        input='incident_report.pdf',
        signature='incident_report.pdf.sig',
        private_key='private.pem',
        passphrase=None
    )
    exit_code = run_sign_report(args)
    
    # Output: Signed incident_report.pdf -> incident_report.pdf.sig
"""

# function: run_correlate(args)
# ============================================================================
"""
FUNCTION CONTRACT: run_correlate

SIGNATURE:
    def run_correlate(args: argparse.Namespace) -> int

PURPOSE:
    Correlate stored alerts into security incidents.

PARAMETERS:
    args (argparse.Namespace): Contains:
        - args.database (str): Path to SQLite database
        - args.window_minutes (int): Correlation window (default: 60)
        - args.min_alerts (int): Minimum alerts to form incident (default: 2)

RETURN VALUE:
    int: Exit code (0 = success, 1 = error)

SIDE EFFECTS:
    - Loads alerts from database
    - Runs correlation engine
    - Stores incidents in database
    - Prints correlation results to stdout

PRECONDITIONS:
    - Database must exist and be readable
    - Database must have alerts table

POSTCONDITIONS:
    - Incidents stored in database
    - Prints: "Correlated N incident(s) from M alert(s)"
    - Each incident: "  - {title} (risk={score})"

ALGORITHM:
    alerts = store.load_alerts()
    engine = CorrelationEngine(
        window_minutes=window_minutes,
        min_alerts=min_alerts
    )
    incidents = engine.correlate(alerts)
    store.save_incidents([incident.to_dict() for incident in incidents])

CORRELATION LOGIC:
    - Groups alerts within time window
    - Minimum alerts per incident threshold
    - Calculates risk scores based on:
        - Alert severity
        - Temporal proximity
        - Alert relationships
    - Maps to MITRE ATT&CK tactics

OUTPUT FORMAT:
    Correlated 3 incident(s) from 42 alert(s)
      - Attack Chain Alpha (risk=85)
      - Lateral Movement Delta (risk=72)
      - Exfiltration Attempt (risk=68)

EXAMPLE USAGE:
    args = argparse.Namespace(
        database='evidence.db',
        window_minutes=120,
        min_alerts=3
    )
    exit_code = run_correlate(args)
    # Correlates alerts within 2-hour window
    # Requires minimum 3 related alerts
"""

# ============================================================================
# MODULE: threatlens.security.crypto_utils
# ============================================================================

# function: generate_aes_key()
# ============================================================================
"""
FUNCTION CONTRACT: generate_aes_key

SIGNATURE:
    def generate_aes_key() -> bytes

PURPOSE:
    Generate a cryptographically secure random AES-256 key.

PARAMETERS:
    None

RETURN VALUE:
    bytes: 32-byte (256-bit) random key

SIDE EFFECTS:
    - Reads from os.urandom() (system entropy)

PRECONDITIONS:
    - System must have entropy source available

POSTCONDITIONS:
    - Returns exactly 32 bytes
    - Bytes are cryptographically random
    - Each call returns different key

ENTROPY:
    - Source: os.urandom() (OS-provided CSPRNG)
    - Quality: Cryptographic-grade randomness
    - Uniqueness: Collision probability < 2^-256

EXAMPLE USAGE:
    key = generate_aes_key()
    assert len(key) == 32
    assert isinstance(key, bytes)
"""

# function: encrypt_bytes(plaintext, key)
# ============================================================================
"""
FUNCTION CONTRACT: encrypt_bytes

SIGNATURE:
    def encrypt_bytes(plaintext: bytes, key: bytes) -> bytes

PURPOSE:
    Encrypt bytes using AES-256-GCM.

PARAMETERS:
    plaintext (bytes): Data to encrypt
    key (bytes): 256-bit encryption key (must be exactly 32 bytes)

RETURN VALUE:
    bytes: JSON envelope (UTF-8) containing base64-encoded nonce and ciphertext

SIDE EFFECTS:
    - Generates random 96-bit nonce (os.urandom)
    - Performs AES-256-GCM encryption

PRECONDITIONS:
    - key must be exactly 32 bytes
    - plaintext can be any length (including empty)

POSTCONDITIONS:
    - Returns valid UTF-8 JSON bytes
    - JSON contains "nonce" and "ciphertext" fields
    - Both fields are base64-encoded

EXCEPTIONS:
    ValueError: If key length != 32 bytes

ENCRYPTION DETAILS:
    - Cipher: AES-256-GCM
    - Nonce: 96-bit random (12 bytes)
    - Nonce reuse: Prevents forgery (unique per encryption)
    - Authentication: GCM mode provides AEAD

JSON ENVELOPE:
    {
      "nonce": "<base64>",
      "ciphertext": "<base64>"
    }

EXAMPLE USAGE:
    key = generate_aes_key()
    plaintext = b"Secret message"
    
    encrypted = encrypt_bytes(plaintext, key)
    # Output: b'{"nonce": "...", "ciphertext": "..."}'
"""

# function: decrypt_bytes(blob, key)
# ============================================================================
"""
FUNCTION CONTRACT: decrypt_bytes

SIGNATURE:
    def decrypt_bytes(blob: bytes, key: bytes) -> bytes

PURPOSE:
    Decrypt AES-256-GCM encrypted JSON envelope.

PARAMETERS:
    blob (bytes): JSON envelope containing base64-encoded nonce and ciphertext
    key (bytes): 256-bit decryption key (must match encryption key)

RETURN VALUE:
    bytes: Original plaintext

SIDE EFFECTS:
    - Parses JSON envelope
    - Verifies GCM authentication tag

PRECONDITIONS:
    - key must be exactly 32 bytes
    - blob must be valid JSON with "nonce" and "ciphertext" fields
    - blob must be valid base64-encoded

POSTCONDITIONS:
    - Returns original plaintext
    - Guaranteed authentic (GCM verified)

EXCEPTIONS:
    ValueError: If key length != 32 bytes
    json.JSONDecodeError: If blob not valid JSON
    base64.binascii.Error: If base64 invalid
    cryptography.exceptions.InvalidTag: If authentication fails

AUTHENTICATION:
    - GCM mode ensures: plaintext not modified, nonce not changed
    - Any bit-flip in ciphertext detected
    - Returns False rather than corrupted data

EXAMPLE USAGE:
    key = generate_aes_key()
    plaintext = b"Secret message"
    
    encrypted = encrypt_bytes(plaintext, key)
    decrypted = decrypt_bytes(encrypted, key)
    
    assert decrypted == plaintext
"""

# ============================================================================
# MODULE: threatlens.detections.hash_chain
# ============================================================================

# class: HashChainManager
# ============================================================================
"""
CLASS CONTRACT: HashChainManager

PURPOSE:
    Manage tamper-evident SHA-256 hash chain in SQLite database.

CONSTRUCTOR:
    def __init__(self, store: ThreatLensStore | Path | str)
    
    Parameters:
        store: ThreatLensStore instance, or path string/Path to database
    
    Creates: HashChainManager with reference to store

METHOD: append_event(event, event_type)
--------
    SIGNATURE:
        def append_event(event: LogEvent | dict, event_type: str = "event") -> HashRecord
    
    PURPOSE:
        Append a log event to the hash chain.
    
    PARAMETERS:
        event: LogEvent object or dictionary
        event_type: Type label (default: "event")
    
    RETURNS:
        HashRecord: Record with hash, previous_hash, payload
    
    SIDE EFFECTS:
        - Computes SHA-256 hash of event
        - Stores in database with chain link

METHOD: verify_chain()
--------
    SIGNATURE:
        def verify_chain() -> tuple[bool, list[str]]
    
    PURPOSE:
        Verify integrity of entire hash chain.
    
    PARAMETERS:
        None
    
    RETURNS:
        tuple:
            bool: True if chain valid, False if tampered
            list[str]: List of errors if invalid
    
    ALGORITHM:
        for record in records:
            expected = SHA256(previous_hash + payload)
            if expected != record.hash:
                errors.append("hash mismatch")
            previous = record.hash
        return (no errors, errors)

SECURITY PROPERTIES:
    - Tamper Detection: Yes (any modification detected)
    - Event Ordering: Yes (hash chain proves order)
    - Non-Repudiation: No (not signed, no key binding)
    - Append-only: Yes (can add records, not modify)

EXAMPLE USAGE:
    manager = HashChainManager("evidence.db")
    
    # Add events
    event = LogEvent(timestamp=..., event_id=123, ...)
    record = manager.append_event(event)
    
    # Verify chain
    is_valid, errors = manager.verify_chain()
    if is_valid:
        print("Chain intact")
    else:
        print(f"Tampering detected: {errors}")
"""

# ============================================================================
# SUMMARY TABLE: Function Return Types
# ============================================================================

"""
╔════════════════════════════╦═════════════════════════════╦═════════════════╗
║ Function                   ║ Return Type                 ║ Success Value   ║
╠════════════════════════════╬═════════════════════════════╬═════════════════╣
║ build_parser()             ║ ArgumentParser              ║ Non-null object ║
║ run_rules()                ║ int                         ║ 0               ║
║ run_summary()              ║ int                         ║ 0 (success)     ║
║ run_verify_chain()         ║ int                         ║ 0 (valid chain) ║
║ run_encrypt_report()       ║ int                         ║ 0               ║
║ run_sign_report()          ║ int                         ║ 0               ║
║ run_correlate()            ║ int                         ║ 0               ║
║ generate_aes_key()         ║ bytes (32)                  ║ Non-null bytes  ║
║ encrypt_bytes()            ║ bytes (JSON UTF-8)          ║ Non-null bytes  ║
║ decrypt_bytes()            ║ bytes (plaintext)           ║ Original data   ║
║ verify_chain()             ║ tuple[bool, list[str]]      ║ (True, [])      ║
║ append_event()             ║ HashRecord                  ║ Record object   ║
╚════════════════════════════╩═════════════════════════════╩═════════════════╝

EXIT CODES:
    0 = Success
    1 = Error / Failure
    2 = Severe error / System error
"""
