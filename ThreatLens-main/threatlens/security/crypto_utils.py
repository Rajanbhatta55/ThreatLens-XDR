"""Cryptographic helpers for report protection and forensic evidence."""

from __future__ import annotations

import base64
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

AES_KEY_SIZE = 32
_NONCE_SIZE = 12


def _require_cryptography():
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding, rsa
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        return InvalidSignature, hashes, serialization, padding, rsa, AESGCM
    except ImportError as exc:  # pragma: no cover - dependency guard
        raise RuntimeError(
            "cryptography is required for AES-256 and RSA operations"
        ) from exc


def generate_aes_key() -> bytes:
    """Generate a random 256-bit AES key."""

    return os.urandom(AES_KEY_SIZE)


def _envelope(payload: bytes, nonce: bytes, tag: bytes | None = None) -> bytes:
    data = {
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ciphertext": base64.b64encode(payload).decode("ascii"),
    }
    if tag is not None:
        data["tag"] = base64.b64encode(tag).decode("ascii")
    return json.dumps(data, sort_keys=True).encode("utf-8")


def _parse_envelope(blob: bytes) -> tuple[bytes, bytes, bytes | None]:
    data = json.loads(blob.decode("utf-8"))
    nonce = base64.b64decode(data["nonce"])
    ciphertext = base64.b64decode(data["ciphertext"])
    tag = base64.b64decode(data["tag"]) if data.get("tag") else None
    return nonce, ciphertext, tag


def encrypt_bytes(plaintext: bytes, key: bytes) -> bytes:
    """Encrypt bytes using AES-256-GCM and return a JSON envelope."""

    _, _, _, _, _, AESGCM = _require_cryptography()
    if len(key) != AES_KEY_SIZE:
        raise ValueError("AES-256 requires a 32-byte key")

    nonce = os.urandom(_NONCE_SIZE)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return _envelope(ciphertext, nonce)


def decrypt_bytes(blob: bytes, key: bytes) -> bytes:
    """Decrypt a JSON-enveloped AES-256-GCM payload."""

    _, _, _, _, _, AESGCM = _require_cryptography()
    if len(key) != AES_KEY_SIZE:
        raise ValueError("AES-256 requires a 32-byte key")

    nonce, ciphertext, _tag = _parse_envelope(blob)
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)


def _write_secure_file(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def encrypt_artifact(input_path: Path, output_path: Path, key: bytes) -> Path:
    """Encrypt a file for secure archival."""

    output_path.write_bytes(encrypt_bytes(input_path.read_bytes(), key))
    return output_path


def decrypt_artifact(input_path: Path, output_path: Path, key: bytes) -> Path:
    """Decrypt a previously encrypted file."""

    output_path.write_bytes(decrypt_bytes(input_path.read_bytes(), key))
    return output_path


def generate_rsa_keypair(private_key_path: Path, public_key_path: Path, passphrase: str | None = None) -> tuple[Path, Path]:
    """Generate and store an RSA-2048 keypair."""

    InvalidSignature, hashes, serialization, padding, rsa, _ = _require_cryptography()
    _ = InvalidSignature, hashes, padding  # keep imports exercised for linting
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    if passphrase:
        enc_algo = serialization.BestAvailableEncryption(passphrase.encode("utf-8"))
    else:
        enc_algo = serialization.NoEncryption()
    _write_secure_file(
        private_key_path,
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=enc_algo,
        ),
    )
    _write_secure_file(
        public_key_path,
        private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ),
    )
    return private_key_path, public_key_path


def sign_bytes(data: bytes, private_key_path: Path, passphrase: str | None = None) -> bytes:
    """Sign bytes with RSA-PSS/SHA-256."""

    InvalidSignature, hashes, serialization, padding, _, _ = _require_cryptography()
    _ = InvalidSignature
    private_key = serialization.load_pem_private_key(
        private_key_path.read_bytes(),
        password=passphrase.encode("utf-8") if passphrase else None,
    )
    signature = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )
    return signature


def verify_bytes(data: bytes, signature: bytes, public_key_path: Path) -> bool:
    """Verify an RSA-PSS/SHA-256 signature."""

    InvalidSignature, hashes, serialization, padding, _, _ = _require_cryptography()
    public_key = serialization.load_pem_public_key(public_key_path.read_bytes())
    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
    except InvalidSignature:
        return False
    return True


def sign_artifact(input_path: Path, signature_path: Path, private_key_path: Path, passphrase: str | None = None) -> Path:
    signature = sign_bytes(input_path.read_bytes(), private_key_path, passphrase)
    _write_secure_file(signature_path, base64.b64encode(signature))
    return signature_path


def verify_artifact(input_path: Path, signature_path: Path, public_key_path: Path) -> bool:
    signature = base64.b64decode(signature_path.read_bytes())
    return verify_bytes(input_path.read_bytes(), signature, public_key_path)
