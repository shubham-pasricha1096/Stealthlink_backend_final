import os
import time
import hmac
import hashlib
import struct
import base64
import qrcode
from cryptography.fernet import Fernet

KEY_FILE = "otp_key.key"
QR_FILE = "encrypted_otp_qr.png"
OTP_LENGTH = 6
T0 = 0           # Unix epoch start
TX = 300         # Time step in seconds (5 minutes)
VALIDITY_SECONDS = TX

def load_or_create_key(path: str = KEY_FILE) -> bytes:
    """Load or create a base32 TOTP secret key (for shared secret)."""
    if os.path.exists(path):
        with open(path, "rb") as f:
            return f.read()
    else:
        key = base64.b32encode(os.urandom(20))  # 160-bit key
        with open(path, "wb") as f:
            f.write(key)
        os.chmod(path, 0o600)
        return key

def generate_totp(key: bytes, digits: int = OTP_LENGTH, t0: int = T0, tx: int = TX) -> str:
    """Generate TOTP per RFC 6238 using HMAC-SHA1."""
    # Calculate counter = floor((current_time - T0) / TX)
    T = int(time.time())
    counter = int((T - t0) / tx)
    # Pack counter into 8-byte big-endian
    counter_bytes = struct.pack(">Q", counter)
    # Decode base32 key and compute HMAC-SHA1
    secret = base64.b32decode(key, casefold=True)
    hmac_hash = hmac.new(secret, counter_bytes, hashlib.sha1).digest()
    # Dynamic truncation
    offset = hmac_hash[-1] & 0x0F
    code = (struct.unpack(">I", hmac_hash[offset:offset + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
    return str(code).zfill(digits)

def make_payload(otp: str, timestamp: int) -> str:
    """Combine otp and timestamp into single payload string."""
    return f"{otp}|{timestamp}"

def encrypt_payload(payload: str, fernet: Fernet) -> str:
    """Encrypt payload and return ascii-safe string."""
    token = fernet.encrypt(payload.encode())
    return token.decode()

def save_qr(data: str, path: str = QR_FILE):
    """Generate a QR image containing data and save to path."""
    qr = qrcode.QRCode(
        version=None,
        error_correction=qrcode.constants.ERROR_CORRECT_Q,
        box_size=8,
        border=4
    )
    qr.add_data(data)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    img.save(path)

def main():
    # Use same Fernet key for encrypting payloads
    fernet_key = Fernet.generate_key()
    fernet = Fernet(fernet_key)
    with open("fernet.key", "wb") as fk:
        fk.write(fernet_key)
        os.chmod("fernet.key", 0o600)

    # Load or create the shared TOTP secret key
    totp_key = load_or_create_key(KEY_FILE)

    otp = generate_totp(totp_key)
    timestamp = int(time.time())
    payload = make_payload(otp, timestamp)

    encrypted = encrypt_payload(payload, fernet)
    save_qr(encrypted, QR_FILE)

    print("=== StealthLink TOTP Generator ===")
    print(f"Timestamp: {timestamp}")
    print(f"Key (base32): {totp_key.decode()}")
    print(f"Encrypted Token: {encrypted[:60]}...")
    print(f"QR saved to: {os.path.abspath(QR_FILE)}")

if __name__ == "__main__":
    main()
