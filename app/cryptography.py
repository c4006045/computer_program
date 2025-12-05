import os
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet, InvalidToken

# from environment
password_pepper = os.environ.get('APP_PASSWORD_PEPPER', '')
fernet_key = os.environ.get('APP_PASSWORD_FERNET_KEY', '')

if fernet_key:
    fernet = Fernet(fernet_key.encode() if isinstance(fernet_key, str) else fernet_key)
else:
    fernet = None

# password hashing using PBKDF2-HMAC-SHA256, salt, and pepper
def hash_password(password: str) -> str:
    if password is None:
        raise ValueError("You must have a password")
    peppered = f"{password}{password_pepper or ''}"
    return generate_password_hash(peppered, method='pbkdf2:sha256', salt_length=32)

# verify password against the hash
def verify_password(hashed_password: str, attempt_password: str) -> bool:
    if hashed_password is None:
        return False
    peppered = f"{attempt_password}{password_pepper or ''}"
    return check_password_hash(hashed_password, peppered)

# bio encryption
def encrypt_bio(plaintext: str) -> str:
    if plaintext is None:
        return None
    if fernet is None:
        raise RuntimeError("You must have a Fernet key")
    return fernet.encrypt(plaintext.encode()).decode()

def decrypt_bio(encrypted: str) -> str:
    if encrypted is None:
        return ''
    if fernet is None:
        raise RuntimeError("You must have a Fernet key")
    try:
        return fernet.decrypt(encrypted).decode()
    except InvalidToken:
        return ''
