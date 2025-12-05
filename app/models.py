from cryptography.fernet import Fernet, InvalidToken
from wtforms.validators import DataRequired, Email
from werkzeug.security import generate_password_hash, check_password_hash
from app.cryptography import hash_password, verify_password, encrypt_bio, decrypt_bio
import os
from app import db

def get_fernet():
    key = os.environ.get('bio_encryption_key')
    if not key:
        raise Exception('Bio encryption key not set, please generate')
    return Fernet(key)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(50), default='user', nullable=False)
    bio = db.Column(db.String(500), nullable=False)

    def __init__(self, username, password, role, bio):
        self.username = (username or '').strip().lower()
        self.set_password(password)
        self.role = role if role in ('user', 'moderator', 'admin') else 'user'
        self.bio = (bio or '')[:500]

    def set_password(self, plaintext_password: str): # secure password by hashing
        pepper = os.environ.get('password_pepper', '')
        self.password = generate_password_hash(plaintext_password + pepper)

    def check_password(self, plaintext_password: str) -> bool: # verifies password with pepper
        try:
            pepper = os.environ.get("password_pepper", "")
            return check_password_hash(self.password, plaintext_password + pepper)
        except Exception:
            return False

    def encrypt_bio(self, plaintext_bio: str) -> str: # encrypts bio with fernet
        if not plaintext_bio:
            bio_plaintext = ""
        return get_fernet().encrypt(bio_plaintext.encode())

    def decrypt_bio(self) -> str: # decrypts bio for user display
        try:
            return get_fernet().decrypt(self.bio).decode()
        except InvalidToken:
            return "Error, bio cannot be decrypted"

    def __repr__(self):
        return f'<User {self.username}>'

    # role checks
    def is_admin(self) -> bool:
        return self.role == 'admin'
    def is_moderator(self) -> bool:
        return self.role == 'moderator'
    def is_user(self) -> bool:
        return self.role == 'user'






