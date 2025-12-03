from wtforms.validators import DataRequired, Email
from werkzeug.security import generate_password_hash, check_password_hash

from app import db

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(50), default='user', nullable=False)
    bio = db.Column(db.String(500), nullable=False)

    def __init__(self, username, password, role, bio):
        self.username = username
        self.set_password(password)
        self.role = role
        self.bio = bio

    def set_password(self, plaintext_password: str):
        self.password = generate_password_hash(plaintext_password)

    def check_password(self, plaintext_password: str) -> bool:
        try:
            return check_password_hash(self.password, plaintext_password)
        except Exception:
            return False

    def __repr__(self):
        return f'<User {self.username}>'






