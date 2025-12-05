from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import CSRFProtect
from config import Config

db = SQLAlchemy()
csrf = CSRFProtect()

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    # session and cookie security
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
    app.config['SESSION_COOKIE_SECURE'] = False  # true if using HTTPS

    db.init_app(app)
    csrf.init_app(app)

    from .routes import main
    app.register_blueprint(main)

    with app.app_context():
        from .models import User
        db.drop_all()
        db.create_all()

        # sample users
        users = [
            {"username": "user1@email.com", "password": "Userpass!23", "role": "user", "bio": "I'm a basic user"},
            {"username": "mod1@email.com", "password": "Modpass!23", "role": "moderator", "bio": "I'm a moderator"},
            {"username": "admin1@email.com", "password": "Adminpass!23", "role": "admin", "bio": "I'm an administrator"}
        ]

        for user in users:
            user = User(username=user["username"], password=user["password"], role=user["role"], bio=user["bio"])
            db.session.add(user)
            db.session.commit()

    def apply_security_headers(response):
        response.headers["X-Frame-Options"] = "DENY" # clickjacking protection
        response.headers["X-Content-Type-Options"] = "nosniff" # mime sniffling protection
        response.headers["X-XSS-Protection"] = "1; mode=block" # XSS protection
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin" # referrer privacy
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=(), fullscreen=(self), accelerometer=(), autoplay=(), magnetometer=(), gyroscope=(), payment=()" # permissions policy
        response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains; preload" # strict transport security HSTS
        response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self' https://cdn.jsdelivr.net https://cdn.jsdelivr.net/npm/sweetalert2@11 'unsafe-inline'; style-src 'self' https://cdn.jsdelivr.net; img-src 'self' data:; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'; " # content security policy (CSP)
        return response

    return app

