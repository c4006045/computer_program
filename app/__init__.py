from idlelib.iomenu import errors

from flask import Flask, session, render_template
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import CSRFProtect
from config import Config
import os
import json
import logging
from logging.handlers import RotatingFileHandler
from config import DevelopConfig, ProductionConfig

db = SQLAlchemy()
csrf = CSRFProtect()

def create_app():
    app = Flask(__name__)

    # select config
    env = os.environ.get("APP_ENV", "development").lower()
    if env == "production":
        app.config.from_object(ProductionConfig)
    else:
        app.config.from_object(DevelopConfig)

    # session and cookie security
    app.config['SESSION_COOKIE_HTTP'] = True
    app.config['SESSION_COOKIE_SAME_SITE'] = 'Lax'

    # initialise extensions
    db.init_app(app)
    csrf.init_app(app)

    # import and register routes
    from .routes import main
    app.register_blueprint(main)

    # create DB
    if app.config.get("DEBUG", False):
        with app.app_context():
            from .models import User
            db.create_all()

            # sample users
            users = [
                {"username": "user1@email.com", "password": "Userpass!23", "role": "user", "bio": "I'm a basic user"},
                {"username": "mod1@email.com", "password": "Modpass!23", "role": "moderator", "bio": "I'm a moderator"},
                {"username": "admin1@email.com", "password": "Adminpass!23", "role": "admin", "bio": "I'm an administrator"}
            ]

            for user in users:
                if not User.query.filter_by(username=user["username"]).first():
                    user = User(**user)
                    db.session.add(user)
            db.session.commit()

    @app.after_request
    def apply_security_headers(response): # HTTP security headers
        response.headers["X-Frame-Options"] = "DENY" # clickjacking protection
        response.headers["X-Content-Type-Options"] = "nosniff" # mime sniffling protection
        response.headers["X-XSS-Protection"] = "1; mode=block" # XSS protection
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin" # referrer privacy
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=(), fullscreen=(self), accelerometer=(), autoplay=(), magnetometer=(), gyroscope=(), payment=()" # permissions policy
        if env == "production":
            response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains; preload" # strict transport security HSTS
            response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self' https://cdn.jsdelivr.net https://cdn.jsdelivr.net/npm/sweetalert2@11 'unsafe-inline'; style-src 'self' https://cdn.jsdelivr.net; img-src 'self' data:; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'; " # content security policy (CSP)
        return response

    # create logs directory
    logs_directory = os.path.join(os.path.dirname(__file__), "..", "logs")
    os.makedirs(logs_directory, exist_ok=True)
    logfile = os.path.join(logs_directory, "app.log")

    # configure logger for the app
    app_logger = logging.getLogger("app")
    app_logger.setLevel(logging.INFO)

    # rotating handler: 1MB per file, keep 5 backups as per spec
    handler = RotatingFileHandler(logfile, maxBytes=1_000_000, backupCount=5)
    handler.setFormatter(logging.Formatter("%(message)s"))
    handler.setLevel(logging.INFO)

    # avoid multiple handlers if create_app is called more than once
    if not any(isinstance(h, RotatingFileHandler) and h.baseFilename == handler.baseFilename for h in app_logger.handlers):
        app_logger.addHandler(handler)

    # join flask logger with security logger
    app.logger.handlers = app_logger.handlers
    app.logger.setLevel(app_logger.level)
    app.logger_security = app_logger

    # error handlers
    @app.errorhandler(400)
    def bad_request(e):
        app.logger_security.warning("Bad request")
        return render_template("errors/400.html"), 400

    @app.errorhandler(403)
    def forbidden(e):
        app.logger_security.warning("Forbidden")
        return render_template("errors/403.html"), 403

    @app.errorhandler(404)
    def not_found(e):
        app.logger_security.warning("Not found")
        return render_template("errors/404.html"), 404

    @app.errorhandler(500)
    def server_error(e):
        app.logger_security.exception("Internal server error")
        return render_template("errors/500.html"), 500

    # stops Flask from leaking stack traces to users
    app.config["PROPAGATE_EXCEPTIONS"] = False

    return app

