import os

class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "custom_key")
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # session cookie defaults
    SESSION_COOKIE_HTTP = True
    SESSION_COOKIE_SAME_SITE = "Lax"
    SESSION_COOKIE_SECURE = os.getenv("SESSION_COOKIE_SECURE", False) == "True"
    # logging config name
    LOG_FILE = os.environ.get("LOG_FILE", "logs/app.log")

class DevelopConfig(Config):
    DEBUG = True
    TESTING = False
    # using local sqlite dev DB
    SQLALCHEMY_DATABASE_URI = os.environ.get("DEV_DATABASE_URI", "sqlite:///dev.db")

class ProductionConfig(Config):
    DEBUG = False
    TESTING = False
    # provided by environment
    SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URI")
    # require SECRET_KEY and DATABASE_URI be set
    if not SQLALCHEMY_DATABASE_URI:
        raise RuntimeError("DATABASE_URI must be set in production environment")
    if Config.SECRET_KEY == "custom_key":
        raise RuntimeError("SECRET_KEY must be set to a secure value in production")