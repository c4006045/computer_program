from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, TextAreaField, SubmitField
from wtforms.validators import DataRequired, Email, Length, Optional, EqualTo, ValidationError
from flask import current_app
from app.models import User
import re

# if username with the email exists already, raise error
def username_not_taken(form, field):
    username = field.data.strip()
    # protection against edge cases
    sanitized = username.replace("%", r"\%").replace("_", r"\_")
    user_exists = User.query.filter(User.username.ilike(sanitized)).first()
    if user_exists:
        raise ValidationError("An account with this email already exists")

# blacklist given in spec
password_blacklist = {"Password123$", "Qwerty123!", "Adminadmin1@", "weLcome123!"}

# validates password
def password_validation(form, field):
    password = field.data
    username = form.username.data if hasattr(form, "username") else ""

    # password rules in part B
    if len(password) < 10:
        raise ValidationError("Password must be at least 10 characters long")
    if not re.search(r"[A-Z]", field.data):
        raise ValidationError("Password must contain at least 1 uppercase letter")
    if not re.search(r"[0-9]", field.data):
        raise ValidationError("Password must contain at least 1 digit")
    if not re.search(r"[^\w\s]", field.data):
        raise ValidationError("Password must contain at least 1 special character")
    if username and username.lower() in password.lower():
        raise ValidationError("Password must not contain your username.")
    if re.search(r"(.)\1\1", password):
        raise ValidationError("Password must not contain repeated repeated sequences (e.g., 'aaa')")
    if password in password_blacklist:
        raise ValidationError("This password is not allowed")

# registration form
class RegisterForm(FlaskForm):
    username = StringField("Email", validators=[DataRequired(), Email(message="Enter a valid email address"), Length(max=320), username_not_taken])
    password = PasswordField("Password", validators=[DataRequired(), Length(min=10, max=128), password_validation])
    confirm = PasswordField("Confirm Password", validators=[DataRequired(), EqualTo('password', message='Passwords must match')])
    bio = TextAreaField("Bio", validators=[Optional(), Length(max=2000)])
    submit = SubmitField("Register")

# login form
class LoginForm(FlaskForm):
    username = StringField("Email", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Login")

# change password form
class ChangePasswordForm(FlaskForm):
    current_password = PasswordField("Current password", validators=[DataRequired()])
    new_password = PasswordField("New password", validators=[DataRequired(), Length(min=10), password_validation])
    confirm = PasswordField("Confirm new password", validators=[DataRequired(), EqualTo('new_password', message='Passwords must match')])
    submit = SubmitField("Change password")
