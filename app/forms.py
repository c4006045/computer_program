from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, TextAreaField, SubmitField
from wtforms.validators import DataRequired, Email, Length, Optional, EqualTo, ValidationError
from flask import current_app
from app.models import User

def username_not_taken(form, field):
    if User.query.filter(User.username.ilike(field.data.strip())).first():
        raise ValidationError("An account with that email already exists.")

class RegisterForm(FlaskForm):
    username = StringField("Email", validators=[DataRequired(), Email(message="Enter a valid email address."), Length(max=320), username_not_taken])
    password = PasswordField("Password", validators=[DataRequired(), Length(min=8, max=128)])
    confirm = PasswordField("Confirm Password", validators=[DataRequired(), EqualTo('password', message='Passwords must match.')])
    bio = TextAreaField("Bio", validators=[Optional(), Length(max=2000)])
    submit = SubmitField("Register")

class LoginForm(FlaskForm):
    username = StringField("Email", validators=[DataRequired(), Email(), Length(max=320)])
    password = PasswordField("Password", validators=[DataRequired(), Length(min=8)])
    submit = SubmitField("Login")

class ChangePasswordForm(FlaskForm):
    current_password = PasswordField("Current password", validators=[DataRequired()])
    new_password = PasswordField("New password", validators=[DataRequired(), Length(min=8)])
    confirm = PasswordField("Confirm new password", validators=[DataRequired(), EqualTo('new_password', message='Passwords must match')])
    submit = SubmitField("Change password")
