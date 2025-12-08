import traceback
from functools import wraps

from flask import request, render_template, redirect, url_for, session, Blueprint, flash, abort, current_app
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from app import db
from app.models import User
from app.forms import RegisterForm, LoginForm, ChangePasswordForm
from app.utils.sanitizer import sanitize_html
from werkzeug.security import generate_password_hash, check_password_hash
from app.utils.audit import log_event


main = Blueprint('main', __name__)

# makes sure user is logged in to access the route
def login_required(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if "user_id" not in session:
            flash("You need to login first", "error")
            return redirect(url_for("main.login"))
        return f(*args, **kwargs)
    return wrap

# makes sure user has a role, matches role to route
def roles_required(role):
    def decorator(f):
        @wraps(f)
        def wrap(*args, **kwargs):
            if "user_id" not in session: # ensures user is logged in
                flash("You need to login first", "error")
                return redirect(url_for("main.login"))
            user = User.query.get(session["user_id"])
            if not user or user.role != role: # checks user exists and has correct role
                # log access violation
                log_event("access_denied", level="WARNING", user_id=(user.id if user else None), username=(user.username if user else None), details={"required_role": role, "attempted_role": user.role if user else None})
                abort(403, description=f"User {user.username} is not authorized to access this page")
            return f(*args, **kwargs)
        return wrap
    return decorator

# protects against characters that have meaning in SQL LIKE queries
def escape_like(value: str) -> str:
    if not value:
        return value
    value = value.replace("\\", "\\\\")
    value = value.replace("%", "\\%")
    value = value.replace("_", "\\_")
    return value

@main.route('/')
def home():
    return render_template('home.html')

# login
@main.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        username_raw = form.username.data.strip().lower()
        username_safe = escape_like(username_raw)

        user = (User.query.filter(User.username.ilike(f"{username_safe}", escape="\\")).first())

        if user and user.check_password(form.password.data):
            session.clear()
            # new session
            session['user_id'] = user.id
            session['user'] = user.username
            session['role'] = user.role
            session['bio'] = user.bio
            session.permanent = True
            log_event("user_login_success", level="INFO", user_id=user.id, username=user.username)
            flash('Login successful', 'success')
            return redirect(url_for('main.dashboard'))
        else:
            # log failed login attempt
            log_event("user_login_failed", level="WARNING", user_id=(user.id if user else None), username=(user.username if user else form.username.data), details={"reason": "invalid_credentials"})
            flash("One of either the username or password is incorrect, please log in again", "error")

    return render_template('login.html', form=form)

# logout
@main.route('/logout')
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for('main.home'))

# dashboard
@main.route('/dashboard')
@login_required # must be logged in
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('main.login'))

    user = User.query.get(session['user_id'])
    if not user:
        session.clear()
        return redirect(url_for('main.login'))

    # decrypt and sanitize bio
    decrypted_bio = user.decrypt_bio()
    safe_bio = sanitize_html(decrypted_bio)

    return render_template('dashboard.html', username=user.username, bio=safe_bio)

# register
@main.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        username = form.username.data.strip().lower()
        password = form.password.data

        # default bio content for new users
        default_bio = "I'm a new user."

        # create user and hash password
        new_user = User(username=username, password=password, role='user', bio=default_bio)
        db.session.add(new_user)
        try:
            db.session.commit()
            # log successful registration
            log_event("user_registration_success", level="INFO", username=username)
        except SQLAlchemyError:
            db.session.rollback()
            current_app.logger.exception("Error creating user")
            # log failure
            log_event("user_registration_failed", level="ERROR", username=username, details={"reason": "db_error"})
            flash("An error has occurred while creating your account", "danger")
            return render_template('register.html', form=form)

        # successful registration
        log_event("user_registration_success", level="INFO", username=username)
        flash("Registration complete, please log into your account", "success")
        return redirect(url_for('main.login'))

    if request.method == "POST" and not form.validate_on_submit():
        errors = {
            field.name: field.errors
            for field in form
            if field.errors and field.name != "password"
        }
        if errors:
            log_event("form_validation_failed", level="WARNING", details={"form": "login", "errors": errors})

    return render_template('register.html', form=form)

# roles
@main.route('/admin-panel')
@roles_required('admin') # access for admins only
def admin():
    return render_template('admin.html')

@main.route('/moderator')
@roles_required('moderator') # access for moderators only
def moderator():
    return render_template('moderator.html')

@main.route('/user-dashboard')
@roles_required('admin') # access for admins only
def user_dashboard():
    user = User.query.get(session['user_id'])
    if not user:
        session.clear()
        return redirect(url_for('main.login'))

    return render_template('user_dashboard.html', username=user.username)

# change password
@main.route('/change-password', methods=['GET', 'POST'])
@login_required # must be logged in
def change_password():
    user = User.query.get(session['user_id'])
    if not user:
        session.clear()
        abort(403, description="Access denied")

    form = ChangePasswordForm()

    if form.validate_on_submit():
        current_password = form.current_password.data
        new_password = form.new_password.data

        # check if password is correct
        if not user.check_password(current_password):
            log_event("password_change_failed", level="WARNING", user_id=user.id, username=user.username, details={"reason": "incorrect_current_password"})
            flash('Current password is incorrect', 'error')
            return render_template('change_password.html', form=form)

        # new password must be different from current
        if user.check_password(new_password):
            flash("New password must be different from old password", "error")
            return render_template('change_password.html', form=form)

        # update password
        user.set_password(new_password)
        db.session.commit()
        log_event("password_changed", level="INFO", user_id=user.id, username=user.username)

        # renew session
        session.clear()
        flash("Password updated, please log in again", "success")
        return redirect(url_for('main.login'))

    if request.method == "POST" and not form.validate_on_submit():
        errors = {
            field.name: field.errors
            for field in form
            if field.errors and field.name not in {"current_password", "new_password"}
        }
        if errors:
            log_event("form_validation_failed", level="WARNING", user_id=user.id, username=user.username, details={"form": "change_password", "errors": errors})

    return render_template('change_password.html', form=form)