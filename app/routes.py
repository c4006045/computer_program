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
            flash('Login successful', 'success')
            return redirect(url_for('main.dashboard'))
        else:
            flash('Login invalid, please try again', 'error')

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
    user = User.query.get(session['user_id'])
    if not user:
        session.clear()
        return redirect(url_for('main.login'))

    # sanitise bio
    safe_bio = sanitize_html(user.bio or '')
    return render_template('dashboard.html', username=user.username, bio=safe_bio)

# register
@main.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        username = form.username.data.strip().lower()
        password = form.password.data

        # sanitized default bio content for new users
        bio_clean = sanitize_html("I'm a new user.")[:500]

        # create user and hash password
        new_user = User(username=username, password=password, role='user', bio=bio_clean)
        db.session.add(new_user)
        try:
            db.session.commit()
        except SQLAlchemyError:
            db.session.rollback()
            current_app.logger.exception("Error creating user")
            flash("An error has occurred while creating your account", "danger")
            return render_template('register.html', form=form)

        # successful registration
        flash("Registration complete, please log into your account", "success")
        return redirect(url_for('main.login'))

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
            flash('Current password is incorrect', 'error')
            return render_template('change_password.html', form=form)

        # new password must be different from current
        if user.check_password(new_password):
            flash("New password must be different from old password", "error")
            return render_template('change_password.html', form=form)

        # update password
        user.set_password(new_password)
        db.session.commit()

        # renew session
        session.clear()
        flash("Password updated, please log in again", "success")
        return redirect(url_for('main.login'))

    return render_template('change_password.html', form=form)