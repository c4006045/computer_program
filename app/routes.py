import traceback
from flask import request, render_template, redirect, url_for, session, Blueprint, flash, abort, current_app
from sqlalchemy import text
from app import db
from app.models import User
from app.forms import RegisterForm, LoginForm, ChangePasswordForm
from app.utils.sanitizer import sanitize_html
from werkzeug.security import generate_password_hash, check_password_hash

main = Blueprint('main', __name__)

@main.route('/')
def home():
    return render_template('home.html')

@main.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data.strip().lower()
        password = form.password.data
        user = User.query.filter(User.username.ilike(username)).first()

        if user and user.check_password(password):
            session.clear()
            session['user_id'] = user.id
            session['user'] = user.username
            session['role'] = user.role
            flash('Login successful', 'success')
            return redirect(url_for('main.dashboard'))
        else:
            flash('Login credentials are invalid, please try again', 'danger')
    return render_template('login.html', form=form)


@main.route('/dashboard')
def dashboard():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        if not user:
            session.clear()
            return redirect(url_for('main.login'))
        # sanitize at render-time as defence-in-depth
        safe_bio = sanitize_html(user.bio or '')
        return render_template('dashboard.html', username=user.username, bio=safe_bio)
    return redirect(url_for('main.login'))

@main.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        username = form.username.data.strip().lower()
        password = form.password.data
        bio = form.bio.data or ''
        # Always set role server-side
        role = 'user'

        # sanitize bio before storing
        bio_clean = sanitize_html(bio)
        # truncate to MAX_BIO_LENGTH to be safe
        max_bio = current_app.config.get('MAX_BIO_LENGTH', 2000)
        if len(bio_clean) > max_bio:
            bio_clean = bio_clean[:max_bio]

        new_user = User(username=username, password=password, role=role, bio=bio_clean)
        db.session.add(new_user)
        try:
            db.session.commit()
        except Exception:
            db.session.rollback()
            current_app.logger.exception("Error creating user")
            flash('An error occurred while creating your account. Please try again.', 'danger')
            return render_template('register.html', form=form)
        flash('Registration complete. Please log in.', 'success')
        return redirect(url_for('main.login'))
    return render_template('register.html', form=form)


def require_role(required_role):
    def decorator(fn):
        def wrapper(*args, **kwargs):
            if session.get('role') != required_role:
                abort(403, description="Access denied.")
            return fn(*args, **kwargs)

        wrapper.__name__ = fn.__name__
        return wrapper

    return decorator

@main.route('/admin-panel')
@require_role('admin')
def admin():
    return render_template('admin.html')

@main.route('/moderator')
@require_role('moderator')
def moderator():
    return render_template('moderator.html')

@main.route('/user-dashboard')
@require_role('user')
def user_dashboard():
    if 'user_id' not in session:
        return redirect(url_for('main.login'))
    user = User.query.get(session['user_id'])
    if not user:
        session.clear()
        return redirect(url_for('main.login'))
    return render_template('user_dashboard.html', username=user.username)

@main.route('/change-password', methods=['GET', 'POST'])
def change_password():
    if 'user_id' not in session:
        abort(403, description="Access denied.")
    user = User.query.get(session['user_id'])
    if not user:
        session.clear()
        abort(403, description="Access denied.")

    form = ChangePasswordForm()
    if form.validate_on_submit():
        current_password = form.current_password.data
        new_password = form.new_password.data

        if not user.check_password(current_password):
            flash('Current password is incorrect', 'error')
            return render_template('change_password.html', form=form)

        if current_password == new_password:
            flash('New password must be different from the current password', 'error')
            return render_template('change_password.html', form=form)

        user.set_password(new_password)
        db.session.add(user)
        db.session.commit()

        flash('Password changed successfully', 'success')
        return redirect(url_for('main.dashboard'))
    return render_template('change_password.html', form=form)