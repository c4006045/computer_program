import traceback
from flask import request, render_template, redirect, url_for, session, Blueprint, flash, abort, current_app
from sqlalchemy import text
from sqlalchemy.sql.functions import user

from app import db
from app.models import User
from app.forms import RegisterForm, LoginForm, ChangePasswordForm
from app.utils.sanitizer import sanitize_html
from werkzeug.security import generate_password_hash, check_password_hash

main = Blueprint('main', __name__)

@main.route('/')
def home():
    return render_template('home.html')

# login
@main.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        username = form.username.data.strip().lower()
        password = form.password.data
        user = User.query.filter(User.username.ilike(username)).first()

        if user and user.check_password(password):
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
def dashboard():
    if 'user' not in session:
        return redirect(url_for('main.login'))
    return render_template('dashboard.html', username=session['user'], bio=session['bio'])

# register
@main.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        username = form.username.data
        password = generate_password_hash(form.password.data)

        user = User(username=username, password=password, role="user", bio="New user")
        db.session.add(user)
        db.session.commit()

        flash("Registration successful.", "success")
        return redirect(url_for('main.login'))

    return render_template('register.html', form=form)

# roles
@main.route('/admin-panel')
def admin():
    return render_template('admin.html')

@main.route('/moderator')
def moderator():
    return render_template('moderator.html')

@main.route('/user-dashboard')
def user_dashboard():
    if 'user_id' not in session:
        return redirect(url_for('main.login'))
    user = User.query.get(session['user_id'])
    if not user:
        session.clear()
        return redirect(url_for('main.login'))
    return render_template('user_dashboard.html', username=user.username)

# change password
@main.route('/change-password', methods=['GET', 'POST'])
def change_password():
    if 'user' not in session:
        abort(403, description="Access denied.")

    form = ChangePasswordForm()
    if form.validate_on_submit():
        current_password = form.current_password.data
        new_password = form.new_password.data

        # check if password is correct
        if not check_password_hash(user.password, current_password):
            flash('Current password is incorrect', 'error')
            return render_template('change_password.html', form=form)

        # new password must be different from current
        if check_password_hash(user.password, new_password):
            flash("New password must be different from old password.", "error")
            return render_template('change_password.html', form=form)

        # update password
        user.password = generate_password_hash(new_password)
        db.session.commit()

        # renew session
        session.clear()
        flash("Password updated. Please log in again.", "success")
        return redirect(url_for('main.login'))

    return render_template('change_password.html', form=form)