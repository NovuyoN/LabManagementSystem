import logging
from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_user, logout_user, login_required, current_user
from models import db, User, Role
from forms import RegistrationForm, LoginForm

logger = logging.getLogger(__name__)

auth_bp = Blueprint("auth", __name__)

# ---------------- LOGIN ---------------- #
@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    """User login route."""
    form = LoginForm()

    # Redirect already logged-in users straight to dashboard
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    if form.validate_on_submit():
        username = form.username.data.strip()
        password = form.password.data

        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            login_user(user)
            logger.info(f"✅ User logged in: {username}")
            flash("Logged in successfully!", "success")
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid username or password.", "danger")
            logger.warning(f"❌ Failed login attempt for username: {username}")

    elif request.method == "POST":
        # Show form field-specific errors
        for field, errors in form.errors.items():
            for error in errors:
                flash(f"{getattr(form, field).label.text}: {error}", "danger")

    return render_template("login.html", form=form)


# ---------------- LOGOUT ---------------- #
@auth_bp.route("/logout")
@login_required
def logout():
    """Logs the user out and redirects to home."""
    username = getattr(current_user, "username", "<unknown>")
    logout_user()
    logger.info(f"👋 User logged out: {username}")
    flash("You have been logged out successfully.", "info")
    return redirect(url_for("home"))


# ---------------- REGISTER ---------------- #
@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    """User registration route (public) — defaults to 'receptionist'."""
    form = RegistrationForm()

    # Redirect logged-in users away from register page
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    if form.validate_on_submit():
        username = form.username.data.strip()
        password = form.password.data

        # Check for duplicate usernames
        if User.query.filter_by(username=username).first():
            flash("Username already exists. Choose another one.", "danger")
            return render_template("register.html", form=form)

        # Default role = receptionist
        role_obj = Role.query.filter_by(name="receptionist").first()
        if not role_obj:
            flash("System setup error: default role not found.", "danger")
            return render_template("register.html", form=form)

        new_user = User(username=username, role_id=role_obj.id)
        new_user.set_password(password)

        try:
            db.session.add(new_user)
            db.session.commit()
            flash("Registration successful — you can now log in!", "success")
            logger.info(f"🆕 New user registered: {username}")
            return redirect(url_for("auth.login"))
        except Exception as e:
            db.session.rollback()
            logger.exception(f"⚠️ Error creating user: {e}")
            flash("An error occurred during registration. Try again.", "danger")

    elif request.method == "POST":
        for field, errors in form.errors.items():
            for error in errors:
                flash(f"{getattr(form, field).label.text}: {error}", "danger")

    return render_template("register.html", form=form)
