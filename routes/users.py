
import logging
from functools import wraps
from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_required, current_user
from werkzeug.security import generate_password_hash
from models import db, User, Role

logger = logging.getLogger(__name__)

users_bp = Blueprint("users", __name__, url_prefix="/users")

# -------------------- PERMISSION GUARD -------------------- #
def permission_required(permission_name):
    """Decorator to restrict access based on user permissions."""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            if not current_user.is_authenticated:
                flash("Please log in to access this page.", "warning")
                return redirect(url_for("auth.login"))
            if not current_user.has_permission(permission_name):
                flash("Access denied — you don't have permission to perform this action.", "danger")
                return redirect(url_for("dashboard"))
            return func(*args, **kwargs)
        return wrapper
    return decorator


# -------------------- MANAGE USERS -------------------- #
@users_bp.route("/", methods=["GET", "POST"])
@login_required
@permission_required("manage_users")
def manage_users():
    """View and create users."""
    roles = Role.query.all()

    if request.method == "POST":
        username = request.form.get("username").strip()
        password = request.form.get("password")
        role_name = request.form.get("role")

        if not username or not password or not role_name:
            flash("All fields are required.", "danger")
            return redirect(url_for("users.manage_users"))

        if User.query.filter_by(username=username).first():
            flash("Username already exists.", "warning")
            return redirect(url_for("users.manage_users"))

        role = Role.query.filter(db.func.lower(Role.name) == role_name.lower()).first()
        if not role:
            flash("Invalid role selected.", "danger")
            return redirect(url_for("users.manage_users"))

        new_user = User(username=username, role_id=role.id)
        new_user.set_password(password)

        try:
            db.session.add(new_user)
            db.session.commit()
            flash(f"User '{username}' added successfully!", "success")
            logger.info(f"New user '{username}' added by {current_user.username}")
        except Exception as e:
            db.session.rollback()
            logger.exception("Error adding user: %s", e)
            flash("An error occurred while adding the user.", "danger")

        return redirect(url_for("users.manage_users"))

    users = User.query.all()
    return render_template("users.html", users=users, roles=roles)


# -------------------- EDIT USER -------------------- #
@users_bp.route("/edit/<int:user_id>", methods=["GET", "POST"])
@login_required
@permission_required("manage_users")
def edit_user(user_id):
    """Edit user role or password."""
    user = User.query.get_or_404(user_id)
    roles = Role.query.all()

    if request.method == "POST":
        role_name = request.form.get("role")
        new_password = request.form.get("password")

        role = Role.query.filter(db.func.lower(Role.name) == role_name.lower()).first()
        if role:
            user.role_id = role.id
        if new_password:
            user.set_password(new_password)

        try:
            db.session.commit()
            flash(f"User '{user.username}' updated successfully.", "success")
            logger.info(f"User '{user.username}' updated by {current_user.username}")
        except Exception as e:
            db.session.rollback()
            logger.exception("Error updating user: %s", e)
            flash("An error occurred while updating the user.", "danger")

        return redirect(url_for("users.manage_users"))

    return render_template("edit_user.html", user=user, roles=roles)


# -------------------- DELETE USER -------------------- #
@users_bp.route("/delete/<int:user_id>", methods=["POST"])
@login_required
@permission_required("manage_users")
def delete_user(user_id):
    """Delete a user."""
    user = User.query.get_or_404(user_id)

    try:
        db.session.delete(user)
        db.session.commit()
        flash(f"User '{user.username}' deleted successfully.", "info")
        logger.info(f"User '{user.username}' deleted by {current_user.username}")
    except Exception as e:
        db.session.rollback()
        logger.exception("Error deleting user: %s", e)
        flash("An error occurred while deleting the user.", "danger")

    return redirect(url_for("users.manage_users"))


# ---------------- ADMIN ROLE UPDATE (SECURE) ---------------- #
@users_bp.route("/users/update_role/<int:user_id>", methods=["POST"])
@login_required
def update_role(user_id):
    """Allow admin to update a user's role securely."""
    if not current_user.has_permission("manage_users"):
        flash("Access denied.", "danger")
        return redirect(url_for("dashboard"))

    new_role_name = request.form.get("role", "").strip().lower()
    role_obj = Role.query.filter_by(name=new_role_name).first()
    if not role_obj:
        flash("Invalid role selected.", "danger")
        return redirect(url_for("users.manage_users"))

    user = User.query.get_or_404(user_id)

    # Prevent self-demotion
    if user.id == current_user.id and new_role_name != "admin":
        flash("You cannot change your own role.", "warning")
        return redirect(url_for("users.manage_users"))

    user.role_id = role_obj.id
    db.session.commit()

    flash(f"Role for '{user.username}' updated to '{new_role_name}'.", "success")
    return redirect(url_for("users.manage_users"))


# ---------------- PROFILE + SETTINGS ---------------- #
@users_bp.route("/profile")
@login_required
def profile():
    """Display user profile information."""
    return render_template("profile.html", user=current_user)


@users_bp.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    """Allow user to update password or preferences."""
    if request.method == "POST":
        new_password = request.form.get("new_password", "").strip()
        confirm_password = request.form.get("confirm_password", "").strip()

        if not new_password or not confirm_password:
            flash("Please fill in all fields.", "warning")
        elif new_password != confirm_password:
            flash("Passwords do not match.", "danger")
        elif len(new_password) < 6:
            flash("Password must be at least 6 characters long.", "warning")
        else:
            current_user.password_hash = generate_password_hash(new_password)
            db.session.commit()
            flash("Password updated successfully!", "success")
            return redirect(url_for("users.profile"))

    return render_template("settings.html", user=current_user)
