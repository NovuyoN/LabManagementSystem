import logging
from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_required, current_user
from models import db, TestCategory

logger = logging.getLogger(__name__)
categories_bp = Blueprint("categories", __name__)

# ---------------- VIEW ALL CATEGORIES ---------------- #
@categories_bp.route("/categories", methods=["GET", "POST"])
@login_required
def view_categories():
    """View and add test categories."""
    if not current_user.has_permission("manage_inventory") and not current_user.has_permission("edit_patient_tests"):
        flash("Access denied: You do not have permission to manage test categories.", "danger")
        return redirect(url_for("dashboard"))

    categories = TestCategory.query.order_by(TestCategory.name.asc()).all()

    if request.method == "POST":
        name = request.form.get("name", "").strip()
        if not name:
            flash("Category name cannot be empty.", "warning")
            return redirect(url_for("categories.view_categories"))

        if TestCategory.query.filter_by(name=name).first():
            flash("Category already exists.", "warning")
            return redirect(url_for("categories.view_categories"))

        try:
            new_category = TestCategory(name=name)
            db.session.add(new_category)
            db.session.commit()
            flash(f"Category '{name}' added successfully.", "success")
        except Exception as e:
            db.session.rollback()
            logger.exception("Error adding category: %s", e)
            flash("Error adding category.", "danger")

        return redirect(url_for("categories.view_categories"))

    return render_template("categories.html", categories=categories)

# ---------------- EDIT CATEGORY ---------------- #
@categories_bp.route("/categories/edit/<int:cat_id>", methods=["POST"])
@login_required
def edit_category(cat_id):
    """Edit an existing test category."""
    if not current_user.has_permission("manage_inventory") and not current_user.has_permission("edit_patient_tests"):
        flash("Access denied.", "danger")
        return redirect(url_for("categories.view_categories"))

    category = TestCategory.query.get_or_404(cat_id)
    new_name = request.form.get("name", "").strip()

    if not new_name:
        flash("Category name cannot be empty.", "warning")
        return redirect(url_for("categories.view_categories"))

    try:
        category.name = new_name
        db.session.commit()
        flash(f"Category '{new_name}' updated successfully.", "success")
    except Exception as e:
        db.session.rollback()
        logger.exception("Error editing category: %s", e)
        flash("Error updating category.", "danger")

    return redirect(url_for("categories.view_categories"))

# ---------------- DELETE CATEGORY ---------------- #
@categories_bp.route("/categories/delete/<int:cat_id>", methods=["POST"])
@login_required
def delete_category(cat_id):
    """Delete a test category."""
    if not current_user.has_permission("manage_inventory") and not current_user.has_permission("edit_patient_tests"):
        flash("Access denied.", "danger")
        return redirect(url_for("categories.view_categories"))

    category = TestCategory.query.get_or_404(cat_id)
    try:
        db.session.delete(category)
        db.session.commit()
        flash(f"Category '{category.name}' deleted successfully.", "info")
    except Exception as e:
        db.session.rollback()
        logger.exception("Error deleting category: %s", e)
        flash("Error deleting category.", "danger")

    return redirect(url_for("categories.view_categories"))
