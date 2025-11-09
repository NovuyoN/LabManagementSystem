import logging
from functools import wraps
from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_required, current_user
from models import db, InventoryItem

# Initialize logger
logger = logging.getLogger(__name__)

# Define blueprint
inventory_bp = Blueprint("inventory", __name__)

# ---------------- PERMISSION GUARD ---------------- #
def permission_required(permission_name):
    """Decorator to restrict access based on user permissions."""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            if not current_user.is_authenticated:
                flash("Please log in to access this page.", "warning")
                return redirect(url_for("auth.login"))
            if not current_user.has_permission(permission_name):
                flash("Access denied — you don’t have permission for this action.", "danger")
                return redirect(url_for("dashboard"))
            return func(*args, **kwargs)
        return wrapper
    return decorator


# ---------------- VIEW + ADD INVENTORY ---------------- #
@inventory_bp.route("/inventory", methods=["GET", "POST"])
@login_required
@permission_required("view_inventory")
def inventory():
    """View all inventory items and add new ones."""
    search_query = request.args.get("search", "").strip()

    # Filter inventory items
    if search_query:
        items = InventoryItem.query.filter(
            InventoryItem.item_name.ilike(f"%{search_query}%")
        ).all()
    else:
        items = InventoryItem.query.all()

    # Handle adding a new item (requires manage_inventory permission)
    if request.method == "POST":
        if not current_user.has_permission("manage_inventory"):
            flash("You do not have permission to add inventory items.", "danger")
            return redirect(url_for("inventory.inventory"))

        item_name = request.form.get("item_name", "").strip()
        quantity = int(request.form.get("quantity", 0))
        description = request.form.get("description", "").strip()

        if not item_name:
            flash("Item name is required.", "warning")
            return redirect(url_for("inventory.inventory"))

        try:
            new_item = InventoryItem(item_name=item_name, quantity=quantity, description=description)
            db.session.add(new_item)
            db.session.commit()
            flash(f"Item '{item_name}' added successfully.", "success")
            logger.info("Item added: %s (by %s)", item_name, current_user.username)
        except Exception as e:
            db.session.rollback()
            logger.exception("Error adding inventory item: %s", e)
            flash("An error occurred while adding the item.", "danger")

        return redirect(url_for("inventory.inventory"))

    return render_template("inventory.html", items=items)


# ---------------- EDIT INVENTORY ---------------- #
@inventory_bp.route("/inventory/edit/<int:item_id>", methods=["GET", "POST"])
@login_required
@permission_required("manage_inventory")
def edit_inventory(item_id):
    """Edit an existing inventory item."""
    item = InventoryItem.query.get_or_404(item_id)

    if request.method == "POST":
        item.item_name = request.form.get("item_name", "").strip()
        item.quantity = int(request.form.get("quantity", 0))
        item.description = request.form.get("description", "").strip()

        try:
            db.session.commit()
            flash(f"Item '{item.item_name}' updated successfully.", "success")
            logger.info("Item updated: %s (by %s)", item.item_name, current_user.username)
        except Exception as e:
            db.session.rollback()
            logger.exception("Error updating inventory item: %s", e)
            flash("An error occurred while updating the item.", "danger")

        return redirect(url_for("inventory.inventory"))

    return render_template("inventory_edit.html", item=item)


# ---------------- DELETE INVENTORY ---------------- #
@inventory_bp.route("/inventory/delete/<int:item_id>", methods=["POST"])
@login_required
@permission_required("manage_inventory")
def delete_inventory(item_id):
    """Delete an inventory item."""
    item = InventoryItem.query.get_or_404(item_id)

    try:
        db.session.delete(item)
        db.session.commit()
        flash(f"Item '{item.item_name}' deleted successfully.", "info")
        logger.warning("Item deleted: %s (by %s)", item.item_name, current_user.username)
    except Exception as e:
        db.session.rollback()
        logger.exception("Error deleting inventory item: %s", e)
        flash("An error occurred while deleting the item.", "danger")

    return redirect(url_for("inventory.inventory"))

