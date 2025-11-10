import logging
from datetime import date, timedelta
from functools import wraps

from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_required, current_user

from models import db, InventoryItem

logger = logging.getLogger(__name__)
inventory_bp = Blueprint("inventory", __name__)

# ---------------- HELPER: PERMISSION CHECK ---------------- #
def require_manage_inventory():
    if not current_user.has_permission("manage_inventory"):
        flash("You do not have permission to manage inventory.", "danger")
        return False
    return True

# ---------------- STATUS COMPUTATION ---------------- #
def compute_status(item: InventoryItem) -> str:
    """
    Determines item status based on expiry and stock levels.
    Order of precedence:
      1) Expired
      2) Expiring Soon (<=14 days)
      3) Out of Stock (<=0)
      4) Low Stock (quantity < min_threshold)
      5) In Stock
    """
    today = date.today()

    # 1) Expired
    if item.expiry_date and item.expiry_date < today:
        return "Expired"

    # 2) Expiring Soon
    if item.expiry_date and (item.expiry_date - today) <= timedelta(days=14):
        return "Expiring Soon"

    # 3) Out of Stock
    if (item.quantity or 0) <= 0:
        return "Out of Stock"

    # 4) Low Stock
    if item.min_threshold is not None and item.quantity < item.min_threshold:
        return "Low Stock"

    # 5) In Stock
    return "In Stock"


# ---------------- VIEW + ADD INVENTORY ---------------- #
@inventory_bp.route("/inventory", methods=["GET", "POST"])
@login_required
def inventory():
    """
    View all inventory items, filter/search, and add new ones.
    POST requires manage_inventory permission; GET is visible to any logged-in user.
    """
    search_query = request.args.get("search", "").strip()

    # Filtering
    q = InventoryItem.query
    if search_query:
        like = f"%{search_query}%"
        q = q.filter(
            db.or_(
                InventoryItem.item_name.ilike(like),
                InventoryItem.category.ilike(like),
                InventoryItem.unit.ilike(like),
            )
        )
    items = q.order_by(InventoryItem.item_name.asc()).all()

    # Compute statuses for display
    statuses = {item.id: compute_status(item) for item in items}

    # Alert banners (low stock + expiring soon)
    today = date.today()
    expiring_soon_items = [
        i for i in items
        if i.expiry_date and i.expiry_date >= today and (i.expiry_date - today).days <= 14
    ]
    expired_items = [i for i in items if i.expiry_date and i.expiry_date < today]
    low_stock_items = [
        i for i in items
        if i.min_threshold is not None and i.quantity is not None and i.quantity < i.min_threshold
    ]
    out_of_stock_items = [i for i in items if (i.quantity or 0) <= 0]

    if request.method == "POST":
        if not require_manage_inventory():
            return redirect(url_for("inventory.inventory"))

        try:
            item_name = request.form.get("item_name", "").strip()
            category = request.form.get("category", "").strip()
            unit = request.form.get("unit", "").strip()
            quantity = int(request.form.get("quantity", 0) or 0)
            min_threshold = int(request.form.get("min_threshold", 0) or 0)

            expiry_str = request.form.get("expiry_date", "").strip()
            expiry_date = None
            if expiry_str:
                try:
                    expiry_date = date.fromisoformat(expiry_str)
                except ValueError:
                    flash("Invalid expiry date. Use YYYY-MM-DD.", "warning")

            if not item_name:
                flash("Item name is required.", "warning")
                return redirect(url_for("inventory.inventory"))

            new_item = InventoryItem(
                item_name=item_name,
                category=category or "General",
                unit=unit or "units",
                quantity=quantity,
                min_threshold=min_threshold,
                expiry_date=expiry_date,
            )
            db.session.add(new_item)
            db.session.commit()
            flash(f"Item '{item_name}' added successfully.", "success")
            logger.info("Item added: %s (by %s)", item_name, current_user.username)
            return redirect(url_for("inventory.inventory"))

        except Exception as e:
            db.session.rollback()
            logger.exception("Error adding inventory item: %s", e)
            flash("An error occurred while adding the item.", "danger")

    return render_template(
        "inventory.html",
        items=items,
        statuses=statuses,
        expiring_soon_items=expiring_soon_items,
        expired_items=expired_items,
        low_stock_items=low_stock_items,
        out_of_stock_items=out_of_stock_items,
    )


# ---------------- EDIT INVENTORY ---------------- #
@inventory_bp.route("/inventory/edit/<int:item_id>", methods=["GET", "POST"])
@login_required
def edit_inventory(item_id):
    """Edit an existing inventory item (manage_inventory required)."""
    if not require_manage_inventory():
        return redirect(url_for("inventory.inventory"))

    item = InventoryItem.query.get_or_404(item_id)

    if request.method == "POST":
        try:
            item.item_name = request.form.get("item_name", "").strip()
            item.category = request.form.get("category", "").strip() or "General"
            item.unit = request.form.get("unit", "").strip() or "units"
            item.quantity = int(request.form.get("quantity", 0) or 0)
            item.min_threshold = int(request.form.get("min_threshold", 0) or 0)

            expiry_str = request.form.get("expiry_date", "").strip()
            item.expiry_date = None
            if expiry_str:
                try:
                    item.expiry_date = date.fromisoformat(expiry_str)
                except ValueError:
                    flash("Invalid expiry date. Use YYYY-MM-DD.", "warning")

            db.session.commit()
            flash(f"Item '{item.item_name}' updated successfully.", "success")
            logger.info("Item updated: %s (by %s)", item.item_name, current_user.username)
            return redirect(url_for("inventory.inventory"))

        except Exception as e:
            db.session.rollback()
            logger.exception("Error updating inventory item: %s", e)
            flash("An error occurred while updating the item.", "danger")

    current_status = compute_status(item)
    return render_template("inventory_edit.html", item=item, status=current_status)


# ---------------- DELETE INVENTORY ---------------- #
@inventory_bp.route("/inventory/delete/<int:item_id>", methods=["POST"])
@login_required
def delete_inventory(item_id):
    """Delete an inventory item (manage_inventory required)."""
    if not require_manage_inventory():
        return redirect(url_for("inventory.inventory"))

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


