import logging
import pdfkit
from flask import Blueprint, render_template, request, redirect, url_for, flash, make_response
from flask_login import login_required, current_user
from models import db, User, PatientTestRecord, InventoryItem

logger = logging.getLogger(__name__)
reports_bp = Blueprint("reports", __name__, url_prefix="/reports")


@reports_bp.route("/")
@login_required
def overview():
    """System reports overview page with charts and summaries."""
    if not current_user.has_permission("view_patient_tests") and not current_user.has_permission("manage_inventory"):
        flash("Access denied: You do not have permission to view reports.", "danger")
        return redirect(url_for("dashboard"))

    total_users = User.query.count()
    total_tests = PatientTestRecord.query.count()
    total_inventory = InventoryItem.query.count()

    completed_tests = PatientTestRecord.query.filter_by(test_result="Completed").count()
    pending_tests = PatientTestRecord.query.filter_by(test_result="Pending").count()
    in_progress_tests = PatientTestRecord.query.filter_by(test_result="In Progress").count()

    # ✅ Dynamic stock health summary
    inventory_items = InventoryItem.query.all()
    status_summary = {"Normal": 0, "Low Stock": 0, "Critical": 0}

    for item in inventory_items:
        if item.quantity <= 5:
            status_summary["Critical"] += 1
        elif item.quantity <= 15:
            status_summary["Low Stock"] += 1
        else:
            status_summary["Normal"] += 1

    status_labels = list(status_summary.keys())
    status_counts = list(status_summary.values())

    return render_template(
        "reports.html",
        total_users=total_users,
        total_tests=total_tests,
        total_inventory=total_inventory,
        completed_tests=completed_tests,
        pending_tests=pending_tests,
        in_progress_tests=in_progress_tests,
        status_labels=status_labels,
        status_counts=status_counts,
    )


@reports_bp.route("/download")
@login_required
def download_pdf():
    """Generate and download a PDF version of the report."""
    try:
        total_users = User.query.count()
        total_tests = PatientTestRecord.query.count()
        total_inventory = InventoryItem.query.count()
        completed_tests = PatientTestRecord.query.filter_by(test_result="Completed").count()
        pending_tests = PatientTestRecord.query.filter_by(test_result="Pending").count()
        in_progress_tests = PatientTestRecord.query.filter_by(test_result="In Progress").count()

        inventory_items = InventoryItem.query.all()
        status_summary = {"Normal": 0, "Low Stock": 0, "Critical": 0}

        for item in inventory_items:
            if item.quantity <= 5:
                status_summary["Critical"] += 1
            elif item.quantity <= 15:
                status_summary["Low Stock"] += 1
            else:
                status_summary["Normal"] += 1

        html = render_template(
            "report_pdf.html",
            total_users=total_users,
            total_tests=total_tests,
            total_inventory=total_inventory,
            completed_tests=completed_tests,
            pending_tests=pending_tests,
            in_progress_tests=in_progress_tests,
            status_summary=status_summary,
        )

        pdf = pdfkit.from_string(html, False)
        response = make_response(pdf)
        response.headers["Content-Type"] = "application/pdf"
        response.headers["Content-Disposition"] = "attachment; filename=LabSystem_Report.pdf"
        return response

    except Exception as e:
        logger.exception("Error generating PDF report: %s", e)
        flash("Error generating PDF report.", "danger")
        return redirect(url_for("reports.overview"))


