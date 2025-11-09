import logging
from datetime import datetime
from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_required, current_user
from models import db, PatientTestRecord

logger = logging.getLogger(__name__)
tests_bp = Blueprint("tests", __name__)

# ---------------- VIEW & ADD TESTS ---------------- #
@tests_bp.route("/tests", methods=["GET", "POST"])
@login_required
def view_tests():
    """View and add patient test records."""
    # Permission: must have 'view_patient_tests'
    if not current_user.has_permission("view_patient_tests"):
        flash("Access denied: You do not have permission to view patient tests.", "danger")
        return redirect(url_for("dashboard"))

    search_query = request.args.get("search", "").strip()

    try:
        # Handle search
        if search_query:
            tests = (
                PatientTestRecord.query.filter(
                    PatientTestRecord.patient_name.ilike(f"%{search_query}%")
                )
                .order_by(PatientTestRecord.test_date.desc())
                .all()
            )
        else:
            tests = PatientTestRecord.query.order_by(
                PatientTestRecord.test_date.desc()
            ).all()

        # Handle adding new test (requires add permission)
        if request.method == "POST":
            if not current_user.has_permission("add_patient_tests"):
                flash("Access denied: You do not have permission to add tests.", "danger")
                return redirect(url_for("tests.view_tests"))

            patient_name = request.form.get("patient_name", "").strip()
            test_type = request.form.get("test_type", "").strip()
            test_result = request.form.get("test_result", "Pending").strip()
            test_date_str = request.form.get("test_date", "").strip()

            if not patient_name or not test_type:
                flash("Patient name and test type are required.", "warning")
                return redirect(url_for("tests.view_tests"))

            try:
                test_date = datetime.strptime(test_date_str, "%Y-%m-%d").date() if test_date_str else datetime.now().date()
            except ValueError:
                test_date = datetime.now().date()

            new_test = PatientTestRecord(
                patient_name=patient_name,
                test_type=test_type,
                test_result=test_result,
                test_date=test_date,
                recorded_by=current_user.id,
            )

            db.session.add(new_test)
            db.session.commit()
            flash(f"Test for '{patient_name}' added successfully.", "success")
            logger.info("New test added: %s by %s", patient_name, current_user.username)
            return redirect(url_for("tests.view_tests"))

    except Exception as e:
        db.session.rollback()
        logger.exception("Error in view_tests: %s", e)
        flash("An error occurred while processing tests.", "danger")

    return render_template("tests.html", tests=tests)


# ---------------- EDIT TEST ---------------- #
@tests_bp.route("/tests/edit/<int:test_id>", methods=["GET", "POST"])
@login_required
def edit_test(test_id):
    """Edit a test record."""
    if not current_user.has_permission("edit_patient_tests"):
        flash("Access denied: You do not have permission to edit test records.", "danger")
        return redirect(url_for("tests.view_tests"))

    test = PatientTestRecord.query.get_or_404(test_id)

    if request.method == "POST":
        try:
            test.patient_name = request.form.get("patient_name", "").strip()
            test.test_type = request.form.get("test_type", "").strip()
            test.test_result = request.form.get("test_result", "Pending").strip()

            test_date_str = request.form.get("test_date", "")
            if test_date_str:
                try:
                    test.test_date = datetime.strptime(test_date_str, "%Y-%m-%d").date()
                except ValueError:
                    flash("Invalid date format. Use YYYY-MM-DD.", "warning")

            db.session.commit()
            flash(f"Test record for '{test.patient_name}' updated successfully.", "success")
            logger.info("Test updated: %s (by %s)", test.patient_name, current_user.username)
            return redirect(url_for("tests.view_tests"))
        except Exception as e:
            db.session.rollback()
            logger.exception("Error editing test: %s", e)
            flash("An error occurred while updating the test record.", "danger")

    return render_template("tests_edit.html", test=test)


# ---------------- DELETE TEST ---------------- #
@tests_bp.route("/tests/delete/<int:test_id>", methods=["POST"])
@login_required
def delete_test(test_id):
    """Delete a test record."""
    if not current_user.has_permission("delete_patient_tests"):
        flash("Access denied: You do not have permission to delete test records.", "danger")
        return redirect(url_for("tests.view_tests"))

    test = PatientTestRecord.query.get_or_404(test_id)

    try:
        db.session.delete(test)
        db.session.commit()
        flash(f"Test for '{test.patient_name}' deleted successfully.", "info")
        logger.warning("Test deleted: %s (by %s)", test.patient_name, current_user.username)
    except Exception as e:
        db.session.rollback()
        logger.exception("Error deleting test: %s", e)
        flash("An error occurred while deleting the test record.", "danger")

    return redirect(url_for("tests.view_tests"))

