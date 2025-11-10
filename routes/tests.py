import logging
import os
from datetime import datetime
from werkzeug.utils import secure_filename
from flask import Blueprint, render_template, request, redirect, url_for, flash, send_from_directory
from flask_login import login_required, current_user
from models import db, PatientTestRecord, TestCategory, User

# ---------------- CONFIG ---------------- #
logger = logging.getLogger(__name__)
tests_bp = Blueprint("tests", __name__)

UPLOAD_FOLDER = os.path.join("static", "uploads", "requests")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
ALLOWED_EXTENSIONS = {"pdf", "png", "jpg", "jpeg"}


def allowed_file(filename):
    """Check if uploaded file has an allowed extension."""
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


# ---------------- VIEW & ADD TESTS ---------------- #
@tests_bp.route("/tests", methods=["GET", "POST"])
@login_required
def view_tests():
    """View, search, and add patient test records."""
    if not current_user.has_permission("view_patient_tests"):
        flash("Access denied: You do not have permission to view patient tests.", "danger")
        return redirect(url_for("dashboard"))

    search_query = request.args.get("search", "").strip()
    categories = TestCategory.query.order_by(TestCategory.name.asc()).all()

    try:
        # Search tests
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

        # Add new test record
        if request.method == "POST":
            if not current_user.has_permission("add_patient_tests"):
                flash("Access denied: You do not have permission to add tests.", "danger")
                return redirect(url_for("tests.view_tests"))

            patient_name = request.form.get("patient_name", "").strip()
            test_type = request.form.get("test_type", "").strip()
            test_result = request.form.get("test_result", "Pending").strip()
            test_date_str = request.form.get("test_date", "").strip()
            category_id = request.form.get("test_category")
            doctor_name = request.form.get("doctor_name", "").strip()
            doctor_email = request.form.get("doctor_email", "").strip()
            hospital_name = request.form.get("hospital_name", "").strip()

            # Handle file upload (doctor request form)
            file = request.files.get("request_form")
            file_path = None
            if file and allowed_file(file.filename):
                # timestamp the filename to avoid collisions
                base = secure_filename(file.filename)
                name, ext = os.path.splitext(base)
                ts = datetime.utcnow().strftime("%Y%m%d%H%M%S%f")
                final_name = f"{name}_{ts}{ext}"
                saved_path = os.path.join(UPLOAD_FOLDER, final_name)
                file.save(saved_path)
                # Save relative path (under /static/) for templates/route
                file_path = os.path.join("uploads", "requests", final_name)

            if not patient_name or not test_type:
                flash("Patient name and test type are required.", "warning")
                return redirect(url_for("tests.view_tests"))

            try:
                test_date = (
                    datetime.strptime(test_date_str, "%Y-%m-%d").date()
                    if test_date_str
                    else datetime.now().date()
                )
            except ValueError:
                test_date = datetime.now().date()

            new_test = PatientTestRecord(
                patient_name=patient_name,
                test_type=test_type,
                test_result=test_result,
                test_date=test_date,
                test_category_id=int(category_id) if category_id else None,
                doctor_name=doctor_name,
                doctor_email=doctor_email,
                hospital_name=hospital_name,
                recorded_by=current_user.id,
                request_form_path=file_path,
                status="entered",
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

    return render_template("tests.html", tests=tests, categories=categories)


# ---------------- VERIFY TEST ---------------- #
@tests_bp.route("/tests/verify/<int:test_id>", methods=["POST"])
@login_required
def verify_test(test_id):
    """Allow supervisors/managers to verify a test record."""
    if not current_user.has_permission("edit_patient_tests"):
        flash("Access denied: You do not have permission to verify tests.", "danger")
        return redirect(url_for("tests.view_tests"))

    test = PatientTestRecord.query.get_or_404(test_id)

    if test.recorded_by == current_user.id:
        flash("You cannot verify your own test result.", "warning")
        return redirect(url_for("tests.view_tests"))

    try:
        notes = request.form.get("verified_notes", "").strip()
        test.mark_verified(current_user, notes)
        db.session.commit()
        flash(f"Test for '{test.patient_name}' verified successfully.", "success")
        logger.info("Test verified: %s by %s", test.patient_name, current_user.username)
    except Exception as e:
        db.session.rollback()
        logger.exception("Error verifying test: %s", e)
        flash("An error occurred while verifying the test record.", "danger")

    return redirect(url_for("tests.view_tests"))


# ---------------- MARK TEST AS REPORTED ---------------- #
@tests_bp.route("/tests/report/<int:test_id>", methods=["POST"])
@login_required
def mark_test_reported(test_id):
    """Mark a verified test as reported (final step)."""
    if not current_user.has_permission("edit_patient_tests"):
        flash("Access denied: You do not have permission to mark reports.", "danger")
        return redirect(url_for("tests.view_tests"))

    test = PatientTestRecord.query.get_or_404(test_id)

    if not test.is_verified:
        flash("Test must be verified before reporting.", "warning")
        return redirect(url_for("tests.view_tests"))

    try:
        test.status = "reported"
        db.session.commit()
        flash(f"Report for '{test.patient_name}' marked as completed.", "success")
        logger.info("Report finalized for %s by %s", test.patient_name, current_user.username)
    except Exception as e:
        db.session.rollback()
        logger.exception("Error marking report: %s", e)
        flash("An error occurred while marking the report.", "danger")

    return redirect(url_for("tests.view_tests"))


# ---------------- EDIT TEST ---------------- #
@tests_bp.route("/tests/edit/<int:test_id>", methods=["GET", "POST"])
@login_required
def edit_test(test_id):
    """Edit a test record."""
    if not current_user.has_permission("edit_patient_tests"):
        flash("Access denied: You do not have permission to edit test records.", "danger")
        return redirect(url_for("tests.view_tests"))

    test = PatientTestRecord.query.get_or_404(test_id)
    categories = TestCategory.query.order_by(TestCategory.name.asc()).all()

    if request.method == "POST":
        try:
            test.patient_name = request.form.get("patient_name", "").strip()
            test.test_type = request.form.get("test_type", "").strip()
            test.test_result = request.form.get("test_result", "Pending").strip()
            test.doctor_name = request.form.get("doctor_name", "").strip()
            test.doctor_email = request.form.get("doctor_email", "").strip()
            test.hospital_name = request.form.get("hospital_name", "").strip()

            cat_id = request.form.get("test_category_id")
            test.test_category_id = int(cat_id) if cat_id else None

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

    return render_template("tests_edit.html", test=test, categories=categories)


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


# ---------------- VIEW / DOWNLOAD REQUEST FORM ---------------- #
@tests_bp.route("/tests/request-form/<path:filename>")
@login_required
def view_request_form(filename):
    """Allow viewing or downloading uploaded doctor request forms."""
    uploads_dir = os.path.join("static", "uploads", "requests")
    file_path = os.path.join(uploads_dir, filename)

    if not os.path.exists(file_path):
        flash("Requested file not found.", "warning")
        return redirect(url_for("tests.view_tests"))

    try:
        # Display in browser where possible (PDF/images) — change to as_attachment=True to force download
        return send_from_directory(uploads_dir, filename, as_attachment=False)
    except Exception as e:
        logger.exception("Error serving request form: %s", e)
        flash("Unable to open the requested file.", "danger")
        return redirect(url_for("tests.view_tests"))




