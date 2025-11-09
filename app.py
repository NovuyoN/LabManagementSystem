import os
from flask import Flask, redirect, url_for, render_template
from dotenv import load_dotenv, find_dotenv
from flask_login import LoginManager, login_required, current_user
from flask_migrate import Migrate
from datetime import datetime
from werkzeug.security import generate_password_hash

# ------------------- Load environment variables -------------------
env_path = find_dotenv()
if env_path:
    load_dotenv(env_path)
else:
    print("Warning: .env file not found!")


def create_app():
    print("DEBUG >>> entered create_app")

    # ------------------- Import models and blueprints -------------------
    from models import db, bcrypt, User, Role, Permission, PatientTestRecord, InventoryItem, TestCategory
    from routes.auth import auth_bp
    from routes.inventory import inventory_bp
    from routes.users import users_bp
    from routes.tests import tests_bp

    print("DEBUG >>> models and blueprints imported")

    # ------------------- Initialize Flask app -------------------
    app = Flask(__name__, template_folder="templates")
    print("DEBUG >>> Flask app created")

    # ------------------- Database setup -------------------
    DATABASE_URL = os.getenv("DATABASE_URL")
    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL not set in environment!")

    print("DEBUG >>> DATABASE_URL =", DATABASE_URL)

    app.config["SQLALCHEMY_DATABASE_URI"] = DATABASE_URL
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "dev_secret_key")
    print("DEBUG >>> Config set")

    # ------------------- Initialize extensions -------------------
    db.init_app(app)
    bcrypt.init_app(app)
    migrate = Migrate(app, db)
    print("DEBUG >>> Extensions initialized")

    # ------------------- Flask-Login setup -------------------
    login_manager = LoginManager()
    login_manager.init_app(app)
    login_manager.login_view = "auth.login"
    login_manager.login_message_category = "warning"

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    # ------------------- Blueprint registration -------------------
    app.register_blueprint(auth_bp, url_prefix="/auth")
    app.register_blueprint(users_bp)
    app.register_blueprint(inventory_bp)
    app.register_blueprint(tests_bp)

    print("DEBUG >>> Blueprints registered")

    # ------------------- Basic Routes -------------------
    @app.route("/login")
    def login_alias():
        return redirect(url_for("auth.login"))

    @app.route("/")
    def home():
        if current_user.is_authenticated:
            return redirect(url_for("dashboard"))
        return render_template("index.html")

    @app.route("/dashboard")
    @login_required
    def dashboard():
        from sqlalchemy import desc

        permissions = {
            "Patient Tests": current_user.has_permission("view_patient_tests"),
            "Inventory": current_user.has_permission("manage_inventory"),
            "Users": current_user.has_permission("manage_users"),
        }

        total_users = User.query.count()
        total_tests = PatientTestRecord.query.count()
        total_inventory = InventoryItem.query.count()
        recent_tests = (
            PatientTestRecord.query.order_by(desc(PatientTestRecord.test_date))
            .limit(5)
            .all()
        )

        return render_template(
            "dashboard.html",
            current_user=current_user,
            user_role=current_user.role.name if current_user.role else "No role",
            permissions=permissions,
            total_users=total_users,
            total_tests=total_tests,
            total_inventory=total_inventory,
            recent_tests=recent_tests,
        )

    # ------------------- Template Context -------------------
    @app.context_processor
    def inject_now():
        """Makes `now()` available in all templates."""
        return {"now": datetime.utcnow}

    # ------------------- ROLE + PERMISSION SEEDING -------------------
    def seed_roles_permissions():
        """Ensure all roles, permissions, and mappings exist."""
        from models import Role, Permission
        from sqlalchemy.orm import load_only

        roles = ["admin", "lab_manager", "technician", "receptionist"]
        for role_name in roles:
            if not Role.query.filter_by(name=role_name).first():
                db.session.add(Role(name=role_name))
        db.session.commit()

        permissions = [
            "manage_users",
            "manage_inventory",
            "add_patient_tests",
            "edit_patient_tests",
            "delete_patient_tests",
            "view_patient_tests",
        ]
        for perm_name in permissions:
            if not Permission.query.filter_by(name=perm_name).first():
                db.session.add(Permission(name=perm_name))
        db.session.commit()

        admin_role = Role.query.filter_by(name="admin").first()
        all_perms = Permission.query.options(load_only(Permission.id)).all()
        for perm in all_perms:
            if perm not in admin_role.permissions:
                admin_role.permissions.append(perm)

        lab_manager = Role.query.filter_by(name="lab_manager").first()
        if lab_manager:
            lm_perms = Permission.query.filter(
                Permission.name.in_(
                    [
                        "add_patient_tests",
                        "edit_patient_tests",
                        "delete_patient_tests",
                        "view_patient_tests",
                        "manage_inventory",
                    ]
                )
            ).all()
            for p in lm_perms:
                if p not in lab_manager.permissions:
                    lab_manager.permissions.append(p)

        technician = Role.query.filter_by(name="technician").first()
        if technician:
            tech_perms = Permission.query.filter(
                Permission.name.in_(
                    ["add_patient_tests", "edit_patient_tests", "view_patient_tests"]
                )
            ).all()
            for p in tech_perms:
                if p not in technician.permissions:
                    technician.permissions.append(p)

        receptionist = Role.query.filter_by(name="receptionist").first()
        if receptionist:
            rec_perms = Permission.query.filter(
                Permission.name.in_(["view_patient_tests"])
            ).all()
            for p in rec_perms:
                if p not in receptionist.permissions:
                    receptionist.permissions.append(p)

        db.session.commit()
        print("Roles, permissions, and mappings updated successfully.")

    # ------------------- TEST CATEGORY SEEDING -------------------
    def seed_test_categories():
        """Automatically add default lab test categories if missing."""
        from models import TestCategory

        default_categories = [
            "Liver Function Tests",
            "Kidney Function Tests",
            "Complete Blood Count (CBC)",
            "Thyroid Function Tests",
            "Blood Glucose Tests",
            "Lipid Profile",
            "Urinalysis",
        ]

        added_any = False
        for name in default_categories:
            if not TestCategory.query.filter_by(name=name).first():
                db.session.add(TestCategory(name=name))
                added_any = True

        if added_any:
            db.session.commit()
            print("Default test categories added successfully.")
        else:
            print("Test categories already exist — skipping seeding.")

    # ------------------- DEFAULT ADMIN CREATION -------------------
    def ensure_admin_exists():
        """Create a default admin account if none exists."""
        admin_role = Role.query.filter_by(name="admin").first()
        if not admin_role:
            admin_role = Role(name="admin")
            db.session.add(admin_role)
            db.session.commit()
            print("Created 'admin' role in database.")

        existing_admin = User.query.filter_by(username="admin").first()
        if not existing_admin:
            new_admin = User(
                username="admin",
                password_hash=generate_password_hash("Admin@123"),
                role_id=admin_role.id,
            )
            db.session.add(new_admin)
            db.session.commit()
            print("Default admin created — username: admin | password: Admin@123")
        else:
            print("Admin user already exists — skipping creation.")

    # ------------------- STARTUP SETUP -------------------
    with app.app_context():
        seed_roles_permissions()
        seed_test_categories()
        ensure_admin_exists()

        # Create uploads folder if missing
        upload_folder = os.path.join("static", "uploads", "requests")
        os.makedirs(upload_folder, exist_ok=True)
        print(f"Ensured upload folder exists at: {upload_folder}")

    print("DEBUG >>> Reached end of create_app")
    return app


# ------------------- Debug Helper -------------------
def print_routes(app):
    """Print all registered routes for debugging."""
    import urllib

    print("\n Registered routes:")
    for rule in sorted(app.url_map.iter_rules(), key=lambda r: r.endpoint):
        methods = ",".join(sorted(rule.methods))
        line = urllib.parse.unquote(f"{rule.endpoint:30s} {methods:20s} {rule}")
        print(line)
    print()


# ------------------- Entry Point -------------------
if __name__ == "__main__":
    app = create_app()
    print("DEBUG >>> create_app() returned:", app)

    with app.app_context():
        try:
            from models import db
            db.create_all()
            print("All tables created successfully (if DB reachable).")
        except Exception as e:
            print("Warning creating tables:", e)

    print_routes(app)
    app.run(debug=True, use_reloader=False)



