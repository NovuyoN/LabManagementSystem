from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from flask_bcrypt import Bcrypt
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()
bcrypt = Bcrypt()

# ----------------------- UTILITY -----------------------
def hash_password(plain_text_password):
    """Generate a bcrypt hash for a plaintext password."""
    return bcrypt.generate_password_hash(plain_text_password).decode('utf-8')


# ----------------------- ROLE-PERMISSION RELATIONSHIP -----------------------
role_permissions = db.Table(
    "role_permissions",
    db.Column("role_id", db.Integer, db.ForeignKey("roles.id"), primary_key=True),
    db.Column("permission_id", db.Integer, db.ForeignKey("permissions.id"), primary_key=True)
)


class Role(db.Model):
    """Represents a system role (admin, technician, etc.)."""
    __tablename__ = "roles"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)

    permissions = db.relationship(
        "Permission",
        secondary=role_permissions,
        back_populates="roles",
        lazy="joined"
    )

    users = db.relationship("User", back_populates="role")

    def __repr__(self):
        return f"<Role {self.name}>"


class Permission(db.Model):
    """Represents a single system permission (e.g., manage_inventory)."""
    __tablename__ = "permissions"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)

    roles = db.relationship(
        "Role",
        secondary=role_permissions,
        back_populates="permissions",
        lazy="joined"
    )

    def __repr__(self):
        return f"<Permission {self.name}>"


# ----------------------- USER -----------------------
class User(UserMixin, db.Model):
    """System users that can log in."""
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(512), nullable=False)

    role_id = db.Column(db.Integer, db.ForeignKey("roles.id"))
    role = db.relationship("Role", back_populates="users")

    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    test_records = db.relationship("PatientTestRecord", backref="user", lazy=True)
    transactions = db.relationship("InventoryTransaction", backref="user", lazy=True)
    activities = db.relationship("ActivityLog", backref="user", lazy=True)

    # Password helpers
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    # Permission helpers
    def has_permission(self, permission_name):
        """Check if the user has a specific permission via their role."""
        if not self.role:
            return False

        # ✅ Admin always has full access
        if self.role.name.lower() == "admin":
            return True

        # ✅ Check if any permission matches
        return any(p.name == permission_name for p in self.role.permissions)

    def __repr__(self):
        return f"<User {self.username} ({self.role.name if self.role else 'No Role'})>"


# ----------------------- PATIENT TEST RECORDS -----------------------
class PatientTestRecord(db.Model):
    """Stores laboratory test results."""
    __tablename__ = "patient_test_records"

    id = db.Column(db.Integer, primary_key=True)
    patient_name = db.Column(db.String(120), nullable=False)
    test_type = db.Column(db.String(100), nullable=False)
    test_result = db.Column(db.String(50), nullable=False)
    test_date = db.Column(db.Date, nullable=False)
    recorded_by = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


# ----------------------- INVENTORY ITEMS -----------------------
class InventoryItem(db.Model):
    """Represents lab inventory (reagents, test kits, etc.)."""
    __tablename__ = "inventory_items"

    id = db.Column(db.Integer, primary_key=True)
    item_name = db.Column(db.String(120), nullable=False)
    category = db.Column(db.String(50), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    unit = db.Column(db.String(20), nullable=False)
    expiry_date = db.Column(db.Date, nullable=True)
    min_threshold = db.Column(db.Integer, nullable=False)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    transactions = db.relationship("InventoryTransaction", backref="item", lazy=True)
    alerts = db.relationship("AlertLog", backref="item", lazy=True)


# ----------------------- INVENTORY TRANSACTIONS -----------------------
class InventoryTransaction(db.Model):
    """Tracks add/remove actions on inventory items."""
    __tablename__ = "inventory_transactions"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    item_id = db.Column(db.Integer, db.ForeignKey("inventory_items.id"), nullable=False)
    quantity_changed = db.Column(db.Integer, nullable=False)
    action_type = db.Column(db.String(10), nullable=False)  # "added" or "removed"
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


# ----------------------- ALERT LOGS -----------------------
class AlertLog(db.Model):
    """Stores alert messages like low stock or expired items."""
    __tablename__ = "alert_logs"

    id = db.Column(db.Integer, primary_key=True)
    item_id = db.Column(db.Integer, db.ForeignKey("inventory_items.id"), nullable=False)
    alert_type = db.Column(db.Integer, nullable=False)  # 1 = low stock, 2 = expiry
    message = db.Column(db.String(255), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)


# ----------------------- ACTIVITY LOGS -----------------------
class ActivityLog(db.Model):
    """Tracks important user actions."""
    __tablename__ = "activity_logs"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    action = db.Column(db.String(255), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
