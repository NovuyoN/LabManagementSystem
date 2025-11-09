"""Add role_id to User

Revision ID: 1a7c0107da60
Revises: fec1fe45dc5d
Create Date: 2025-09-18 19:44:56.100461
"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = "1a7c0107da60"
down_revision = "fec1fe45dc5d"
branch_labels = None
depends_on = None


def upgrade():
    # 1. Add role_id column as nullable
    op.add_column("users", sa.Column("role_id", sa.Integer(), nullable=True))

    # 2. Create foreign key to roles table
    op.create_foreign_key(
        "fk_users_roles", "users", "roles", ["role_id"], ["id"]
    )

    # 3. Set default role for existing users
    conn = op.get_bind()
    result = conn.execute(sa.text("SELECT id FROM roles WHERE name = 'receptionist'"))
    role_id = result.scalar()

    if role_id is None:
        conn.execute(sa.text("INSERT INTO roles (name) VALUES ('receptionist') RETURNING id"))
        role_id = conn.execute(sa.text("SELECT id FROM roles WHERE name = 'receptionist'")).scalar()

    conn.execute(sa.text("UPDATE users SET role_id = :role_id WHERE role_id IS NULL"), {"role_id": role_id})

    # 4. Make the column non-nullable
    op.alter_column("users", "role_id", nullable=False)


def downgrade():
    op.drop_constraint("fk_users_roles", "users", type_="foreignkey")
    op.drop_column("users", "role_id")

