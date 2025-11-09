from models import User, db
from app import app

with app.app_context():
    print("Seeding initial data...")

    if not User.query.filter_by(username="admin").first():
        user = User(
            username="admin",
            password_hash="hashed_password_here",  # ideally use a real hash
            role="admin"
        )
        db.session.add(user)
        db.session.commit()
        print("Admin user created.")
    else:
        print("Admin user already exists.")