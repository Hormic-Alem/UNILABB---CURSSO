from werkzeug.security import generate_password_hash

from app import app, db, User

DEFAULT_USERNAME = "Apolo96"
DEFAULT_PASSWORD = "MiataMx5"
DEFAULT_ROLE = "admin"
DEFAULT_ACTIVE = True
DEFAULT_EMAIL = "apolo96@admin.local"


with app.app_context():
    db.create_all()

    admin = User.query.filter_by(username=DEFAULT_USERNAME).first()

    if admin:
        admin.password = generate_password_hash(DEFAULT_PASSWORD)
        admin.role = DEFAULT_ROLE
        admin.active = DEFAULT_ACTIVE
        if not admin.email:
            admin.email = DEFAULT_EMAIL
        db.session.commit()
        print(f"✅ Admin actualizado: {DEFAULT_USERNAME}")
    else:
        admin = User(
            username=DEFAULT_USERNAME,
            email=DEFAULT_EMAIL,
            password=generate_password_hash(DEFAULT_PASSWORD),
            role=DEFAULT_ROLE,
            active=DEFAULT_ACTIVE,
            progress={"completed_questions": [], "by_category": {}},
            avatar_url=None,
        )
        db.session.add(admin)
        db.session.commit()
        print(f"✅ Admin creado: {DEFAULT_USERNAME}")
