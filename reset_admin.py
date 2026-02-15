import os

from dotenv import load_dotenv
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash

load_dotenv()

app = Flask(__name__)
database_url = os.environ.get('DATABASE_URL')
if not database_url:
    raise RuntimeError('DATABASE_URL no está configurada.')
if database_url.startswith('postgres://'):
    database_url = database_url.replace('postgres://', 'postgresql://', 1)

app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.Text, nullable=False)
    active = db.Column(db.Boolean, nullable=False, default=False)


with app.app_context():
    db.create_all()
    admin = User.query.filter_by(username='admin').first()
    nueva_contrasena = 'Admin1234'

    if not admin:
        print("No se encontró un usuario 'admin' en la base de datos")
    else:
        admin.password = generate_password_hash(nueva_contrasena)
        admin.active = True
        db.session.commit()
        print(f"✅ Contraseña del admin reseteada a '{nueva_contrasena}'")
