from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from os import path
from flask_login import LoginManager
import os

db = SQLAlchemy()
DB_NAME = "database.db"

def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = os.getenv("SECRET_KEY")
    db_path = os.path.join(os.path.dirname(__file__), '../instance/database.db')
    app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}'
    db.init_app(app)

    from .views import views
    from .auth import auth

    app.register_blueprint(views, url_prefix='/')
    app.register_blueprint(auth, url_prefix='/')

    from .models import User, Permutation, UserInfo, Transfer

    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    with app.app_context():
        db.create_all()
        print('Database created')

    login_manager = LoginManager()
    login_manager.login_view = 'auth.client_number'
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(client_number):
        return User.query.get(client_number)

    return app