from datetime import datetime
from app import db, login_manager
from flask_login import UserMixin

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    pin = db.Column(db.String(6), nullable=True)  # 6-digit PIN, optional
    security_question = db.Column(db.String(255), nullable=True)  # Optional security question
    security_answer = db.Column(db.String(255), nullable=True)  # Security answer, hashed
    setup_completed = db.Column(db.Boolean, default=False)  # Check if user has completed PIN/Security question setup
    last_login = db.Column(db.DateTime, nullable=True)  # Add last_login attribute
    password_updated = db.Column(db.DateTime, nullable=True)  # Track when password was updated
    security_updated = db.Column(db.DateTime, nullable=True)  # Track when security settings were updated
    first_name = db.Column(db.String(50), nullable=True)  # Optional first name
    last_name = db.Column(db.String(50), nullable=True)  # Optional last name
    profile_picture = db.Column(db.String(120), nullable=True)  # Optional profile picture URL
    gender = db.Column(db.String(10), nullable=True)  # Optional gender
    date_of_birth = db.Column(db.Date, nullable=True)  # Optional date of birth
    nationality = db.Column(db.String(50), nullable=True)  # Optional nationality
    is_verified = db.Column(db.Boolean, default=False)
    records = db.relationship('Record', backref='author', lazy=True)


    def __repr__(self):
        return f"User('{self.username}', '{self.email}')"


class Record(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __repr__(self):
        return f"Record('{self.title}', '{self.date_posted}')"
