from flask_sqlalchemy import SQLAlchemy
from app import app
from werkzeug.security import generate_password_hash
from datetime import datetime


# Initialize SQLAlchemy
db = SQLAlchemy(app)

# Define the User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    name = db.Column(db.String(80), nullable=False)
    qualification = db.Column(db.String(80), nullable=False)
    dob = db.Column(db.String(10), nullable=False)
    is_admin = db.Column(db.Boolean, nullable=False, default=False)

# Subject Table
class Subject(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sub_name = db.Column(db.String(100), nullable=False, unique=True)
    chapters = db.relationship('Chapter', backref='subject', lazy=True, cascade="all, delete-orphan")

# Chapter Table
class Chapter(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    subject_id = db.Column(db.Integer, db.ForeignKey('subject.id'), nullable=False)
    questions = db.relationship('Question', backref='chapter', lazy=True, cascade="all, delete-orphan")

# Question Table
class Question(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    option_a = db.Column(db.String(200), nullable=False)
    option_b = db.Column(db.String(200), nullable=False)
    option_c = db.Column(db.String(200), nullable=False)
    option_d = db.Column(db.String(200), nullable=False)
    correct_option = db.Column(db.String(1), nullable=False)  # Stores 'A', 'B', 'C', or 'D'
    chapter_id = db.Column(db.Integer, db.ForeignKey('chapter.id'), nullable=False)

# Quiz Table
class Quiz(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)  # Title of the quiz
    subject_id = db.Column(db.Integer, db.ForeignKey('subject.id'), nullable=False)  # Related subject
    chapter_id = db.Column(db.Integer, db.ForeignKey('chapter.id'), nullable=False)  # Related chapter
    num_questions = db.Column(db.Integer, nullable=False)  # Number of questions in the quiz
    duration = db.Column(db.Integer, nullable=False)  # Duration in minutes
    created_at = db.Column(db.DateTime, default=datetime.utcnow)  # Timestamp

    # Relationships
    subject = db.relationship('Subject', backref='quizzes', lazy="joined")
    chapter = db.relationship('Chapter', backref='quizzes', lazy="joined")

# user-side database models
class UserQuizAttempt(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    quiz_id = db.Column(db.Integer, db.ForeignKey('quiz.id'), nullable=False)
    score = db.Column(db.Float, nullable=False)  # Store percentage score
    total_questions = db.Column(db.Integer, nullable=False)
    timestamp = db.Column(db.DateTime, default=db.func.current_timestamp())

class Snapshot(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    quiz_id = db.Column(db.Integer, db.ForeignKey('quiz.id'), nullable=False)
    image = db.Column(db.LargeBinary, nullable=False)  # Store image as binary
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class AudioRecord(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    quiz_id = db.Column(db.Integer, db.ForeignKey('quiz.id'), nullable=False)
    audio = db.Column(db.LargeBinary, nullable=False)  # Store audio as binary
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)


# Create the database
with app.app_context():
    db.create_all()