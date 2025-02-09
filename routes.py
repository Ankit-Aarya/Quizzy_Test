from flask import render_template, request, redirect, url_for, flash, session, jsonify
from app import app
from models import db, User, Subject, Chapter, Question, Quiz, UserQuizAttempt, Snapshot, AudioRecord
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import json
from datetime import datetime
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import io
import base64
from flask_cors import CORS
CORS(app)

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # Debugging: Print the received form data
        print(request.form)

        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        cpassword = request.form.get('cpassword', '').strip()
        name = request.form.get('name', '').strip()
        qualification = request.form.get('qualification', '').strip()
        dob = request.form.get('dob', '').strip()

        # Validation for empty fields
        if not all([username, password, cpassword, name, qualification, dob]):
            flash('Please complete all fields', 'danger')
            return redirect(url_for('register'))

        # Password mismatch check
        if password != cpassword:
            flash('Passwords do not match', 'danger')
            return redirect(url_for('register'))

        # Check if user already exists
        user = User.query.filter_by(username=username).first()
        if user:
            flash('Username already exists', 'danger')
            return redirect(url_for('register'))

        # Save user to the database
        password_hash = generate_password_hash(password)
        new_user = User(username=username, password=password_hash, name=name, qualification=qualification, dob=dob, is_admin=False)

        try:
            db.session.add(new_user)
            db.session.commit()
            flash('Account created successfully', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            flash('An error occurred. Please try again.', 'danger')
            return redirect(url_for('register'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if not username or not password:
            flash('Please fill in all fields', 'danger')
            return redirect(url_for('login'))
        
        user = User.query.filter_by(username=username).first()

        if not user:
            flash('Username does not exist', 'danger')
            return redirect(url_for('login'))
        
        if not check_password_hash(user.password, password):
            flash('Password incorrect', 'danger')
            return redirect(url_for('login'))
        
        session['user_id'] = user.id
        session['user_name'] = user.name
        session['is_admin'] = user.is_admin
        session.permanent = True

        # Redirect based on the user's role
        if user.is_admin:
            flash('Login successful', 'success')
            return redirect(url_for('admin_dashboard'))  # Redirect to admin dashboard
        else:
            flash('Login successful', 'success')
            return redirect(url_for('user_dashboard'))  # Redirect to user dashboard
        
    return render_template('login.html')

# decorator for auth required
def auth_required(func):
    """Restrict access to user-only pages (block admins)."""
    @wraps(func)
    def inner(*args, **kwargs):
        if "user_id" not in session:
            flash('Please login to continue', 'info')
            return redirect(url_for('login'))
        
        user = User.query.get(session['user_id'])
        if not user:  
            flash('User not found, please login again', 'danger')
            return redirect(url_for('login'))

        if user.is_admin:  # Block admin access
            flash('You are not allowed to access this page', 'danger')
            return redirect(url_for('home'))  # Redirect admin to home

        return func(*args, **kwargs)

    return inner

def admin_required(func):
    """Restrict access to admin-only pages (block normal users)."""
    @wraps(func)
    def inner(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login to continue', 'danger')
            return redirect(url_for('login'))

        user = User.query.get(session['user_id'])
        if not user:  
            flash('User not found, please login again', 'danger')
            return redirect(url_for('login'))

        if not user.is_admin:  # Block normal user access
            flash('You are not authorized to access this page', 'danger')
            return redirect(url_for('home'))  # Redirect user to home

        return func(*args, **kwargs)

    return inner 

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out', 'info')
    return  redirect(url_for('login'))

# admin dashboard
@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    user_name = session.get('user_name', 'User')
    subjects = Subject.query.all()
    return render_template('admin_side/admin_dashboard.html', user_name=user_name, subjects=subjects)

@app.route('/add_subject_page')
@admin_required
def add_subject_page():
    return render_template('admin_side/add_subject.html')

@app.route('/add_subject', methods=["POST"])
@admin_required
def add_subject():
    subject_name = request.form.get('subjectName')

    if not subject_name:
        flash("Subject name is required!", 'danger')
        return redirect(url_for('add_subject_page'))  # Stay on the add subject page

    # Ensure 'sub_name' matches your database field
    existing_subject = Subject.query.filter_by(sub_name=subject_name).first()
    if existing_subject:
        flash(f"Subject '{subject_name}' already exists!", 'danger')
        return redirect(url_for('add_subject_page'))  # Stay on the add subject page

    # Add new subject
    new_sub = Subject(sub_name=subject_name)
    db.session.add(new_sub)
    db.session.commit()

    flash(f"Subject '{subject_name}' added successfully!", 'success')
    return redirect(url_for('admin_dashboard'))  # Redirect back to admin dashboard

@app.route('/delete_subject/<int:subject_id>', methods=['POST'])
@admin_required
def delete_subject(subject_id):
    subject = Subject.query.get_or_404(subject_id)

    try:
        db.session.delete(subject)
        db.session.commit()
        flash('Subject deleted successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Error deleting subject. Make sure there are no related chapters.', 'danger')

    return redirect(url_for('admin_dashboard'))


@app.route('/admin/add_chapter/<int:subject_id>', methods=['GET', 'POST'])
@admin_required
def add_chapter(subject_id):
    subject = Subject.query.get_or_404(subject_id)
    
    if request.method == 'POST':
        chapter_name = request.form.get('chapter_name', '').strip()

        if not chapter_name:
            flash("Chapter name cannot be empty", "danger")
            return redirect(url_for('add_chapter', subject_id=subject.id))

        new_chapter = Chapter(name=chapter_name, subject=subject)
        db.session.add(new_chapter)
        db.session.commit()
        flash("Chapter added successfully!", "success")
        return redirect(url_for('admin_dashboard'))

    return render_template('admin_side/add_chapter.html', subject=subject)

@app.route('/admin/add_question/<int:chapter_id>', methods=['GET', 'POST'])
@admin_required
def add_question(chapter_id):
    chapter = Chapter.query.get_or_404(chapter_id)

    if request.method == 'POST':
        text = request.form.get('question_text', '').strip()
        option_a = request.form.get('option_a', '').strip()
        option_b = request.form.get('option_b', '').strip()
        option_c = request.form.get('option_c', '').strip()
        option_d = request.form.get('option_d', '').strip()
        correct_option = request.form.get('correct_option', '').strip().upper()

        if not all([text, option_a, option_b, option_c, option_d, correct_option]):
            flash("All fields are required!", "danger")
            return redirect(url_for('add_question', chapter_id=chapter.id))

        if correct_option not in ['A', 'B', 'C', 'D']:
            flash("Correct answer must be A, B, C, or D!", "warning")
            return redirect(url_for('add_question', chapter_id=chapter.id))

        new_question = Question(
            text=text, option_a=option_a, option_b=option_b,
            option_c=option_c, option_d=option_d,
            correct_option=correct_option, chapter=chapter
        )
        db.session.add(new_question)
        db.session.commit()
        flash("Question added successfully!", "success")
        return redirect(url_for('add_question', chapter_id=chapter.id))

    return render_template('admin_side/add_question.html', chapter=chapter)


@app.route('/admin/chapters/<int:subject_id>')
@admin_required
def view_chapters(subject_id):
    subject = Subject.query.get_or_404(subject_id)
    return render_template('admin_side/view_chapters.html', subject=subject)

@app.route('/admin/view_questions/<int:chapter_id>')
@admin_required
def view_questions(chapter_id):
    chapter = Chapter.query.get(chapter_id)
    
    if not chapter:
        flash("Chapter not found!", "danger")
        return redirect(url_for('admin_dashboard'))

    questions = Question.query.filter_by(chapter_id=chapter_id).all()

    return render_template('admin_side/view_questions.html', chapter=chapter, questions=questions)


@app.route('/admin/edit_chapter/<int:chapter_id>', methods=['GET', 'POST'])
@admin_required
def edit_chapter(chapter_id):
    chapter = Chapter.query.get(chapter_id)

    if not chapter:
        flash('Chapter not found', 'danger')
        return redirect(url_for('admin_dashboard'))

    if request.method == 'POST':
        chapter_name = request.form.get('chapter_name', '').strip()

        if not chapter_name:
            flash('Chapter name cannot be empty', 'danger')
            return redirect(url_for('edit_chapter', chapter_id=chapter_id))

        # Check if a chapter with the same name already exists under the same subject
        existing_chapter = Chapter.query.filter_by(name=chapter_name, subject_id=chapter.subject_id).first()
        if existing_chapter and existing_chapter.id != chapter_id:
            flash('A chapter with this name already exists in the same subject.', 'warning')
            return redirect(url_for('edit_chapter', chapter_id=chapter_id))

        chapter.name = chapter_name
        db.session.commit()
        flash('Chapter updated successfully', 'success')
        return redirect(url_for('view_chapters', subject_id=chapter.subject_id))

    return render_template('admin_side/edit_chapter.html', chapter=chapter)

# Edit Question
@app.route('/admin/edit_question/<int:question_id>', methods=['GET', 'POST'])
@admin_required
def edit_question(question_id):
    question = Question.query.get(question_id)
    
    if not question:
        flash("Question not found!", "danger")
        return redirect(url_for('admin_dashboard'))

    if request.method == 'POST':
        question.text = request.form['text']
        question.option_a = request.form['option_a']
        question.option_b = request.form['option_b']
        question.option_c = request.form['option_c']
        question.option_d = request.form['option_d']
        question.correct_option = request.form['correct_option']

        try:
            db.session.commit()
            flash("Question updated successfully!", "success")
            return redirect(url_for('view_questions', chapter_id=question.chapter_id))
        except Exception as e:
            db.session.rollback()
            flash("An error occurred while updating the question.", "danger")

    return render_template('admin_side/edit_question.html', question=question)

# Delete Chapter
@app.route('/admin/delete_chapter/<int:chapter_id>')
@admin_required
def delete_chapter(chapter_id):
    chapter = Chapter.query.get_or_404(chapter_id)
    db.session.delete(chapter)
    db.session.commit()
    flash("Chapter deleted successfully!", "success")
    return redirect(url_for('admin_dashboard'))

# Delete Question
@app.route('/admin/delete_question/<int:question_id>', methods=['POST'])
@admin_required
def delete_question(question_id):
    question = Question.query.get(question_id)
    
    if not question:
        flash("Question not found!", "danger")
        return redirect(url_for('admin_dashboard'))

    chapter_id = question.chapter_id  # Store chapter ID before deletion

    try:
        db.session.delete(question)
        db.session.commit()
        flash("Question deleted successfully!", "success")
    except Exception as e:
        db.session.rollback()
        flash("An error occurred while deleting the question.", "danger")

    return redirect(url_for('view_questions', chapter_id=chapter_id))

# Create Quiz
@app.route('/create_quiz', methods=['GET', 'POST'])
@admin_required
def create_quiz():
    if request.method == 'POST':
        title = request.form['title']
        subject_id = request.form['subject']
        chapter_id = request.form['chapter']
        num_questions = request.form['num_questions']
        duration = request.form['duration']

        new_quiz = Quiz(title=title, subject_id=subject_id, chapter_id=chapter_id, num_questions=num_questions, duration=duration)
        db.session.add(new_quiz)
        db.session.commit()
        flash('Quiz created successfully!', 'success')
        return redirect(url_for('view_quizzes'))

    subjects = Subject.query.all()
    chapters = {
        subject.id: [{"id": ch.id, "name": ch.name, "question_count": len(ch.questions)} for ch in subject.chapters]
        for subject in subjects
    }

    return render_template('admin_side/create_quiz.html', subjects=subjects, chapters=json.dumps(chapters))


# Route to display all quizzes
@app.route('/admin/quizzes')
@admin_required
def view_quizzes():
    quizzes = Quiz.query.all()
    return render_template('admin_side/view_quizzes.html', quizzes=quizzes)

# edit quiz
@app.route('/edit_quiz/<int:quiz_id>', methods=['GET', 'POST'])
@admin_required
def edit_quiz(quiz_id):
    quiz = Quiz.query.get_or_404(quiz_id)
    subjects = Subject.query.all()

    if request.method == 'POST':
        title = request.form['title']
        subject_id = request.form['subject']
        chapter_id = request.form['chapter']
        num_questions = request.form['num_questions']
        duration = request.form['duration']

        # Updating quiz details
        quiz.title = title
        quiz.subject_id = subject_id
        quiz.chapter_id = chapter_id
        quiz.num_questions = num_questions
        quiz.duration = duration

        db.session.commit()
        flash('Quiz updated successfully!', 'success')
        return redirect(url_for('view_quizzes'))

    return render_template('admin_side/edit_quiz.html', quiz=quiz, subjects=subjects)


# Route to delete a quiz
@app.route('/admin/delete_quiz/<int:quiz_id>', methods=['POST'])
@admin_required
def delete_quiz(quiz_id):
    quiz = Quiz.query.get_or_404(quiz_id)
    db.session.delete(quiz)
    db.session.commit()
    flash("Quiz deleted successfully!", "success")
    return redirect(url_for('view_quizzes'))

@app.route('/admin/summary')
@admin_required  
def summary():
    records = (
        db.session.query(UserQuizAttempt, User, Quiz)
        .join(User, UserQuizAttempt.user_id == User.id)
        .join(Quiz, UserQuizAttempt.quiz_id == Quiz.id)
        .order_by(UserQuizAttempt.timestamp.desc())
        .all()
    )

    return render_template('admin_side/summary.html', records=records)



#user dashboard
@app.route('/user/dashboard')
@auth_required
def user_dashboard():
    quizzes = Quiz.query.all()
    user_name = session.get('user_name', 'User')
    return render_template('user_side/user_dashboard.html', quizzes=quizzes, user_name=user_name )

@app.route('/user/profile', methods=['GET', 'POST'])
@auth_required
def profile():
    user = User.query.get(session['user_id'])
    if request.method == 'POST':
        cpassword = request.form.get('cpassword')
        password = request.form.get('password')
        name = request.form.get('name')

        if not all([cpassword, password, name]):
            flash('Please fill all the fields', 'danger')
            return redirect(url_for('profile'))
        
        if not check_password_hash(user.password, cpassword):
            flash('Incorrect Current Password', 'danger')
            return redirect(url_for('profile'))
        
        if cpassword == password:
            flash('New password same as old password', 'info')
            return redirect(url_for('profile'))
        
        new_password_hash = generate_password_hash(password)
        user.password = new_password_hash
        user.name = name
        db.session.commit()
        flash('Profile updated successfully', 'success')
        return redirect(url_for('profile'))

    return render_template('user_side/profile.html', user=user)

@app.route('/start_quiz/<int:quiz_id>')
@auth_required
def start_quiz(quiz_id):
    # Fetch the quiz by ID
    quiz = Quiz.query.get_or_404(quiz_id)

    # Fetch all questions related to the selected chapter
    questions = Question.query.filter_by(chapter_id=quiz.chapter_id).all()

    # If there are no questions, redirect back with an error message
    if not questions:
        flash("No questions available for this quiz!", "warning")
        return redirect(url_for('user_dashboard'))

    return render_template('user_side/start_quiz.html', quiz=quiz, questions=questions, duration=quiz.duration)

@app.route('/submit_quiz/<int:quiz_id>', methods=['POST'])
@auth_required
def submit_quiz(quiz_id):
    quiz = Quiz.query.get_or_404(quiz_id)
    user_id = session.get('user_id')

    if not user_id:
        flash("You must be logged in to submit the quiz.", "danger")
        return redirect(url_for('login'))

    # Fetch questions using the chapter_id of the quiz
    questions = Question.query.filter_by(chapter_id=quiz.chapter_id).all()
    total_questions = len(questions)
    score = 0

    # Check answers
    for question in questions:
        user_answer = request.form.get(f'question_{question.id}')
        if user_answer and user_answer == question.correct_option:
            score += 1  # Increase score if correct

    # Convert score to percentage
    percentage_score = (score / total_questions) * 100 if total_questions > 0 else 0

    # Check if the user has already attempted the quiz
    attempt = UserQuizAttempt.query.filter_by(user_id=user_id, quiz_id=quiz_id).first()

    if attempt:
        # Update the existing attempt
        attempt.score = percentage_score
        attempt.timestamp = datetime.now()
    else:
        # Create a new attempt if none exists
        attempt = UserQuizAttempt(
            user_id=user_id,
            quiz_id=quiz_id,
            score=percentage_score,
            total_questions=total_questions,
            timestamp=datetime.now()
        )
        db.session.add(attempt)

    db.session.commit()

    flash(f"Quiz submitted! Your score: {score}/{total_questions} ({percentage_score}%)", "success")
    return redirect(url_for('user_dashboard'))


@app.route('/user_result')
@auth_required
def user_results():
    user_id = session.get('user_id')

    if not user_id:
        flash("You must be logged in to view results.", "danger")
        return redirect(url_for('login'))

    # Fetch all quiz attempts by the user
    attempts = (
        db.session.query(UserQuizAttempt, Quiz.title)
        .join(Quiz, UserQuizAttempt.quiz_id == Quiz.id)
        .filter(UserQuizAttempt.user_id == user_id)
        .order_by(UserQuizAttempt.timestamp.desc())  # Show latest attempts first
        .all()
    )

    return render_template('user_side/user_results.html', attempts=attempts)

@app.route('/user/summary')
@auth_required
def user_result_graph():
    user_id = session.get('user_id')

    if not user_id:
        flash("You must be logged in to view results.", "danger")
        return redirect(url_for('login'))

    # Fetch user quiz attempts with quiz titles
    attempts = (
        db.session.query(UserQuizAttempt, Quiz)
        .join(Quiz, UserQuizAttempt.quiz_id == Quiz.id)
        .filter(UserQuizAttempt.user_id == user_id)
        .order_by(UserQuizAttempt.timestamp)
        .all()
    )

    if not attempts:
        return "No quiz results available."

    # Extract quiz names and scores
    quiz_names = [quiz.title for _, quiz in attempts]
    scores = [attempt.score for attempt, _ in attempts]

    # Calculate the overall progress (average score)
    avg_score = sum(scores) / len(scores)

    # Generate the graph
    plt.figure(figsize=(10, 5))
    plt.plot(quiz_names, scores, marker='o', linestyle='-', color='b', label='Score (%)')
    plt.xlabel('Quiz Name')
    plt.ylabel('Score (%)')
    plt.title('Quiz Performance Over Time')
    plt.xticks(rotation=45, ha='right')
    plt.ylim(0, 100)
    plt.legend()
    plt.grid(True)

    # Save graph to a BytesIO object
    img = io.BytesIO()
    plt.savefig(img, format='png', bbox_inches='tight')
    img.seek(0)
    plt.close()

    # Convert to base64 for embedding in HTML
    img_base64 = base64.b64encode(img.getvalue()).decode()

    return render_template('user_side/summary.html', img_base64=img_base64, avg_score=avg_score)

@app.route('/save_snapshot', methods=['POST'])
def save_snapshot():
    try:
        data = request.get_json()
        user_id = data.get("user_id")
        quiz_id = data.get("quiz_id")
        image_data = data.get("image")

        if not image_data or not user_id or not quiz_id:
            return jsonify({"error": "Missing data"}), 400

        # Extract and decode Base64 image
        try:
            image_data = image_data.split(",")[1]  # Remove "data:image/png;base64,"
            image_binary = base64.b64decode(image_data)
        except Exception as e:
            return jsonify({"error": f"Base64 decoding failed: {str(e)}"}), 400

        # Save snapshot to database
        snapshot = Snapshot(user_id=user_id, quiz_id=quiz_id, image=image_binary)
        db.session.add(snapshot)
        db.session.commit()

        return jsonify({"message": "Snapshot saved successfully"}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/save_audio', methods=['POST'])
def save_audio():
    if 'audio' not in request.files or 'user_id' not in request.form or 'quiz_id' not in request.form:
        return jsonify({"error": "Missing audio or user/quiz data"}), 400

    user_id = request.form['user_id']
    quiz_id = request.form['quiz_id']
    audio_file = request.files['audio']
    audio_data = audio_file.read()

    # Save to database
    audio_record = AudioRecord(user_id=user_id, quiz_id=quiz_id, audio=audio_data)
    db.session.add(audio_record)
    db.session.commit()

    return jsonify({"message": "Audio recording saved successfully"})

@app.route('/admin/view_media/<int:user_id>/<int:quiz_id>')
@admin_required
def view_media(user_id, quiz_id):
    snapshots = Snapshot.query.filter_by(user_id=user_id, quiz_id=quiz_id).all()
    audio_records = AudioRecord.query.filter_by(user_id=user_id, quiz_id=quiz_id).all()

    return render_template('admin_side/view_media.html', snapshots=snapshots, audio_records=audio_records)

@app.template_filter('b64encode')
def b64encode_filter(data):
    """Convert binary data to base64 for embedding in HTML."""
    return base64.b64encode(data).decode('utf-8')







