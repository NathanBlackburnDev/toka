from __main__ import app
from db_connector import Database
from flask import render_template, redirect, url_for, session, flash, get_flashed_messages, request
from datetime import datetime, date
import hashlib
import re
from functools import wraps


# Create instance of Database class
db = Database()


# Index route
@app.route('/')
def index():
    return render_template('index.html')


# Verify user is 13 or older
def check_age(user_dob, today):
    # Format date correctly
    user_dob = datetime.strptime(user_dob, '%Y-%m-%d').strftime('%d/%m/%Y')
    today = datetime.strptime(today, '%d/%m/%Y')
    user_dob = datetime.strptime(user_dob, '%d/%m/%Y')

    age = today.year - user_dob.year

    # If user has not had birthday this current year
    if user_dob.month < today.month or (user_dob.month == today.month and user_dob.day < today.day):
        age -= 1

    return age >= 13


# Verify date is not in the past
def verify_date(user_date):
    user_date = datetime.strptime(user_date, '%Y-%m-%d').date()
    today = date.today()
    
    return user_date >= today


# Require user to log in
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get('user') is None:
            return redirect('/login',code=302)
        return f(*args, **kwargs)
    return decorated_function


# Require admin to log in
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get('admin') is None:
            return redirect('/admin_login',code=302)
        return f(*args, **kwargs)
    return decorated_function


# Register route
@app.route('/register', methods=['GET', 'POST'])
def register():
    # If user submitted incorrect form 
    if session.get('register_data'):
        session.pop('register_data', None)

    # If user submitted form
    if request.method == 'POST':    
        # Get user form data
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        dob = request.form.get('dob')
        
        # Add to session to repopulate form is user enters incorrect input
        session['register_data'] = [username, email, password, dob, confirm_password]

        # Pre-requisites and verify age
        if dob:
            old_enough = check_age(dob, datetime.today().strftime('%d/%m/%Y'))
            if not old_enough:
                flash('You must be 13 or older to create an account', 'danger')
        else:
            flash('Please enter date of birth', 'danger')
        existing_user = db.queryDB('SELECT * FROM users WHERE username = ? OR email = ?', [username, email])
        username_pattern = r'^[A-Za-z0-9_]+$'
        email_pattern = r'^[A-Za-z0-9_@\.]+$'
        password_pattern = r'^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[a-zA-Z]).{8,}$'

        # Validate user input
        if existing_user:
            flash('Account is already in use', 'danger')
        elif not re.match(username_pattern, username):
            flash('Username must be only letters, numbers and underscores', 'danger')
        elif not (4 <= len(username) <= 16):
            flash('Username must be between 4 and 16 characters (inclusive)', 'danger')
        elif not re.match(email_pattern, email):
            flash('Please enter a valid email address', 'danger')
        elif not (6 <= len(email) <= 40):
            flash('Email must be between 6 and 60 characters (inclusive)', 'danger')
        elif not re.match(password_pattern, password):
            flash('Password must be 8 characters minimum and container at least 1 number', 'danger')
        elif password != confirm_password:
            flash('Passwords must match', 'danger')
        else:
            # Hash user data
            hashed_password = hashlib.md5(str(password).encode()).hexdigest()
            hashed_email = hashlib.md5(str(email).encode()).hexdigest()

            # Format date of birth
            dob = datetime.strptime(dob, '%Y-%m-%d').strftime('%d/%m/%Y')

            # Insert user into database
            db.updateDB('INSERT INTO users (username, email, dob, password) VALUES (?, ?, ?, ?)', [username, hashed_email, dob, hashed_password])

            # Redirect to login page
            return redirect(url_for('login'))


    return render_template('register.html', register_data=session.get('register_data'))


# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    # Clear previous form data if any
    if session.get('login_data'):
        session.pop('login_data', None)

    # If user has submitted form
    if request.method == 'POST':
        # Get form data
        username = request.form.get('username')
        password = request.form.get('password')

        # Add form values to form if user gets form wrong
        session['login_data'] = [username, password]

        # Get user info
        account_details = db.queryDB('SELECT * FROM users WHERE username = ?', [username])
        if account_details:
            stored_password = account_details[0][-1]
            hashed_password = hashlib.md5(str(password).encode()).hexdigest()

        # Validate user input
        if not account_details:
            flash('Account does not exist', 'danger')
        elif stored_password != hashed_password:
            flash('Incorrect password', 'danger')
        else:
            # Add user to session
            session['user'] = username
            return redirect(url_for('index'))
    
    # If user is already logged in
    if 'user' in session:
        return redirect(url_for('index'))

    return render_template('login.html', login_data=session.get('login_data'))


# Log user out
@app.route('/logout')
def logout():
    for key in list(session.keys()):
        session.pop(key)

    return redirect(url_for('index'))


# Accessibility route
@app.route('/accessibility')
def accessibility():
    return render_template('accessibility.html')


# Admin register route
@app.route('/admin_register', methods=['GET', 'POST'])
def admin_register():
    # If admin submitted incorrect form 
    if session.get('admin_register_data'):
        session.pop('admin_register_data', None)

    # If admin submitted form
    if request.method == 'POST':    
        # Get admin form data
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        # Add to session to repopulate form if admin enters incorrect input
        session['admin_register_data'] = [username, email, password, confirm_password]

        # Pre-requisites
        existing_admin = db.queryDB('SELECT * FROM admin WHERE admin_username = ? OR admin_email = ?', [username, email])
        username_pattern = r'^[A-Za-z0-9_]+$'
        email_pattern = r'^[A-Za-z0-9_@\.]+$'
        password_pattern = r'^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[a-zA-Z]).{8,}$'

        # Validate user input
        if existing_admin:
            flash('Account is already in use', 'danger')
        elif not re.match(username_pattern, username):
            flash('Username must be only letters, numbers and underscores', 'danger')
        elif not (4 <= len(username) <= 16):
            flash('Username must be between 4 and 16 characters (inclusive)', 'danger')
        elif not re.match(email_pattern, email):
            flash('Please enter a valid email address', 'danger')
        elif not (6 <= len(email) <= 40):
            flash('Email must be between 6 and 60 characters (inclusive)', 'danger')
        elif not re.match(password_pattern, password):
            flash('Password must be 8 characters minimum and container at least 1 number', 'danger')
        elif password != confirm_password:
            flash('Passwords must match', 'danger')
        else:
            # Hash admin data
            hashed_password = hashlib.md5(str(password).encode()).hexdigest()
            hashed_email = hashlib.md5(str(email).encode()).hexdigest()

            # Insert admin into database
            db.updateDB('INSERT INTO admin (admin_username, admin_email, admin_password) VALUES (?, ?, ?)', [username, hashed_email, hashed_password])

            # Redirect to login page
            return redirect(url_for('admin_login'))


    return render_template('admin_register.html', admin_register_data=session.get('admin_register_data'))


# Admin login route
@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    # Clear previous form data if any
    if session.get('admin_login_data'):
        session.pop('admin_login_data', None)

    # If user has submitted form
    if request.method == 'POST':
        # Get form data
        username = request.form.get('username')
        password = request.form.get('password')

        # Add form values to form if user gets form wrong
        session['admin_login_data'] = [username, password]

        # Get admin info
        account_details = db.queryDB('SELECT * FROM admin WHERE admin_username = ?', [username])
        if account_details:
            stored_password = account_details[0][-1]
            hashed_password = hashlib.md5(str(password).encode()).hexdigest()

        # Validate user input
        if not account_details:
            flash('Account does not exist', 'danger')
        elif stored_password != hashed_password:
            flash('Incorrect password', 'danger')
        else:
            # Add user to session
            session['admin'] = username
            return redirect(url_for('index'))
    
    # If admin is already logged in
    if 'admin' in session:
        return redirect(url_for('index'))

    return render_template('admin_login.html', admin_login_data=session.get('admin_login_data'))


# Add instructors route
@app.route('/add_instructor', methods=['GET', 'POST'])
@admin_required
def add_instructor():
    # If admin submitted incorrect form 
    if session.get('add_instructor_data'):
        session.pop('add_instructor_data', None)

    # If admin submitted form
    if request.method == 'POST':    
        # Get admin instructor form data
        instructor_email = request.form.get('instructor_email')
        
        # Add to session to repopulate form if admin enters incorrect input
        session['add_instructor_data'] = [instructor_email]

        # Pre-requisites
        existing_instructor = db.queryDB('SELECT * FROM instructors WHERE instructor_email = ?', [instructor_email])
        email_pattern = r'^[A-Za-z0-9_@\.]+$'

        # Validate admin instructor input
        if existing_instructor:
            flash('Instructor already added', 'danger')
        elif not re.match(email_pattern, instructor_email):
            flash('Please enter a valid instructor email address', 'danger')
        elif not (6 <= len(instructor_email) <= 40):
            flash('Instructor email must be between 6 and 60 characters (inclusive)', 'danger')
        else:
            # Insert instructor into database
            db.updateDB('INSERT INTO instructors (instructor_email) VALUES (?)', [instructor_email])
            flash('Instructor successfully added', 'success')

    return render_template('add_instructor.html', add_instructor_data=session.get('add_instructor_data'))


# Book training session route
@app.route('/training_session', methods=['GET', 'POST'])
@login_required
def training_session():
    # If user submitted incorrect form
    if session.get('training_session_data'):
        session.pop('training_session_data')

    # Get user_id
    user_id = db.queryDB('SELECT * FROM users WHERE username = ?', [session['user']])
    user_id = user_id[0][0]

    # Get instructor emails
    instructors = db.queryDB('SELECT * FROM instructors')

    # Get all previous bookings
    sessions = db.queryDB('SELECT * FROM fitness_sessions WHERE user_id = ? ORDER BY session_id DESC', [user_id])

    # If user submitted form
    if request.method == 'POST':
        # Get user form data
        instructor_id = request.form.get('instructor_id')
        session_date = request.form.get('session_date')
        session_time = request.form.get('session_time')
        session_name = request.form.get('session_name')
        session_location = request.form.get('session_location')

        # Update previous form data
        session['training_session_data'] = [instructor_id, session_date, session_time, session_name, session_location]

        # Verify if date is valid
        valid_date = None
        if session_date:
            valid_date = verify_date(session_date)

        # Existing session
        existing_session = None
        if session_date and session_time:
            existing_session = db.queryDB('SELECT * FROM fitness_sessions WHERE session_date = ? AND session_time = ?', [session_date, session_time])
        
        # Validate user input
        if existing_session:
            flash('Sorry, this instructor has already been booked', 'danger')
        elif instructor_id == 'None':
            flash('Please select a valid instructor email', 'danger')
        elif session_name == 'None':
            flash('Please select a session', 'danger')
        elif session_location == 'None':
            flash('Please select a location', 'danger')
        elif not valid_date:
            flash('Please select a valid date', 'danger')
        elif session_time == 'None':
            flash('Please select a valid time', 'danger')
        else:
            # Book session
            db.updateDB('INSERT INTO fitness_sessions (user_id, instructor_id, session_date, session_time, session_name, session_location) VALUES (?, ?, ?, ?, ?, ?)', [
                user_id,
                instructor_id,
                session_date,
                session_time,
                session_name,
                session_location
            ])
            return redirect(url_for('training_session'))
        
    return render_template('training_session.html', sessions=sessions, instructors=instructors, training_session_data=session.get('training_session_data'))
        

# Cancel training session route
@app.route('/cancel_session/<int:session_id>')
def cancel_session(session_id):
    db.updateDB('DELETE FROM fitness_sessions WHERE session_id = ?', [session_id])
    return redirect(url_for('training_session'))


# Add training advice
@app.route('/add_training_advice', methods=['GET', 'POST'])
@admin_required
def add_training_advice():
    # Clear previous admin form data if any
    if session.get('add_training_data'):
        session.pop('add_training_data', None)

    # If admin has submitted form
    if request.method == 'POST':
        # Get form data
        title = request.form.get('title')
        desc = request.form.get('desc')
        preview_desc = request.form.get('preview_desc')

        # Add form data to prevent form being cleared
        session['add_training_data'] = [title, desc, preview_desc]

        # Prerequisites
        existing_advice = db.queryDB('SELECT * FROM training_advice WHERE title = ? OR desc = ? OR preview_desc = ?', [title, desc, preview_desc])
        pattern = r'^[A-Za-z0-9\(\)\.\•\s\-\'",\n]+$'

        # Validate input data
        if existing_advice:
            flash('This advice has already been created', 'danger')
        elif not re.match(pattern, title):
            flash('Please enter valid title', 'danger')
        elif not (4 <= len(title) <= 60):
            flash('Title must be between 4 and 60 characters (inclusive)', 'danger')
        elif not (4 <= len(desc) <= 1000):
            flash('Description must be between 4 and 1000 characters (inclusive)', 'danger')
        elif not re.match(pattern, preview_desc):
            flash('Please enter preview description', 'danger')
        elif not (4 <= len(preview_desc) <= 280):
            flash('Preview description must be between 4 and 280 characters (inclusive)', 'danger')
        else:
            # Insert into table
            db.updateDB('INSERT INTO training_advice (title, desc, preview_desc) VALUES (?, ?, ?)', [title, desc, preview_desc])
            flash('Successfully added advice', 'success')

    return render_template('add_training_advice.html', add_training_data=session.get('add_training_data'))


# Add health living advice
@app.route('/add_living_advice', methods=['GET', 'POST'])
@admin_required
def add_living_advice():
    # Clear previous admin form data if any
    if session.get('add_living_data'):
        session.pop('add_living_data', None)

    # If admin has submitted form
    if request.method == 'POST':
        # Get form data
        title = request.form.get('title')
        desc = request.form.get('desc')
        preview_desc = request.form.get('preview_desc')

        # Add form data to prevent form being cleared
        session['add_living_data'] = [title, desc, preview_desc]

        # Prerequisites
        existing_advice = db.queryDB('SELECT * FROM living_advice WHERE title = ? OR desc = ? OR preview_desc = ?', [title, desc, preview_desc])
        pattern = r'^[A-Za-z0-9\(\)\.\•\s\-\'",\n]+$'

        # Validate input data
        if existing_advice:
            flash('This advice has already been created', 'danger')
        elif not re.match(pattern, title):
            flash('Please enter valid title', 'danger')
        elif not (4 <= len(title) <= 60):
            flash('Title must be between 4 and 60 characters (inclusive)', 'danger')
        elif not (4 <= len(desc) <= 1000):
            flash('Description must be between 4 and 1000 characters (inclusive)', 'danger')
        elif not re.match(pattern, preview_desc):
            flash('Please enter preview description', 'danger')
        elif not (4 <= len(preview_desc) <= 280):
            flash('Preview description must be between 4 and 280 characters (inclusive)', 'danger')
        else:
            # Insert into table
            db.updateDB('INSERT INTO living_advice (title, desc, preview_desc) VALUES (?, ?, ?)', [title, desc, preview_desc])
            flash('Successfully added advice', 'success')

    return render_template('add_living_advice.html', add_living_data=session.get('add_living_data'))


# Fitness training advice page
@app.route('/advice/fitness_training')
def fitness_training():
    cards = 4
    results = db.queryDB('SELECT * FROM training_advice LIMIT ?', [cards])
    query_len = len(results)
    return render_template('fitness_training.html', results=results, query_len=query_len, cards=cards)


# Load more cards for fitness training
@app.route('/advice/fitness_traning/loadmore/<int:cards>')
def loadmore_fitness_traning(cards):
    cards += 4
    results = db.queryDB('SELECT * FROM training_advice LIMIT ?', [cards])
    query_len = len(results)
    return render_template('fitness_training.html', results=results, query_len=query_len, cards=cards)


# Health living advice page
@app.route('/advice/health_living_advice')
def healthy_living_advice():
    cards = 4
    results = db.queryDB('SELECT * FROM living_advice LIMIT ?', [cards])
    query_len = len(results)
    return render_template('healthy_living.html', cards=cards, results=results, query_len=query_len)


# Load more cards for healthy living advice
@app.route('/advice/health_living_advice/loadmore/<int:cards>')
def loadmore_health_living_advice(cards):
    cards += 4
    results = db.queryDB('SELECT * FROM living_advice LIMIT ?', [cards])
    query_len = len(results)
    return render_template('healthy_living.html', cards=cards, results=results, query_len=query_len)