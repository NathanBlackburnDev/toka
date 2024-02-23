from __main__ import app
from db_connector import Database
from flask import render_template, redirect, url_for, session, flash, get_flashed_messages, request
from datetime import datetime, date
import hashlib
import re
from functools import wraps
import base64


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


# Require payment to access content
def payment_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Get user_id
        user_id = db.queryDB('SELECT * FROM users WHERE username = ?', [session.get('user')])
        user_id = user_id[0][0]
        payment_details = db.queryDB('SELECT * FROM payment_info WHERE user_id = ?', [user_id])
        # Prevent the user from having to enter payment details more than once
        if session.get('payment_check') is None and not payment_details:
            return redirect('/payment_info',code=302)
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
    # Prevent admin from being logged in as user at same time
    if session.get('admin'):
        session.pop('admin', None)

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
    # Prevent user from being logged in as admin + user at same time
    if session.get('user'):
        session.pop('user', None)

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


# Fitness training advice route
@app.route('/fitness_training_advice')
def fitness_training_advice():
    records = 8
    query = db.queryDB('SELECT * FROM training_advice LIMIT ?', [records])
    query_len = len(query)

    return render_template('fitness_training.html', records=records, query=query, query_len=query_len)


# Load more records for fitness traning
@app.route('/loadmore_fitness/<int:records>')
def loadmore_fitness_records(records):
    records += 8
    query = db.queryDB('SELECT * FROM training_advice LIMIT ?', [records])
    query_len = len(query)

    return render_template('fitness_training.html', records=records, query=query, query_len=query_len)


# Healthy living advice route
@app.route('/healthy_living_advice')
def healthy_living_advice():
    records = 8
    query = db.queryDB('SELECT * FROM living_advice LIMIT ?', [records])
    query_len = len(query)

    return render_template('healthy_living.html', records=records, query=query, query_len=query_len)


# Load more records for healthy living 
@app.route('/loadmore_living/<int:records>')
def loadmore_healthy_living_advice(records):
    records += 8
    query = db.queryDB('SELECT * FROM living_advice LIMIT ?', [records])
    query_len = len(query)

    return render_template('healthy_living.html', records=records, query=query, query_len=query_len)


# More information for fitness advice
@app.route('/fitness_moreinfo/<int:record_id>')
def moreinfo_fitness(record_id):
    query = db.queryDB('SELECT * FROM training_advice WHERE record_id = ?', [record_id])
    return render_template('moreinfo_fitness.html', query=query)


# More information for healthy living advice
@app.route('/healthy_living_moreinfo/<int:record_id>')
def moreinfo_healthy_living(record_id):
    query = db.queryDB('SELECT * FROM living_advice WHERE record_id = ?', [record_id])
    return render_template('moreinfo_healthy_living.html', query=query)


# Payment info form
@app.route('/payment_info', methods=['GET', 'POST'])
@login_required
def payment_info():
    # Get user_id
    user_id = db.queryDB('SELECT * FROM users WHERE username = ?', [session.get('user')])
    user_id = user_id[0][0]

    # Clear previous form submission
    if session.get('payment_info_data'):
        session.pop('payment_info_data', None)

    # If the user has submitted the form
    if request.method == 'POST':
        # Get form data
        card_type = request.form.get('card_type')
        card_holder_name = request.form.get('card_holder_name')
        card_number = request.form.get('card_number')
        expr_date = request.form.get('expr_date')
        cvv = request.form.get('cvv')

        # Add form data to session if form gets
        session['payment_info_data'] = [card_type, card_holder_name, card_number, expr_date, cvv]

        # RegEx patterns
        card_holder_pattern = r'^[A-Za-z\s]+$'
        card_number_pattern = r'^[0-9\-]+$'
        expr_pattern = r'^[0-9\-\/]+$'

        # Query for existing card details
        existing_card = db.queryDB('SELECT * FROM payment_info WHERE card_number = ?', [hashlib.md5(str(card_number).encode()).hexdigest()])

        # Validate user input
        if existing_card:
            flash('Card information is already in use, contact your bank if you have not entered them before', 'danger')
        elif card_type == 'Select card type':
            flash('Must select card type', 'danger')
        elif not re.match(card_holder_pattern, card_holder_name):
            flash('Please enter a valid card holder name', 'danger')
        elif not (4 <= len(card_holder_pattern) <= 60):
            flash('Card holder name must be between 4 and 60 characters (inclusive)', 'danger')
        elif not re.match(card_number_pattern, card_number) or len(card_number) != 19:
            flash('Please enter valid card number, i.e. 0123-4567-8910-1111', 'danger')
        elif not re.match(expr_pattern, expr_date):
            flash('Please enter valid expiry date, i.e. 01/27', 'danger')
        elif not cvv.isdigit() or len(cvv) != 3:
            flash('Please enter a valid 3 letter digit', 'danger')
        else:
            # Add user payment details and hash payment info
            db.updateDB('INSERT INTO payment_info (user_id, card_type, card_holder_name, card_number, expr_date, cvv) VALUES (?, ?, ?, ?, ?, ?)', [
                user_id,
                card_type,
                card_holder_name,
                hashlib.md5(str(card_number).encode()).hexdigest(),
                hashlib.md5(str(expr_date).encode()).hexdigest(),
                hashlib.md5(str(cvv).encode()).hexdigest()
            ])
            session['payment_check'] = True
            flash('Successfully added payment details', 'success')

    return render_template('payment_info.html', payment_info_data=session.get('payment_info_data'))


# Add paid-for content route
@app.route('/add_content', methods=['GET', 'POST'])
@admin_required
def add_content():
    # Clear previous form attempt
    if session.get('add_content_data'):
        session.pop('add_content_data', None)

    # If admin has submitted form
    if request.method == 'POST':
        # Get form data
        url = request.form.get('url')
        title = request.form.get('title')
        desc = request.form.get('desc')

        session['add_content_data'] = [url, title, desc]

        # RegEx pattern
        pattern = r'^[A-Za-z0-9\(\)\.\•\s\-\'",\n\-\|!]+$'
        url_pattern = r'^((?:https?:)?\/\/)?((?:www|m)\.)?((?:youtube(-nocookie)?\.com|youtu.be))(\/(?:[\w\-]+\?v=|embed\/|live\/|v\/)?)([\w\-]+)(\S+)?$'

        # Existing video in table
        existing_video = db.queryDB('SELECT * FROM content WHERE url = ?', [url])

        # Validate user input
        if existing_video:
            flash('This video has already been uploaded', 'danger')
        elif not re.match(url_pattern, url):
            flash('Please enter a valid embdeded YouTube URL, without quotes', 'danger')
        elif 'embed' not in url:
            flash('Please enter a valid embdeded YouTube URL, without quotes', 'danger')
        elif not re.match(pattern, title):
            flash('Please enter valid title', 'danger')
        elif not (4 <= len(title) <= 120):
            flash('Title must be between 4 and 60 characters (inclusive)', 'danger')
        elif not re.match(pattern, desc):
            flash('Please enter valid description', 'danger')
        elif not (4 <= len(desc) <= 280):
            flash('Description must be between 4 and 1000 characters (inclusive)', 'danger')
        else:
            # Add video to table
            db.updateDB('INSERT INTO content (url, title, desc) VALUES (?, ?, ?)', [url, title, desc])
            flash('Successfully added video', 'success')

    return render_template('add_content.html', add_content_data=session.get('add_content_data'))


# Paid-for content route
@app.route('/content')
@login_required
@payment_required
def content():
    records = 3
    query = db.queryDB('SELECT * FROM content LIMIT ?', [records])
    query_len = len(query)
    return render_template('content.html', records=records, query=query, query_len=query_len)


# Return more records for paid-for content
@app.route('/more_content/<int:records>')
def more_content(records):
    records += 3
    query = db.queryDB('SELECT * FROM content LIMIT ?', [records])
    query_len = len(query)
    return render_template('content.html', records=records, query=query, query_len=query_len)


# Customisable workout plan
@app.route('/workout_plan', methods=['GET', 'POST'])
def workout_plan():
    # Clear previous form attempt if wrong
    if session.get('workout_plan_data'):
        session.pop('workout_plan_data', None)

    # Check for existing plan
    user_id = db.queryDB('SELECT * FROM users WHERE username = ?', [session.get('user')])
    user_id = user_id[0][0]

    # Get users workout plans
    workout_plans = db.queryDB('SELECT * FROM workout_plans WHERE user_id = ? ORDER BY plan_id DESC', [user_id])

    # If user submitted form
    if request.method == 'POST':
        # Get form data
        workout_name = request.form.get('workout_name')
        workout_type = request.form.get('workout_type')
        workout_intensity = request.form.get('workout_intensity')
        workout_length = request.form.get('workout_length')
        workout_time = request.form.get('workout_time')
        notes = request.form.get('notes')

        # Parse form data
        workout_plan_data = [workout_name, workout_type, workout_intensity, workout_length, workout_time, notes]

        # RegEx pattern
        pattern = r'^[A-Za-z0-9\s]+$'
        existing_plan = db.queryDB('SELECT * FROM workout_plans WHERE user_id = ? AND workout_name = ?', [user_id, workout_name])
        plan_nums = db.queryDB('SELECT * FROM workout_plans WHERE user_id = ?', [user_id])

        # Validate user input
        if existing_plan:
            flash('You have already made this plan, delete it or customise it to change it', 'danger')
        elif len(plan_nums) > 4:
            flash('You cannot make more than 4 plans, please delete some', 'danger')
        elif not re.match(pattern, workout_name):
            flash('Please enter valid workout name', 'danger')
        elif not (4 <= len(workout_name) <= 60):
            flash('Workout name must be between 4 and 60 characters (inclusive)', 'danger')
        elif not workout_type:
            flash('Must enter workout type', 'danger')
        elif not workout_intensity:
            flash('Please enter intensity (1-5)', 'danger')
        elif not workout_length:
            flash('Must enter workout length', 'danger')
        elif not workout_time:
            flash('Must enter time to start workout', 'danger')
        elif len(notes) > 120:
            flash('Notes cannot be more than 120 characters', 'danger')
        else:
            # Add plan to table
            if notes:
                db.updateDB('INSERT INTO workout_plans (user_id, workout_name, workout_type, workout_length, workout_intensity, notes, workout_time) VALUES (?, ?, ?, ?, ?, ?, ?)', [
                    user_id, workout_name, workout_type, workout_length, workout_intensity, notes, workout_time
                ])
                return redirect(url_for('workout_plan'))
            else:
                # If user did not add any notes
                db.updateDB('INSERT INTO workout_plans (user_id, workout_name, workout_type, workout_length, workout_intensity, workout_time) VALUES (?, ?, ?, ?, ?, ?)', [
                    user_id, workout_name, workout_type, workout_length, workout_intensity, workout_time
                ])
                return redirect(url_for('workout_plan'))

    return render_template('workout_plan.html', workout_plan_data=session.get('workout_plan_data'), workout_plans=workout_plans)


# View full workout plan
@app.route('/view_workout_plan/<int:plan_id>')
def view_workout_plan(plan_id):
    plan = db.queryDB("""
        SELECT *
        FROM workout_plans
            WHERE plan_id = ?
        """, [plan_id])
    
    return render_template('view_workout.html', plan=plan)


# Delete plan route
@app.route('/delete_workout/<int:plan_id>')
def delete_workout(plan_id):
    db.updateDB('DELETE FROM workout_plans WHERE plan_id = ?', [plan_id])
    return redirect(url_for('workout_plan'))


# Update the workout plan
@app.route('/update_workout/<int:plan_id>', methods=['GET', 'POST'])
def update_workout(plan_id):
    # Clear previous form attempt if wrong
    if session.get('workout_update_data'):
        session.pop('workout_update_data', None)

    # Check for existing plan
    user_id = db.queryDB('SELECT * FROM users WHERE username = ?', [session.get('user')])
    user_id = user_id[0][0]

    if request.method == 'POST':
        # Get form data
        workout_name = request.form.get('workout_name')
        workout_type = request.form.get('workout_type')
        workout_intensity = request.form.get('workout_intensity')
        workout_length = request.form.get('workout_length')
        workout_time = request.form.get('workout_time')
        notes = request.form.get('notes')

        # Parse form data
        workout_update_data = [workout_name, workout_type, workout_intensity, workout_length, workout_time, notes]

        # RegEx pattern
        pattern = r'^[A-Za-z0-9\s]+$'
        existing_plan = db.queryDB('SELECT * FROM workout_plans WHERE user_id = ? AND workout_name = ?', [user_id, workout_name])

        # Validate user input
        if existing_plan:
            flash('You have already made this plan, delete it or customise it to change it', 'danger')
        elif not re.match(pattern, workout_name):
            flash('Please enter valid workout name', 'danger')
        elif not (4 <= len(workout_name) <= 60):
            flash('Workout name must be between 4 and 60 characters (inclusive)', 'danger')
        elif not workout_type:
            flash('Must enter workout type', 'danger')
        elif not workout_intensity:
            flash('Please enter intensity (1-5)', 'danger')
        elif not workout_length:
            flash('Must enter workout length', 'danger')
        elif not workout_time:
            flash('Must enter time to start workout', 'danger')
        elif len(notes) > 120:
            flash('Notes cannot be more than 120 characters', 'danger')
        else:
            # Add plan to table
            if notes:
                db.updateDB('UPDATE workout_plans SET workout_name = ?, workout_type = ?, workout_length = ?, workout_intensity = ?, notes = ?, workout_time = ? WHERE plan_id = ?', [
                    workout_name, workout_type, workout_length, workout_intensity, notes, workout_time, plan_id
                ])
                return redirect(url_for('workout_plan'))
            else:
                # If user did not add any notes
                db.updateDB('UPDATE workout_plans SET user_id = ?, workout_name = ?, workout_type = ?, workout_length = ?, workout_intensity = ?, workout_time = ? WHERE plan_id = ?', [
                    user_id, workout_name, workout_type, workout_length, workout_intensity, workout_time, plan_id
                ])
                return redirect(url_for('workout_plan'))

    return render_template('update_workout.html', workout_update_data=session.get('workout_update_data'))


# Customisable eating plan
@app.route('/eating_plan', methods=['GET', 'POST'])
def eating_plan():
    # Clear previous form attempt if wrong
    if session.get('eating_plan_data'):
        session.pop('eating_plan_data', None)

    # Check for existing plan
    user_id = db.queryDB('SELECT * FROM users WHERE username = ?', [session.get('user')])
    user_id = user_id[0][0]

    # Get users workout plans
    eating_plans = db.queryDB('SELECT * FROM eating_plans WHERE user_id = ? ORDER BY plan_id DESC', [user_id])

    # If user submitted form
    if request.method == 'POST':
        # Get form data
        breakfast = request.form.get('breakfast')
        lunch = request.form.get('lunch')
        dinner = request.form.get('dinner')
        snacks = request.form.get('snacks')
        liquid = request.form.get('liquid')
        notes = request.form.get('notes')

        # Parse form data
        eating_plan_data = [breakfast, lunch, dinner, snacks, liquid, notes]

        # RegEx pattern
        pattern = r'^[A-Za-z0-9\s]+$'
        snacks_pattern = r'^[A-Za-z0-9\s\u2022]'
        existing_plan = db.queryDB('SELECT * FROM eating_plans WHERE user_id = ? AND breakfast = ? AND lunch = ? AND dinner = ? AND snacks = ?', [
            user_id,
            breakfast,
            lunch,
            dinner,
            snacks
        ])
        plan_nums = db.queryDB('SELECT * FROM eating_plans WHERE user_id = ?', [user_id])

        # Validate user input
        if existing_plan:
            flash('You have already made this plan, delete it or customise it to change it', 'danger')
        elif len(plan_nums) > 4:
            flash('You cannot make more than 4 eating plans, please delete some', 'danger')
        elif not re.match(pattern, breakfast):
            flash('Please enter valid breakfast', 'danger')
        elif not (4 <= len(breakfast) <= 30):
            flash('Breakfast name must be between 4 and 30 characters (inclusive)', 'danger')
        elif not re.match(pattern, lunch):
            flash('Please enter valid lunch', 'danger')
        elif not (4 <= len(lunch) <= 30):
            flash('Lunch name must be between 4 and 30 characters (inclusive)', 'danger')
        elif not re.match(pattern, dinner):
            flash('Please enter valid dinner', 'danger')
        elif not (4 <= len(dinner) <= 30):
            flash('Dinner name must be between 4 and 30 characters (inclusive)', 'danger')
        elif not re.match(snacks_pattern, snacks):
            flash('Please enter valid snack', 'danger')
        elif not (4 <= len(snacks) <= 30):
            flash('Snack name must be between 4 and 30 characters (inclusive)', 'danger')
        elif not liquid:
            flash('Please enter amount of water you consume', 'danger')
        elif len(notes) >= 120:
            flash('Notes cannot be more than 120 characters', 'danger')
        else:
            # Add plan to table
            if notes:
                db.updateDB('INSERT INTO eating_plans (user_id, breakfast, lunch, dinner, snacks, liquid, notes) VALUES (?, ?, ?, ?, ?, ?, ?)', [
                    user_id, breakfast, lunch, dinner, snacks, liquid, notes
                ])
                return redirect(url_for('eating_plan'))
            else:
                # If user did not add any notes
                db.updateDB('INSERT INTO eating_plans (user_id, breakfast, lunch, dinner, snacks, liquid) VALUES (?, ?, ?, ?, ?, ?)', [
                    user_id, breakfast, lunch, dinner, snacks, liquid
                ])
                return redirect(url_for('eating_plan'))

    return render_template('eating_plan.html', eating_plan_data=session.get('eating_plan_data'), eating_plans=eating_plans)


# View full eating plan
@app.route('/view_eating_plan/<int:plan_id>')
def view_eating_plan(plan_id):
    plan = db.queryDB("""
        SELECT *
        FROM eating_plans
            WHERE plan_id = ?
        """, [plan_id])
    
    return render_template('view_eating.html', plan=plan)


# Delete eating plan route
@app.route('/delete_eating_plan/<int:plan_id>')
def delete_eating_plan(plan_id):
    db.updateDB('DELETE FROM eating_plans WHERE plan_id = ?', [plan_id])
    return redirect(url_for('eating_plan'))


# Update the eating plan
@app.route('/update_eating_plan/<int:plan_id>', methods=['GET', 'POST'])
def update_eating_plan(plan_id):
    # Clear previous form attempt if wrong
    if session.get('eating_plan_data'):
        session.pop('eating_plan_data', None)

    # Check for existing plan
    user_id = db.queryDB('SELECT * FROM users WHERE username = ?', [session.get('user')])
    user_id = user_id[0][0]

    # Get users workout plans
    eating_plans = db.queryDB('SELECT * FROM eating_plans WHERE user_id = ? ORDER BY plan_id DESC', [user_id])

    # If user submitted form
    if request.method == 'POST':
        # Get form data
        breakfast = request.form.get('breakfast')
        lunch = request.form.get('lunch')
        dinner = request.form.get('dinner')
        snacks = request.form.get('snacks')
        liquid = request.form.get('liquid')
        notes = request.form.get('notes')

        # Parse form data
        eating_plan_data = [breakfast, lunch, dinner, snacks, liquid, notes]

        # RegEx pattern
        pattern = r'^[A-Za-z0-9\s]+$'
        snacks_pattern = r'^[A-Za-z0-9\s\u2022]'
        existing_plan = db.queryDB('SELECT * FROM eating_plans WHERE user_id = ? AND breakfast = ? AND lunch = ? AND dinner = ? AND snacks = ?', [
            user_id,
            breakfast,
            lunch,
            dinner, 
            snacks
        ])

        # Validate user input
        if existing_plan:
            flash('You have already made this plan, delete it or customise it to change it', 'danger')
        elif not re.match(pattern, breakfast):
            flash('Please enter valid breakfast', 'danger')
        elif not (4 <= len(breakfast) <= 30):
            flash('Breakfast name must be between 4 and 30 characters (inclusive)', 'danger')
        elif not re.match(pattern, lunch):
            flash('Please enter valid lunch', 'danger')
        elif not (4 <= len(lunch) <= 30):
            flash('Lunch name must be between 4 and 30 characters (inclusive)', 'danger')
        elif not re.match(pattern, dinner):
            flash('Please enter valid dinner', 'danger')
        elif not (4 <= len(dinner) <= 30):
            flash('Dinner name must be between 4 and 30 characters (inclusive)', 'danger')
        elif not re.match(snacks_pattern, snacks):
            flash('Please enter valid snack', 'danger')
        elif not (4 <= len(snacks) <= 30):
            flash('Snack name must be between 4 and 30 characters (inclusive)', 'danger')
        elif not liquid:
            flash('Please enter amount of water you consume', 'danger')
        elif len(notes) >= 120:
            flash('Notes cannot be more than 120 characters', 'danger')
        else:
            # Update values in table if notes
            if notes:
                db.updateDB('UPDATE eating_plans SET breakfast = ?, lunch = ?, dinner = ?, snacks = ?, liquid = ?, notes = ? WHERE user_id = ? AND plan_id = ?', [
                    breakfast, lunch, dinner, snacks, liquid, notes, user_id, plan_id
                ])
                return redirect(url_for('eating_plan'))
            else:
                # Update without notes
                db.updateDB('UPDATE eating_plans SET breakfast = ?, lunch = ?, dinner = ?, snacks = ?, liquid = ? WHERE user_id = ? AND plan_id = ?', [
                    breakfast, lunch, dinner, snacks, liquid, user_id, plan_id
                ])
                return redirect(url_for('eating_plan'))

    return render_template('update_eating_plan.html', eating_plan_data=session.get('eating_plan_data'))


# Terms and conditions route
@app.route('/tandcs')
def tandcs():
    return render_template('tandc.html')


# About us route
@app.route('/about_us')
def about_us():
    return render_template('about_us.html')


# Create social media post
@app.route('/post', methods=['GET', 'POST'])
@login_required
def post():
    # If user has submitted form incorrectly
    if session.get('post'):
        session.pop('post', None)

    # Check for existing plan
    user_id = db.queryDB('SELECT * FROM users WHERE username = ?', [session.get('user')])
    user_id = user_id[0][0]

    # If user has submitted form
    if request.method == 'POST':
        # Get form data
        title = request.form.get('title')
        desc = request.form.get('desc')

        # Pre-requisites
        title_pattern = r'^[A-Za-z0-9\s]+$'
        existing_post = db.queryDB('SELECT * FROM posts WHERE user_id = ? AND title = ? AND desc = ?', [user_id, title, desc])

        # Validate user input
        if existing_post:
            flash('You have already made this exact same post', 'danger')
        elif not re.match(title_pattern, title):
            flash('Please enter a valid title', 'danger')
        elif not (4 <= len(title) <= 60):
            flash('Title must be between 4 and 60 characters (inclusive)', 'danger')
        elif not (4 <= len(desc) <= 280):
            flash('Description must be between 4 and 280 characters (inclusive)', 'danger')
        else:
            # Create post
            db.updateDB('INSERT INTO posts (user_id, title, desc) VALUES (?, ?, ?)', [user_id, title, desc])
            return redirect(url_for('social_media'))

    return render_template('post.html', post=session.get('post'))


# Delete posts route
@app.route('/delete_post/<int:post_id>')
def delete_post(post_id):
    db.updateDB('DELETE FROM posts WHERE post_id = ?', [post_id])
    return redirect(url_for('social_media'))


# Social media route
@app.route('/social_media')
def social_media():
    records = 8
    posts = db.queryDB('SELECT * FROM posts INNER JOIN users ON posts.user_id = users.user_id LIMIT ?', [records])
    user_id = db.queryDB('SELECT * FROM users WHERE username = ?', [session.get('user')])
    user_id = user_id[0][0]
    query_len = len(posts)
    return render_template('social_media.html', posts=posts, records=records, query_len=query_len, user_id=user_id)


# Load more posts
@app.route('/load_more_posts/<int:records>')
def load_social(records):
    records += 8
    posts = db.queryDB('SELECT * FROM posts INNER JOIN users ON posts.user_id = users.user_id LIMIT ?', [records])
    query_len = len(posts)
    return render_template('social_media.html', posts=posts, records=records, query_len=query_len)