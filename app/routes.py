from flask import render_template, url_for, flash, redirect, Blueprint
from app import db, bcrypt
from app.forms import *
from app.models import *
from flask_login import login_user, current_user, logout_user, login_required
import requests
from werkzeug.utils import secure_filename

main = Blueprint('main', __name__)


@main.route("/")
@main.route("/home")
def home():
    return render_template('home.html')

@main.route("/about")
def about():
    return render_template('about.html')

@main.route("/privacy")
def privacy():
    return render_template('privacy.html')

@main.route("/contact")
def contact():
    return render_template('contact.html')

from flask import current_app, flash, redirect, url_for, render_template
from flask_login import login_required
from werkzeug.utils import secure_filename
import os

@main.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    form = UpdateProfileForm()

    if form.validate_on_submit():
        current_user.first_name = form.first_name.data
        current_user.last_name = form.last_name.data
        current_user.email = form.email.data
        current_user.gender = form.gender.data
        current_user.date_of_birth = form.date_of_birth.data
        current_user.nationality = form.nationality.data

        # Handle profile picture upload
        if form.profile_picture.data:
            picture_file = form.profile_picture.data
            
            # Check if the file has a filename
            if picture_file.filename == '':
                flash('No selected file', 'danger')
                return redirect(url_for('main.profile'))

            filename = secure_filename(picture_file.filename)
            picture_path = os.path.join(current_app.root_path, 'static/profile_pics', filename)

            # Ensure the filename is unique
            base, extension = os.path.splitext(filename)
            counter = 1
            while os.path.exists(picture_path):
                filename = f"{base}_{counter}{extension}"
                picture_path = os.path.join(current_app.root_path, 'static/profile_pics', filename)
                counter += 1

            picture_file.save(picture_path)
            current_user.profile_picture = filename

        db.session.commit()
        flash('Your profile has been updated!', 'success')
        return redirect(url_for('main.profile'))

    # Pre-fill the form with the current user's data
    form.first_name.data = current_user.first_name
    form.last_name.data = current_user.last_name
    form.email.data = current_user.email
    form.gender.data = current_user.gender
    form.date_of_birth.data = current_user.date_of_birth
    form.nationality.data = current_user.nationality

    # Pre-fill the profile picture field with the current user's profile picture
    form.profile_picture.data = current_user.profile_picture  # This will be the filename

    return render_template('profile.html', form=form)

@main.route('/account_settings')
@login_required
def account_settings():
    return render_template('account_settings.html')

@main.route('/notifications')
@login_required
def notifications():
    return render_template('notifications.html')

@main.route('/support')
@login_required
def support():
    return render_template('support.html')

@main.route("/register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        print("User is already authenticated, redirecting to home.")
        return redirect(url_for('main.home'))
    
    form = RegistrationForm()
    if form.validate_on_submit():
        try:
            hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
            user = User(username=form.username.data, email=form.email.data, password=hashed_password)
            db.session.add(user)
            db.session.commit()
            flash('Your account has been created! You can now log in.', 'success')
            print(f"User {user.username} registered successfully.")
            return redirect(url_for('main.login'))
        except Exception as e:
            db.session.rollback()  # Rollback the session in case of an error
            flash('An error occurred while creating your account. Please try again.', 'danger')
            print(f"Error during registration: {str(e)}")
    
    return render_template('register.html', form=form)


@main.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        print("User is already authenticated, redirecting to home.")
        return redirect(url_for('main.dashboard'))
    
    form = LoginForm()
    
    if form.validate_on_submit():
        try:
            # Attempt to find the user by either email or username
            user = User.query.filter(
                (User.email == form.email_or_username.data) | 
                (User.username == form.email_or_username.data)
            ).first()

            # Check if the user exists and if the password matches
            if user:
                if bcrypt.check_password_hash(user.password, form.password.data):
                    login_user(user)
                    user.last_login = datetime.utcnow()  # Update last_login
                    db.session.commit()  # Commit the changes to the database
                    print(f"User {user.username} logged in successfully.")

                    # Check if the user has completed the security setup
                    if not user.setup_completed:
                        print("User has not completed security setup, redirecting to setup.")
                        return redirect(url_for('main.setup_security'))

                    # If the user has completed the setup, redirect to the security verification page
                    print("User has completed security setup, redirecting to verification.")
                    return redirect(url_for('main.verify_security'))
                else:
                    # Password is incorrect
                    flash('Your details were not correct. Please try again.', 'danger')
                    print("Login failed: Invalid password.")
            else:
                # User does not exist
                flash('Your details were not correct. Please try again.', 'danger')
                print("Login failed: No user found with the provided credentials.")

        except Exception as e:
            flash('Your details were not correct. Please try again.', 'danger')
            print(f"Error during login: {str(e)}")

    return render_template('login.html', form=form)

from flask import render_template, redirect, url_for, flash, request, jsonify
from flask_login import current_user, login_required
from werkzeug.security import generate_password_hash

@main.route('/setup_security', methods=['GET', 'POST'])
@login_required
def setup_security():
    if request.method == 'POST':
        data = request.get_json()  # Get JSON data from the request
        
        if data['choice'] == 'pin':
            pin = data.get('pin')
            confirm_pin = data.get('confirmPin')
            if pin and pin == confirm_pin:
                # Clear the security question if user sets a PIN
                current_user.security_question = None
                current_user.security_answer = None
                current_user.pin = generate_password_hash(pin)  # Store the hashed PIN
            else:
                return jsonify({'success': False, 'error': 'PINs do not match'}), 400
        
        elif data['choice'] == 'question':
            question = data.get('security_question')  # This will now contain the full question
            answer = data.get('security_answer')
            # Clear the PIN if user sets a security question
            current_user.pin = None
            current_user.security_question = question  # Store the complete question
            current_user.security_answer = generate_password_hash(answer)
        
        current_user.setup_completed = True  # Mark setup as complete
        db.session.commit()  # Commit the changes to the database
        flash('Security setup completed successfully!', 'success')
        return jsonify({'success': True}), 200  # Respond with success

    return render_template('setup_security.html')



# Helper function for verification
def verify_user_input(stored_hash, user_input):
    """Verify the user's PIN or security answer."""
    if user_input and check_password_hash(stored_hash, user_input.strip()):
        current_user.is_verified = True
        db.session.commit()
        return True
    return False


from flask import request, render_template, flash, redirect, url_for
from flask_login import login_required, current_user
from werkzeug.security import check_password_hash

@main.route('/verify_security', methods=['GET', 'POST'])
@login_required
def verify_security():
    if request.method == 'POST':
        pin = request.form.get('pin')
        answer = request.form.get('answer')

        # Check PIN
        if current_user.pin and verify_user_input(current_user.pin, pin):
            current_user.is_verified = True
            db.session.commit()  # Commit the change to the database
            flash('Verification successful! Redirecting to your dashboard.', 'success')
            return redirect(url_for('main.dashboard'))  # Redirect to dashboard after success

        # Check Security Question
        elif current_user.security_question and verify_user_input(current_user.security_answer, answer):
            current_user.is_verified = True
            db.session.commit()  # Commit the change to the database
            flash('Verification successful! Redirecting to your dashboard.', 'success')
            return redirect(url_for('main.dashboard'))  # Redirect to dashboard after success

        flash('Incorrect PIN or answer. Please try again.', 'danger')

    return render_template('verify_security.html')


@main.route('/dashboard')
@login_required
def dashboard():
    if not current_user.is_verified:
        flash('Please verify your security details before accessing the dashboard.', 'warning')
        return redirect(url_for('main.verify_security'))

    records = Record.query.filter_by(user_id=current_user.id).order_by(Record.date_posted.desc()).all()
    return render_template('dashboard.html', records=records)

@main.route('/search', methods=['GET', 'POST'])
@login_required
def search():
    results = []
    query = request.args.get('query')
    
    if query:
        # Assuming you have a method in your Record model to search records
        results = Record.query.filter(Record.title.ilike(f'%{query}%')).all()  # Modify based on your model fields

    return render_template('search.html', results=results, query=query)

@main.route('/create_record', methods=['GET', 'POST'])
@login_required
def create_record():
    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        date_posted = datetime.utcnow()

        # Create a new record, associating it with the current user
        new_record = Record(title=title, content=content, date_posted=date_posted, user_id=current_user.id)

        db.session.add(new_record)
        db.session.commit()
        flash('Record created successfully!', 'success')
        return redirect(url_for('main.dashboard'))  

    return render_template('create_record.html')

from datetime import datetime

@main.route('/activity')
@login_required
def activity():
    # Example: Fetch recent activity from a database or other logic
    recent_activities = [
    {
        'ip': '192.168.1.100', 
        'time': current_user.last_login.strftime('%Y-%m-%d %H:%M:%S'),  # Format last login time
        'activity': 'Logged in'
    },
    {
        'time': current_user.password_updated.strftime('%Y-%m-%d %H:%M:%S') if current_user.password_updated else None,
        'activity': 'Updated password'
    },
    {
        'time': current_user.security_updated.strftime('%Y-%m-%d %H:%M:%S') if current_user.security_updated else None,
        'activity': 'Updated security settings'
    }
]

    return render_template('activity.html', activities=recent_activities)

@main.route('/change_pin', methods=['POST'])
@login_required
def change_pin():
    pin = request.form.get('pin')
    if len(pin) == 6 and pin.isdigit():
        current_user.pin = bcrypt.generate_password_hash(pin).decode('utf-8')
        current_user.setup_completed = True
        db.session.commit()
        flash('PIN updated successfully!', 'success')
    else:
        flash('PIN must be 6 digits long.', 'danger')
    return redirect(url_for('main.security'))

@main.route('/update_password', methods=['GET', 'POST'])
@login_required
def update_password():
    form = UpdatePasswordForm()  # Assuming you have a form for updating the password
    if form.validate_on_submit():
        current_user.password = bcrypt.generate_password_hash(form.new_password.data).decode('utf-8')
        current_user.password_updated = datetime.utcnow()  # Update password updated time
        db.session.commit()  # Commit changes
        flash('Your password has been updated!', 'success')
        return redirect(url_for('main.dashboard'))
    return render_template('update_password.html', form=form)


@main.route('/security', methods=['GET', 'POST'])
@login_required
def security():
    # Check the user's current security setup
    setup_type = 'pin' if current_user.pin else 'question' if current_user.security_question else None
    
    if setup_type is None:
        flash('No security setup found. Please complete your security settings.', 'danger')
        return redirect(url_for('main.setup_security'))

    form = SecurityValidationForm()  # New form for validating current security setup

    if form.validate_on_submit():
        # Validate the user's input based on the existing setup
        if setup_type == 'pin':
            if form.pin.data == current_user.pin:  # Assuming pins are stored in plain text (you should ideally hash it)
                return redirect(url_for('main.setup_security'))
            else:
                flash('Invalid PIN. Please try again.', 'danger')
        elif setup_type == 'question':
            if check_security_answer(current_user.security_answer, form.security_answer.data):
                return redirect(url_for('main.setup_security'))
            else:
                flash('Invalid answer to your security question. Please try again.', 'danger')

    return render_template('security_settings.html', form=form, setup_type=setup_type)



@main.route('/verify', methods=['GET', 'POST'])
@login_required
def verify_newsecurity():
    if request.method == 'POST':
        pin = request.form.get('pin')
        answer = request.form.get('answer')

        # Check for PIN verification
        if current_user.pin and verify_user_input(current_user.pin, pin):
            current_user.is_verified = False  # Mark user as verified
            db.session.commit()  # Commit the changes
            return redirect(url_for('main.setup_security'))  # Redirect to setup_security

        # Check for security question verification
        elif current_user.security_question and verify_user_input(current_user.security_answer, answer):
            current_user.is_verified = False  # Mark user as verified
            db.session.commit()  # Commit the changes
            return redirect(url_for('main.setup_security'))  # Redirect to setup_security

        # Return error if verification fails
        return jsonify({'status': 'fail', 'message': 'Incorrect PIN or answer. Please try again.'})

    return render_template('verify_security.html')



@main.route('/update_security', methods=['GET', 'POST'])
@login_required
def update_security():
    form = UpdateSecurityForm()  # Assuming you have a form for updating security settings
    if form.validate_on_submit():
        current_user.security_question = form.security_question.data
        current_user.security_answer = bcrypt.generate_password_hash(form.security_answer.data).decode('utf-8')
        current_user.security_updated = datetime.utcnow()  # Update security updated time
        db.session.commit()  # Commit changes
        flash('Your security settings have been updated!', 'success')
        return redirect(url_for('main.dashboard'))
    return render_template('update_security.html', form=form)


@main.route('/change_security_question', methods=['POST'])
@login_required
def change_security_question():
    security_question = request.form.get('security_question')
    security_answer = request.form.get('security_answer')
    if security_question and security_answer:
        current_user.security_question = security_question
        current_user.security_answer = bcrypt.generate_password_hash(security_answer).decode('utf-8')
        current_user.setup_completed = True
        db.session.commit()
        flash('Security question updated successfully!', 'success')
    else:
        flash('Please fill in both the security question and answer.', 'danger')
    return redirect(url_for('main.security'))

@main.route("/logout")
def logout():
    current_user.is_verified = False
    db.session.commit()
    logout_user()
    flash('Log out successful.', 'info')
    return redirect(url_for('main.home'))

@main.route('/record/<int:record_id>')
@login_required
def view_record(record_id):
    record = Record.query.get_or_404(record_id)
    if record.user_id != current_user.id:
        flash('You do not have permission to view this record.', 'danger')
        return redirect(url_for('main.dashboard'))
    return render_template('view_record.html', record=record)


@main.route('/record/<int:record_id>/delete', methods=['POST'])
@login_required
def delete_record(record_id):
    record = Record.query.get_or_404(record_id)
    if record.user_id != current_user.id:
        flash('You do not have permission to delete this record.', 'danger')
        return redirect(url_for('main.dashboard'))
    
    db.session.delete(record)
    db.session.commit()
    flash('Your record has been deleted.', 'success')
    return redirect(url_for('main.dashboard'))

@main.route('/record/<int:record_id>/update', methods=['GET', 'POST'])
@login_required
def update_record(record_id):
    record = Record.query.get_or_404(record_id)
    if record.user_id != current_user.id:
        flash('You do not have permission to update this record.', 'danger')
        return redirect(url_for('main.dashboard'))
    
    form = UpdateRecordForm()
    if form.validate_on_submit():
        record.title = form.title.data
        record.content = form.content.data
        db.session.commit()
        flash('Your record has been updated!', 'success')
        return redirect(url_for('main.dashboard', record_id=record.id))
    elif request.method == 'GET':
        form.title.data = record.title
        form.content.data = record.content
    
    return render_template('update_record.html', form=form, record=record)
