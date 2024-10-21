from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, DateField, SelectField, FileField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError, Optional
from app.models import User
from app import db, bcrypt
import pycountry


class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('That username is already taken. Please choose a different one.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('That email is already registered. Please choose a different one.')

class LoginForm(FlaskForm):
    email_or_username = StringField('Email or Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')


from flask_wtf import FlaskForm
from wtforms import StringField, RadioField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length

class SecuritySetupForm(FlaskForm):
    choice = RadioField('Setup Option', choices=[('pin', '6-digit PIN'), ('question', 'Security Question')], validators=[DataRequired()])
    pin = StringField('6-digit PIN', validators=[Length(min=6, max=6)], render_kw={"placeholder": "Enter a 6-digit PIN"})
    security_question = StringField('Security Question', validators=[Length(max=255)], render_kw={"placeholder": "Enter your security question"})
    security_answer = PasswordField('Security Answer', render_kw={"placeholder": "Enter your answer"})
    submit = SubmitField('Save')

class SecurityValidationForm(FlaskForm):
    pin = PasswordField('Enter your PIN', validators=[Length(min=6, max=6)])
    security_answer = StringField('Answer to your Security Question', validators=[DataRequired()])
    submit = SubmitField('Validate')

class RecordForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    content = TextAreaField('Content', validators=[DataRequired()])
    submit = SubmitField('Create Record')

class UpdateProfileForm(FlaskForm):
    first_name = StringField('First Name', validators=[Length(max=50)])
    last_name = StringField('Last Name', validators=[Length(max=50)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    # Gender select field
    gender_choices = [
        ('', 'Select Gender'),  # Empty choice for prompt
        ('Male', 'Male'),
        ('Female', 'Female'),
        ('Other', 'Other'),
        ('Prefer not to say', 'Prefer not to say')
    ]
    gender = SelectField('Gender', choices=gender_choices, validators=[Optional()])
    date_of_birth = DateField('Date of Birth', format='%Y-%m-%d', validators=[Optional()])

    # Field for uploading a profile picture
    profile_picture = FileField('Profile Picture', validators=[Optional()])

    # Populate countries alphabetically
    nationality_choices = [(country.name, country.name) for country in pycountry.countries]
    nationality = SelectField('Nationality', choices=nationality_choices, validators=[Optional()])    
    submit = SubmitField('Update Profile')


class UpdateRecordForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    content = TextAreaField('Content', validators=[DataRequired()])
    submit = SubmitField('Update Record')

from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField, ValidationError
from wtforms.validators import DataRequired, Length, EqualTo

class SecuritySettingsForm(FlaskForm):
    setup_type = SelectField('Setup Type', choices=[('pin', 'PIN'), ('question', 'Security Question')], validators=[DataRequired()])
    previous_security_answer = StringField('Previous Security Answer', validators=[DataRequired(), Length(min=1, max=255)])
    pin = PasswordField('New PIN', validators=[Length(min=6, max=6)])  # Validate for 6-digit PIN
    security_question = StringField('New Security Question', validators=[Length(max=255)])
    security_answer = StringField('New Security Answer', validators=[DataRequired(), Length(min=1, max=255)])
    submit = SubmitField('Update Security Settings')

    def validate_pin(self, pin):
        if self.setup_type.data == 'pin' and not pin.data:
            raise ValidationError('PIN is required when selecting PIN setup.')

    def validate_security_question(self, security_question):
        if self.setup_type.data == 'question' and not security_question.data:
            raise ValidationError('Security question is required when selecting security question setup.')
    
    def check_security_answer(stored_answer, provided_answer):
        return bcrypt.check_password_hash(stored_answer, provided_answer)

