from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, FloatField, RadioField, SelectField, HiddenField
from wtforms.validators import DataRequired, Email, EqualTo, ValidationError, NumberRange, Optional, Length, Regexp
from models import User
from cryptography.fernet import Fernet, InvalidToken
import os
import re

fernet_key = os.environ.get("FERNET_KEY")
if not fernet_key:
    raise ValueError("FERNET_KEY not found in environment variables.")
fernet = Fernet(fernet_key)

#Password strength validator
def validate_strong_password(form, field):
    password = field.data
    if (len(password) < 8 or not re.search(r'[A-Z]', password) or
        not re.search(r'[a-z]', password) or
        not re.search(r'[0-9]', password) or
        not re.search(r'[!@#$%^&*(),.?":{}|<>]', password)):
        raise ValidationError('Password must be at least 8 characters long and include uppercase, lowercase, digit, and special character.')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=64)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])
    submit = SubmitField('Login')

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[
        DataRequired(), Length(min=3, max=64),
        Regexp(r'^[A-Za-z0-9_.]+$', message="Username can only contain letters, numbers, underscores, or dots.")
    ])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), validate_strong_password])
    password2 = PasswordField('Repeat Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

    def validate_username(self, username):
        if User.query.filter_by(username=username.data).first():
            raise ValidationError('Please use a different username.')

    def validate_email(self, email):
        if User.query.filter_by(email=email.data).first():
            raise ValidationError('Please use a different email address.')

class TransferForm(FlaskForm):
    transfer_type = RadioField('Transfer Type',
                               choices=[('username', 'By Username'), ('account', 'By Account Number')],
                               default='username')
    recipient_username = StringField('Recipient Username', validators=[Optional(), Length(max=64)])
    recipient_account = StringField('Recipient Account Number', validators=[Optional(), Regexp(r'^\d{10}$', message='Must be 10 digits')])
    amount = FloatField('Amount', validators=[DataRequired(), NumberRange(min=0.01)])
    submit = SubmitField('Transfer')

    def validate(self, extra_validators=None):
        if not super(TransferForm, self).validate():
            return False
        if self.transfer_type.data == 'username':
            if not self.recipient_username.data:
                self.recipient_username.errors.append('Username is required.')
                return False
            if not User.query.filter_by(username=self.recipient_username.data).first():
                self.recipient_username.errors.append('No user with that username.')
                return False
        elif self.transfer_type.data == 'account':
            if not self.recipient_account.data:
                self.recipient_account.errors.append('Account number is required.')
                return False
            if not User.query.filter_by(account_number=self.recipient_account.data).first():
                self.recipient_account.errors.append('No user with that account number.')
                return False
        return True

class ResetPasswordRequestForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Request Password Reset')

    def validate_email(self, email):
        found = False
        for user in User.query.all():
            try:
                if user.email == email.data:
                    found = True
                    break
            except (InvalidToken, AttributeError):
                continue
        if not found:
            raise ValidationError('No account is associated with that email.')

class ResetPasswordForm(FlaskForm):
    password = PasswordField('New Password', validators=[DataRequired(), validate_strong_password])
    password2 = PasswordField('Repeat Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Reset Password')

class DepositForm(FlaskForm):
    account_number = StringField('Account Number', validators=[
        DataRequired(), Regexp(r'^\d{10}$', message="Account number must be 10 digits.")])
    amount = FloatField('Amount', validators=[DataRequired(), NumberRange(min=0.01)])
    submit = SubmitField('Deposit')

    def validate(self, extra_validators=None):
        if not super(DepositForm, self).validate():
            return False
        if not User.query.filter_by(account_number=self.account_number.data).first():
            self.account_number.errors.append('No account with that number.')
            return False
        return True

class UserEditForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    firstname = StringField('First Name', validators=[Optional(), Length(max=64)])
    lastname = StringField('Last Name', validators=[Optional(), Length(max=64)])
    address_line = StringField('Street Address', validators=[Optional(), Length(max=256)])
    postal_code = StringField('Postal Code', validators=[Optional(), Regexp(r'^\d{4,5}$', message="Enter a valid postal code.")])
    region_code = HiddenField('Region Code')
    province_code = HiddenField('Province Code')
    city_code = HiddenField('City Code')
    barangay_code = HiddenField('Barangay Code')
    region_name = SelectField('Region', choices=[], validators=[Optional()])
    province_name = SelectField('Province', choices=[], validators=[Optional()])
    city_name = SelectField('City/Municipality', choices=[], validators=[Optional()])
    barangay_name = SelectField('Barangay', choices=[], validators=[Optional()])
    phone = StringField('Phone Number', validators=[
        Optional(), Regexp(r'^\+?[\d\s\-]{7,15}$', message="Enter a valid phone number.")])
    status = SelectField('Account Status',
                         choices=[('active', 'Active'), ('deactivated', 'Deactivated'), ('pending', 'Pending')],
                         validators=[DataRequired()])
    submit = SubmitField('Update User')

    def __init__(self, original_email, *args, **kwargs):
        super(UserEditForm, self).__init__(*args, **kwargs)
        self.original_email = original_email

    def validate_email(self, email):
        if email.data != self.original_email:
            if User.query.filter_by(email=email.data).first():
                raise ValidationError('This email is already in use.')

class ConfirmTransferForm(FlaskForm):
    recipient_username = HiddenField('Recipient Username')
    recipient_account = HiddenField('Recipient Account Number')
    amount = HiddenField('Amount')
    transfer_type = HiddenField('Transfer Type')
    submit = SubmitField('Confirm Transfer')
