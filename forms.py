from flask_wtf import FlaskForm
from wtforms import TextField, BooleanField, TextAreaField, StringField, PasswordField, SelectField, validators

class LoginForm(FlaskForm):
    username = TextField('Username', [
        validators.Required(), 
        validators.Length(min=4, max=25)
    ])
    password = PasswordField('New Password', [
        validators.Required()
    ])
    twofa = TextField('2fa', [validators.Required()])

class SpellCheckForm(FlaskForm):
	inputtext = TextField('inputtext', [
        validators.Required()
    ])

class LogForm(FlaskForm):
	username = TextField('Username', [
        	validators.Required(), 
        	validators.Length(min=4, max=25)
    	])
